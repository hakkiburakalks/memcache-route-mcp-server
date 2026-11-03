//! Process-wide memory reservations for untrusted upstream replies.
//!
//! Permits are measured in KiB and held by an RAII guard. The budget is intentionally a
//! reservation limit, not a claim that every byte in the process is accounted for: JSON
//! serialization, HTTP bodies and allocator overhead are outside these reservations.

use std::sync::{Arc, OnceLock};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const KIB: usize = 1024;

/// Default process-wide reservation budget. The Helm chart sets the same value explicitly;
/// 96 MiB is chosen to leave room for the runtime, JSON serialization and HTTP bodies under a
/// 256 MiB container limit, but that container limit is not proven by this constant.
pub const DEFAULT_BUDGET_BYTES: usize = 96 * 1024 * 1024;

/// A reservation is rounded up to whole KiB; the requested byte count is kept for reporting.
#[derive(Debug)]
pub struct MemoryReservation {
    _permit: Option<OwnedSemaphorePermit>,
    bytes: usize,
}

impl MemoryReservation {
    pub fn bytes(&self) -> usize {
        self.bytes
    }
}

#[derive(Debug)]
pub struct MemoryBudget {
    sem: Arc<Semaphore>,
    capacity_bytes: usize,
}

impl MemoryBudget {
    /// Creates a budget. Byte counts are rounded up to whole KiB.
    pub fn new(bytes: usize) -> Self {
        let units = bytes.div_ceil(KIB).min(u32::MAX as usize);
        let capacity_bytes = units.saturating_mul(KIB);
        Self {
            sem: Arc::new(Semaphore::new(units)),
            capacity_bytes,
        }
    }

    pub fn capacity_bytes(&self) -> usize {
        self.capacity_bytes
    }

    pub fn available_bytes(&self) -> usize {
        self.sem.available_permits().saturating_mul(KIB)
    }

    /// Reserves memory before the caller allocates it. Exhaustion is an immediate error; this
    /// never waits, so a request cannot hold an HTTP worker while waiting for memory.
    pub fn try_reserve(&self, bytes: usize) -> Result<MemoryReservation, String> {
        if bytes == 0 {
            return Ok(MemoryReservation {
                _permit: None,
                bytes: 0,
            });
        }
        let units = u32::try_from(bytes.div_ceil(KIB))
            .map_err(|_| format!("memory request of {bytes} bytes is too large"))?;
        match self.sem.clone().try_acquire_many_owned(units) {
            Ok(permit) => Ok(MemoryReservation {
                _permit: Some(permit),
                bytes,
            }),
            Err(_) => Err(format!(
                "memory budget exceeded: requested {bytes} bytes, {} of {} bytes available",
                self.available_bytes(),
                self.capacity_bytes
            )),
        }
    }
}

static GLOBAL: OnceLock<Arc<MemoryBudget>> = OnceLock::new();

/// Configures the process-wide budget once at startup.
pub fn configure_global(bytes: usize) -> Result<(), String> {
    if bytes == 0 {
        return Err("memory budget must be positive".to_owned());
    }
    GLOBAL
        .set(Arc::new(MemoryBudget::new(bytes)))
        .map_err(|_| "memory budget was already configured".to_owned())
}

/// The process-wide budget, or None in tests/embeddings that did not configure one.
pub fn global() -> Option<Arc<MemoryBudget>> {
    GLOBAL.get().cloned()
}

#[cfg(test)]
mod tests {
    use std::panic::{catch_unwind, AssertUnwindSafe};

    use super::*;

    #[test]
    fn reservations_are_rounded_up_and_released_on_drop() {
        let budget = MemoryBudget::new(64 * KIB);
        assert_eq!(budget.capacity_bytes(), 64 * KIB);
        let first = budget.try_reserve(1).unwrap();
        assert_eq!(first.bytes(), 1);
        assert_eq!(budget.available_bytes(), 63 * KIB);
        let second = budget.try_reserve(63 * KIB).unwrap();
        assert_eq!(second.bytes(), 63 * KIB);
        assert_eq!(budget.available_bytes(), 0);
        drop(first);
        assert_eq!(budget.available_bytes(), KIB);
        drop(second);
        assert_eq!(budget.available_bytes(), 64 * KIB);
    }

    #[test]
    fn exhaustion_fails_immediately_without_a_partial_reservation() {
        let budget = MemoryBudget::new(2 * KIB);
        let _first = budget.try_reserve(KIB).unwrap();
        let _second = budget.try_reserve(KIB).unwrap();
        let err = budget.try_reserve(1).unwrap_err();
        assert!(err.contains("memory budget exceeded"), "{err}");
        assert_eq!(budget.available_bytes(), 0);
    }

    #[test]
    fn zero_bytes_needs_no_permit() {
        let budget = MemoryBudget::new(KIB);
        let reservation = budget.try_reserve(0).unwrap();
        assert_eq!(reservation.bytes(), 0);
        assert_eq!(budget.available_bytes(), KIB);
    }

    #[test]
    fn a_panicking_holder_returns_its_reservation() {
        let budget = std::sync::Arc::new(MemoryBudget::new(64 * KIB));
        let held = std::sync::Arc::clone(&budget);
        let result = catch_unwind(AssertUnwindSafe(|| {
            let _reservation = held.try_reserve(32 * KIB).unwrap();
            panic!("simulated panic while holding a reply buffer");
        }));
        assert!(result.is_err());
        assert_eq!(budget.available_bytes(), 64 * KIB);
    }
}
