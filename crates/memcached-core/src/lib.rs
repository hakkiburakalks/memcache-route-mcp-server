//! Async memcached client and server capability detection.

pub mod client;

pub use client::{Capabilities, Client, ClientError, KeyInfo, KeySample};
pub use memcached_protocol::text::DumpEntry;
