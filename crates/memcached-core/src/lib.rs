//! Async memcached client and server capability detection.

pub mod client;

pub use client::{Capabilities, Client, ClientError};
