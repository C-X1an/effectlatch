//! Bounded core Wasm execution primitives. The guest has no ambient imports.
pub mod abi;
pub mod engine;
pub mod ipc;
pub mod supervisor;
pub mod validate;
