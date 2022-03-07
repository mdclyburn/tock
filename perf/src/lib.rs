#![no_std]

mod counter;
mod proto;

// Types
pub use counter::PerformanceCounter;

// Functions
pub use counter::account_ffi;

// Constants
pub use proto::TX_BUFFER_BYTE_LEN;

// Values
pub use counter::INSTANCE;
