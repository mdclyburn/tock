#![no_std]

mod counter;
mod proto;

// Types
pub use counter::PerformanceCounter;

// Functions
pub use counter::account_ffi;
pub use counter::freeze_ffi;

// Constants
pub use proto::TX_BUFFER_BYTE_LEN;

// Values
pub use counter::INSTANCE;
