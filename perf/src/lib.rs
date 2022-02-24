#![no_std]

mod counter;
mod proto;

pub use counter::INSTANCE;
pub use counter::PerformanceCounter;
pub use counter::use_instance;

pub use proto::TX_BUFFER_BYTE_LEN;
