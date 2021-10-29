//! Memory statistic tracking.

use crate::errorcode::ErrorCode;

// `pub use` to make it easier to refer to this type without
// polluting the code with external library references.
pub use clockwise_shared::mem::{CounterId, serialize_u32};

pub static mut INSTANCE: Option<&dyn MemoryStatistics> = None;

pub trait MemoryStatistics {
    /// Returns the memory usage accounted to the counter.
    fn get(&self, id: CounterId) -> Result<usize, ErrorCode>;

    /// Assign the memory usage to a specific counter.
    fn set(&self, id: CounterId, bytes_used: usize) -> Result<(), ErrorCode>;

    /// Change the current memory usage for a counter.
    fn modify(&self, id: CounterId, delta: isize) -> Result<(), ErrorCode> {
        let new_val = if delta < 0 {
            self.get(id)?.checked_sub((delta * -1) as usize)
                .ok_or(ErrorCode::FAIL)?
        } else {
            self.get(id)?.checked_add(delta as usize)
                .ok_or(ErrorCode::FAIL)?
        };

        self.set(id, new_val)
    }
}

pub fn instance() -> &'static dyn MemoryStatistics {
    unsafe {
        if let Some(memstat) = crate::hil::memstat::INSTANCE {
            memstat
        } else {
            panic!("Cannot use memory statistics tracking when unconfigured.");
        }
    }
}

#[macro_export]
macro_rules! memstat_set {
    ($counter:expr, $bytes_used:expr) => {{
        let counter_id: crate::hil::memstat::CounterId = ($counter);
        let bytes_used: usize = ($bytes_used);

        crate::hil::memstat::instance().set(counter_id, bytes_used).unwrap();
    }}
}

#[macro_export]
macro_rules! memstat_mod {
    ($counter:expr, $delta:expr) => {{
        let counter_id: crate::hil::memstat::CounterId = ($counter);
        let delta: isize = ($delta);

        crate::hil::memstat::instance().modify(counter_id, delta).unwrap();
    }}
}
