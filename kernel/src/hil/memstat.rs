//! Memory statistic tracking.

use crate::errorcode::ErrorCode;
use crate::process::ProcessId;

pub static mut INSTANCE: Option<&dyn MemoryStatistics> = None;

/// Memory statistic category
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum CounterId {
    Grant(ProcessId),
}

pub trait MemoryStatistics {
    /// Returns the memory usage accounted to the counter.
    fn get(&self, id: CounterId) -> Result<usize, ErrorCode>;

    /// Assign the memory usage to a specific counter.
    fn set(&self, id: CounterId, bytes_used: usize) -> Result<(), ErrorCode>;

    /// Change the current memory usage for a counter.
    fn modify(&self, id: CounterId, delta: isize) -> Result<(), ErrorCode> {
        if delta < 0 {
            self.set(id, self.get(id)? - ((delta * -1) as usize))
        } else {
            self.set(id, self.get(id)? + (delta as usize))
        }
    }
}
