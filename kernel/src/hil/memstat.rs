//! Memory statistic tracking.

use crate::errorcode::ErrorCode;
use crate::process::ProcessId;

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
    fn modify<F>(&self, id: CounterId, mod_fun: F) -> Result<(), ErrorCode>
    where
        F: FnOnce(usize) -> usize;
}
