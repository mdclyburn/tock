//! Memory statistic tracking.

use core::fmt::{
    self,
    Display,
};

use crate::errorcode::ErrorCode;
use crate::process::ProcessId;

pub static mut INSTANCE: Option<&dyn MemoryStatistics> = None;

/// Memory statistic category
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum CounterId {
    Grant(ProcessId),
}

impl Display for CounterId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use CounterId::*;
        match self {
            Grant(ref pid) => write!(f, "grant for process {}", pid.id()),
        }
    }
}

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
