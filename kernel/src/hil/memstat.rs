//! Memory statistic tracking.

use core::fmt::{
    self,
    Display,
};

use crate::returncode::ReturnCode;
use crate::callback::AppId;

pub static mut INSTANCE: Option<&dyn MemoryStatistics> = None;

/// Memory statistic category
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum CounterId {
    /// Total for allocated grant types.
    AllGrantStructures(AppId),
    /// Sizes of individual grants.
    Grant(AppId, usize),
    /// Grant pointer table.
    GrantPointerTable(AppId),
    /// Process control block.
    PCB(AppId),
    /// Upcall queue.
    UpcallQueue(AppId),
}

impl Display for CounterId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use CounterId::*;
        match self {
            AllGrantStructures(ref pid) => write!(f, "grant total for {}", pid.id()),
            Grant(ref pid, grant_no) => write!(f, "grant #{} for process {}", grant_no, pid.id()),
            GrantPointerTable(ref pid) => write!(f, "grant pointer table for process {}", pid.id()),
            PCB(ref pid) => write!(f, "PCB for process {}", pid.id()),
            UpcallQueue(ref pid) => write!(f, "upcall queue for process {}", pid.id()),
        }
    }
}

pub trait MemoryStatistics {
    /// Returns the memory usage accounted to the counter.
    fn get(&self, id: CounterId) -> Result<usize, ReturnCode>;

    /// Assign the memory usage to a specific counter.
    fn set(&self, id: CounterId, bytes_used: usize) -> Result<(), ReturnCode>;

    /// Change the current memory usage for a counter.
    fn modify(&self, id: CounterId, delta: isize) -> Result<(), ReturnCode> {
        let new_val = if delta < 0 {
            self.get(id)?.checked_sub((delta * -1) as usize)
                .ok_or(ReturnCode::FAIL)?
        } else {
            self.get(id)?.checked_add(delta as usize)
                .ok_or(ReturnCode::FAIL)?
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
