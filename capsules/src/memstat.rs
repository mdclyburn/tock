//! Runtime memory statistics.

use core::cell::Cell;

use kernel::{
    ErrorCode,
    ProcessId,
    process,
    syscall::SyscallDriver,
    utilities::cells::TakeCell,
};

pub type Result<T> = core::result::Result<T, ErrorCode>;

/// Memory statistic category.
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum CounterId {
    Grant(ProcessId),
}

pub struct MemoryCounterNode {
    id: CounterId,
    val: Cell<usize>,
}

pub struct MemoryStatistics {
    counters: TakeCell<'static, [Option<MemoryCounterNode>]>,
}

impl MemoryStatistics {
    pub fn new(counters: &'static mut [Option<MemoryCounterNode>]) -> MemoryStatistics {
        MemoryStatistics {
            counters: TakeCell::new(counters),
        }
    }

    fn with_counter<F>(&self, id: CounterId, fun: F) -> Result<()>
    where
        F: FnOnce(&mut MemoryCounterNode),
    {
        self.counters.map(|counters| {
            let res = counters.iter_mut()
                .filter_map(|opt_node| opt_node.as_mut())
                .find(|opt_node| opt_node.id == id);
            if let Some(counter) = res {
                fun(counter);
                Ok(())
            } else {
                let next_empty = counters.iter_mut()
                    .filter(|opt_node| opt_node.is_none())
                    .next();
                if let Some(counter) = next_empty {
                    *counter = Some(MemoryCounterNode {
                        id,
                        val: Cell::new(0),
                    });
                    fun(counter.as_mut().unwrap());

                    Ok(())
                } else {
                    Err(ErrorCode::NOMEM)
                }
            }
        }).unwrap()
    }

    pub fn set(&self, id: CounterId, val: usize) -> Result<()> {
        self.with_counter(id, |counter| counter.val.set(val))
    }

    pub fn modify(&self, id: CounterId, delta: isize) -> Result<()> {
        self.with_counter(id, |counter| {
            let delta = if delta < 0 {
                (delta * -1) as usize
            } else {
                delta as usize
            };
            let val = counter.val.get().saturating_sub(delta);
            counter.val.set(val);
        })
    }
}

impl SyscallDriver for MemoryStatistics {
    fn allocate_grant(&self, _process_id: ProcessId) -> core::result::Result<(), process::Error> {
        Ok(())
    }
}
