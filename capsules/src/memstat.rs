//! Runtime memory statistics.

use core::cell::Cell;

use kernel::{
    ErrorCode,
    ProcessId,
    hil::memstat::{
        CounterId,
        MemoryStatistics,
    },
    process,
    syscall::SyscallDriver,
    utilities::cells::TakeCell,
};

pub struct SimpleMemoryCounterNode {
    id: CounterId,
    val: Cell<usize>,
}

pub struct SimpleMemoryStatistics {
    counters: TakeCell<'static, [Option<SimpleMemoryCounterNode>]>,
}

impl SimpleMemoryStatistics {
    pub fn new(counters: &'static mut [Option<SimpleMemoryCounterNode>]) -> SimpleMemoryStatistics {
        SimpleMemoryStatistics {
            counters: TakeCell::new(counters),
        }
    }

    fn with_counter<F, T>(&self, id: CounterId, fun: F) -> Result<T, ErrorCode>
    where
        F: FnOnce(&mut SimpleMemoryCounterNode) -> Result<T, ErrorCode>,
    {
        self.counters.map(|counters| {
            let res = counters.iter_mut()
                .filter_map(|opt_node| opt_node.as_mut())
                .find(|opt_node| opt_node.id == id);
            if let Some(counter) = res {
                fun(counter)
            } else {
                let next_empty = counters.iter_mut()
                    .filter(|opt_node| opt_node.is_none())
                    .next();
                if let Some(counter) = next_empty {
                    *counter = Some(SimpleMemoryCounterNode {
                        id,
                        val: Cell::new(0),
                    });
                    fun(counter.as_mut().unwrap())
                } else {
                    Err(ErrorCode::NOMEM)
                }
            }
        }).unwrap()
    }
}

impl MemoryStatistics for SimpleMemoryStatistics {
    fn get(&self, id: CounterId) -> Result<usize, ErrorCode> {
        self.with_counter(id, |counter| Ok(counter.val.get()) )
    }

    fn set(&self, id: CounterId, bytes_used: usize) -> Result<(), ErrorCode> {
        self.with_counter(id, |counter| {
            counter.val.set(bytes_used);
            Ok(())
        })
    }

    fn modify<F>(&self, id: CounterId, mod_fun: F) -> Result<(), ErrorCode>
    where
        F: FnOnce(usize) -> usize,
    {
        self.set(id, mod_fun(self.get(id)?))?;
        Ok(())
    }
}

impl SyscallDriver for SimpleMemoryStatistics {
    fn allocate_grant(&self, _process_id: ProcessId) -> core::result::Result<(), process::Error> {
        Ok(())
    }
}
