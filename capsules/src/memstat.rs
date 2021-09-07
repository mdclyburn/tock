//! Runtime memory statistics.

use core::cell::Cell;

use kernel::{
    debug,
    hil::memstat::{
        CounterId,
        MemoryStatistics,
    },
    ReturnCode,
    common::cells::TakeCell,
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

    fn with_counter<F, T>(&self, id: CounterId, fun: F) -> Result<T, ReturnCode>
    where
        F: FnOnce(&mut SimpleMemoryCounterNode) -> Result<T, ReturnCode>,
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
                    Err(ReturnCode::ENOMEM)
                }
            }
        }).unwrap()
    }
}

impl MemoryStatistics for SimpleMemoryStatistics {
    fn get(&self, id: CounterId) -> Result<usize, ReturnCode> {
        self.with_counter(id, |counter| Ok(counter.val.get()) )
    }

    fn set(&self, id: CounterId, bytes_used: usize) -> Result<(), ReturnCode> {
        debug!("{} uses {} bytes", id, bytes_used);
        self.with_counter(id, |counter| {
            counter.val.set(bytes_used);
            Ok(())
        })
    }
}
