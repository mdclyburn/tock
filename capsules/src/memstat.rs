//! Runtime memory statistics.

use core::cell::Cell;

use kernel::{
    ErrorCode,
    ProcessId,
    debug,
    hil::{
        memstat::{
            CounterId,
            MemoryStatistics,
        },
        uart::{
            self,
            TransmitClient,
            Uart,
        },
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
        debug!("{} uses {} bytes", id, bytes_used);
        self.with_counter(id, |counter| {
            counter.val.set(bytes_used);
            Ok(())
        })
    }
}

impl SyscallDriver for SimpleMemoryStatistics {
    fn allocate_grant(&self, _process_id: ProcessId) -> Result<(), process::Error> {
        Ok(())
    }
}

pub struct MemoryStatisticsBridge<'a> {
    uart: &'a dyn Uart<'a>,
    tx_buffer: TakeCell<'static, [u8]>,
}

impl<'a> MemoryStatisticsBridge<'a> {
    pub fn new(uart: &'a dyn Uart<'a>,
               buffer: &'static mut [u8]) -> MemoryStatisticsBridge<'a> {
        uart.configure(uart::Parameters {
            baud_rate: 115200,
            width: uart::Width::Eight,
            parity: uart::Parity::Even,
            stop_bits: uart::StopBits::One,
            hw_flow_control: false,
        }).expect("Failed to configure UART for memory statistics.");

        MemoryStatisticsBridge {
            uart,
            tx_buffer: TakeCell::new(buffer),
        }
    }
}

impl<'a> MemoryStatistics for MemoryStatisticsBridge<'a> {
    /// Retrieval of counters not supported here and will always return an error.
    fn get(&self, _id: CounterId) -> Result<usize, ErrorCode> {
        Err(ErrorCode::NOSUPPORT)
    }

    fn set(&self, id: CounterId, bytes_used: usize) -> Result<(), ErrorCode> {
        let mut tx_buffer: Option<_> = self.tx_buffer.take();
        while tx_buffer.is_none() {
            self.uart.poll_service();
            tx_buffer = self.tx_buffer.take();
        }
        let tx_buffer = tx_buffer.unwrap();

        tx_buffer[0] = ((u8::from(id)) << 1) | 0b0000_0001;
        tx_buffer[1] = (bytes_used & 0xFF) as u8;
        tx_buffer[2] = ((bytes_used >> 8) & 0xFF) as u8;
        tx_buffer[3] = ((bytes_used >> 16) & 0xFF) as u8;
        tx_buffer[4] = ((bytes_used >> 24) & 0xFF) as u8;

        let r = self.uart.transmit_buffer(tx_buffer, 5);
        if let Err((error_code, tx_buffer)) = r {
            self.tx_buffer.put(Some(tx_buffer));
            Err(error_code)
        } else {
            Ok(())
        }
    }

    fn modify(&self, id: CounterId, delta: isize) -> Result<(), ErrorCode> {
        let delta: usize = if delta < 0 {
            unimplemented!("Decreasing memory counter not supported.");
        } else {
            delta as usize
        };

        let mut tx_buffer: Option<_> = self.tx_buffer.take();
        while tx_buffer.is_none() {
            self.uart.poll_service();
            tx_buffer = self.tx_buffer.take();
        }
        let tx_buffer = tx_buffer.unwrap();

        tx_buffer[0] = (u8::from(id)) << 1;
        tx_buffer[1] = (delta & 0xFF) as u8;
        tx_buffer[2] = ((delta >> 8) & 0xFF) as u8;
        tx_buffer[3] = ((delta >> 16) & 0xFF) as u8;
        tx_buffer[4] = ((delta >> 24) & 0xFF) as u8;

        let r = self.uart.transmit_buffer(tx_buffer, 5);
        if let Err((error_code, tx_buffer)) = r {
            self.tx_buffer.put(Some(tx_buffer));
            Err(error_code)
        } else {
            Ok(())
        }
    }
}

impl<'a> TransmitClient for MemoryStatisticsBridge<'a> {
    fn transmitted_buffer(
        &self,
        tx_buffer: &'static mut [u8],
        _tx_len: usize,
        _rval: Result<(), ErrorCode>)
    {
        self.tx_buffer.put(Some(tx_buffer));
    }
}
