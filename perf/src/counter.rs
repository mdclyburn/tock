use core::cell::Cell;

use kernel::errorcode::ErrorCode;
use kernel::hil::time::{Counter, Frequency, Ticks, OverflowClient};
use kernel::hil::uart::{Transmit, TransmitClient};
use kernel::utilities::cells::{MapCell, OptionalCell, TakeCell};

use crate::proto;
use crate::proto::Message;

#[derive(Copy, Clone)]
struct Stat {
    time_upper: u32,
    time_lower: u32,
    data: u32,
}

impl Stat {
    pub fn new() -> Stat {
        Stat {
            time_upper: 0,
            time_lower: 0,
            data: 0,
        }
    }

    fn account(&mut self, time_upper: u32, time_lower: u32, data: u32) {
        self.time_upper = time_upper;
        self.time_lower = time_lower;
        self.data += data;
    }

    fn ready(&self) -> bool {
        self.data > 0
    }

    fn serialize_out(&mut self, buffer: &mut [u8]) {
        proto::put_performance_data(buffer, self.time_upper, self.time_lower, self.data);
        self.data = 0;
    }
}

pub struct PerformanceCounter<F: 'static + Frequency, T: 'static + Ticks> {
    overflow_count: Cell<u32>,
    counter: &'static dyn Counter<'static, Frequency = F, Ticks = T>,
    stat: OptionalCell<Stat>,
    tx: &'static dyn Transmit<'static>,
    tx_buffer: TakeCell<'static, [u8]>,
    stats: MapCell<[Stat; 8]>,
}

impl<F: Frequency, T: Ticks> PerformanceCounter<F, T> {
    pub fn new(
        counter: &'static dyn Counter<Frequency = F, Ticks = T>,
        tx: &'static dyn Transmit<'static>,
        tx_buffer: &'static mut [u8; proto::TX_BUFFER_LEN],
    ) -> PerformanceCounter<F, T>
    {
        PerformanceCounter {
            overflow_count: Cell::new(0),
            counter,
            stat: OptionalCell::empty(),
            tx,
            tx_buffer: TakeCell::new(tx_buffer),
            stats: MapCell::new([
                Stat::new(),
                Stat::new(),
                Stat::new(),
                Stat::new(),
                Stat::new(),
                Stat::new(),
                Stat::new(),
                Stat::new(),
            ]),
        }
    }

    pub fn configure(&'static self) {
        self.counter.set_overflow_client(self);
        self.tx.set_transmit_client(self);
    }

    pub fn start(&'static self) {
        let buffer = self.tx_buffer.take().unwrap();
        proto::put_header(&mut buffer[0..1], Message::Start);
        proto::put_signal(&mut buffer[1..], 32, 16);
        proto::send(self.tx, buffer);
    }

    fn account(&'static self, id: u8, val: u32) {
        // Grab the current timestamp.
        let (time_upper, time_lower) = (
            self.overflow_count.get(),
            self.counter.now().into_u32(),
        );

        // If the stat container holds some data, then the system was too fast,
        // and data will have to coalesce into a single bucket.
        // Otherwise, we make a new entry.
        self.stats.map(|s| s[id as usize].account(time_upper, time_lower, val));

        // If the buffer is missing, then a send is in progress.
        // We simply return and let the transmitted_buffer function start a new transfer.
        //
        // If the buffer is here, then we were previously idling.
        // Start a new transfer now.
        if let Some(tx_buffer) = self.tx_buffer.take() {
            // Iterate through all stats; send the first one that is ready.
            self.stats.map(|s| {
                for i in 0..8 {
                    if s[i].ready() {
                        proto::put_header(&mut tx_buffer[0..1], Message::PerformanceData(i as u8));
                        s[i].serialize_out(&mut tx_buffer[1..]);
                        break;
                    }
                }
            });

            // Send the data.
            proto::send(self.tx, tx_buffer);
        }
    }
}

impl<F: 'static + Frequency, T: 'static + Ticks> OverflowClient for PerformanceCounter<F, T> {
    fn overflow(&self) {
        self.overflow_count.set(self.overflow_count.get()+1);
    }
}

impl<F: Frequency, T: Ticks> TransmitClient for PerformanceCounter<F, T> {
    fn transmitted_buffer(
        &self,
        tx_buffer: &'static mut [u8],
        tx_len: usize,
        rval: Result<(), ErrorCode>)
    {
        self.tx_buffer.put(Some(tx_buffer));
    }
}
