use core::cell::Cell;

use kernel::errorcode::ErrorCode;
use kernel::hil::time::{Counter, Frequency, Ticks, OverflowClient};
use kernel::hil::uart::{Transmit, TransmitClient};
use kernel::utilities::cells::{MapCell, OptionalCell, TakeCell};

use crate::proto;
use crate::proto::Message;

#[derive(Copy, Clone)]
struct Stat {
    acc: u32,
    t_latest: u64,
    is_frozen: bool,
}

impl Stat {
    fn new() -> Stat {
        Stat {
            acc: 0,
            t_latest: 0,
            is_frozen: false,
        }
    }

    fn freeze(&mut self) {
        self.is_frozen = true;
    }

    fn reset(&mut self) {
        self.acc = 0;
        self.is_frozen = false;
    }

    fn account(&mut self, time: u64, val: u32) {
        if !self.is_frozen {
            self.acc += val;
            self.t_latest = time;
        }
    }
}

#[derive(Copy, Clone, PartialEq)]
enum CollectionState {
    Collecting,
    Freezing(u8),
    Waiting,
}

pub struct PerformanceCounter<F: 'static + Frequency, T: 'static + Ticks> {
    overflow_count: Cell<u32>,
    counter: &'static dyn Counter<'static, Frequency = F, Ticks = T>,
    state: Cell<CollectionState>,
    no_waypoints: u8,
    tx: &'static dyn Transmit<'static>,
    tx_buffer: TakeCell<'static, [u8]>,
    stats: MapCell<[Stat; 8]>,
    t_start: Cell<u64>,
}

impl<F: Frequency, T: Ticks> PerformanceCounter<F, T> {
    pub fn new(
        counter: &'static dyn Counter<Frequency = F, Ticks = T>,
        no_waypoints: u8,
        tx: &'static dyn Transmit<'static>,
        tx_buffer: &'static mut [u8; proto::TX_BUFFER_LEN],
    ) -> PerformanceCounter<F, T>
    {
        PerformanceCounter {
            overflow_count: Cell::new(0),
            counter,
            state: Cell::new(CollectionState::Collecting),
            no_waypoints,
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
            t_start: Cell::new(0),
        }
    }

    pub fn configure(&'static self) {
        self.counter.set_overflow_client(self);
        self.tx.set_transmit_client(self);
    }

    pub fn start(&self) {
        let buffer = self.tx_buffer.take().unwrap();
        proto::put_header(&mut buffer[0..1], Message::Start);
        proto::put_signal(&mut buffer[1..], 32, 16);
        proto::send(self.tx, buffer);
    }

    pub fn freeze(&self) {
        self.state.set(CollectionState::Freezing(0));
    }

    fn account(&self, id: u8, val: u32) {
        // Grab the current timestamp.
        let now = self.counter.now().into_u32() as u64
            | ((self.overflow_count.get() as u64) << 32);

        // Accumulate the quantity in the stat counter.
        // We must either be in the Collecting state or the freeze must not have reached the given `id`.
        match self.state.get() {
            CollectionState::Collecting => { self.stats.map(|s| s[id as usize].account(now, val)); },

            CollectionState::Freezing(frozen_high) => {
                self.stats.map(|s| s[id as usize].account(now, val));
                // Decide if we can freeze this stat counter.
                // It must be the next counter in the sequence
                // and have reached the amount of data in the previous counter.
                let (is_next, saturated) = (
                    frozen_high + 1 == id,
                    self.stats.map(|s| s[id as usize].acc == s[frozen_high as usize].acc)
                        .unwrap()
                );

                if is_next && saturated {
                    self.state.set(CollectionState::Freezing(id));
                    // Start a transmission once we have frozen all counters.
                    if id == self.no_waypoints - 1 {
                        self.send();
                    }
                }
            },

            // There is nothing we can do to hold this new data.
            // The current set of stats are waiting for serialization to an outstanding buffer.
            // This is the "drop the data path".
            CollectionState::Waiting => {  }
        }
    }

    fn send(&self) {
        // If the transmit buffer is present, then we can begin transfer immediately.
        // When the UART is still sending the previous payload we cannot start a new send.
        if let Some(tx_buffer) = self.tx_buffer.take() {
            let len = self.stats.map(|stats| serialize_stats(tx_buffer, self.t_start.get(), &*stats))
                .unwrap();
            self.tx.transmit_buffer(tx_buffer, len);

            // Reset all stats and the the starting reference for the next round of stat collection.
            self.stats.map(|stats| {
                for s in stats {
                    s.reset();
                }
                self.t_start.set((self.overflow_count.get() as u64) << 32
                                 | self.counter.now().into_u32() as u64);
            });
            self.state.set(CollectionState::Collecting);
        } else {
            // We just return and have the callback trigger this for us.
            self.state.set(CollectionState::Waiting);
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

        // Start transmitting stats waiting to be sent.
        if self.state.get() == CollectionState::Waiting {
            self.send();
        }
    }
}

/* Performance data payload format

Header, 1 byte
B7 - payload type bit, set to 1

Start time, 8 bytes
B63:B0 - implementation-specific, up-to-64-bit counter value

Performance data, 12 bytes
B95:B32 - end time for data collection
B31:B0  - stat value
 */
fn serialize_stats(out_buffer: &mut [u8], t0: u64, stats: &[Stat]) -> usize {
    // Write the header.
    out_buffer[0] = 1 << 7;

    let mut b_no = 1;

    // Write the start time.
    serialize_u64(&mut out_buffer[b_no..b_no+8], t0);
    b_no += 8;

    // Write each performance stat.
    for stat in stats {
        serialize_u64(&mut out_buffer[b_no..b_no+8], stat.t_latest);
        serialize_u32(&mut out_buffer[b_no+8..b_no+12], stat.acc);
        b_no += 8 + 4;
    }

    b_no
}

#[inline]
fn serialize_u64(out_buffer: &mut [u8], val: u64) {
    for i in 0..8 {
        out_buffer[i] = ((val >> (8 * i)) & 0xFF) as u8;
    }
}

#[inline]
fn serialize_u32(out_buffer: &mut [u8], val: u32) {
    for i in 0..4 {
        out_buffer[i] = ((val >> (8 * i)) & 0xFF) as u8;
    }
}
