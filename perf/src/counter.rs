use core::cell::Cell;

use kernel::errorcode::ErrorCode;
use kernel::hil::time::{Counter, Frequency, Ticks, Ticks32, OverflowClient};
use kernel::hil::uart::{Transmit, TransmitClient};
use kernel::utilities::cells::{MapCell, OptionalCell, TakeCell};

/// Container for performance data.
#[derive(Copy, Clone)]
struct Stat {
    acc: u32,
    t_latest: u64,
}

impl Stat {
    fn new() -> Stat {
        Stat {
            acc: 0,
            t_latest: 0,
        }
    }

    fn reset(&mut self) {
        self.acc = 0;
    }

    fn account(&mut self, time: u64, val: u32) {
        self.acc += val;
        self.t_latest = time;
    }
}

/// FSM states for stat collection.
#[derive(Copy, Clone, PartialEq)]
enum CollectionState {
    /// Performance counter is not completely initialized.
    Uninitialized,
    /// Collecting performance data from trace points.
    Collecting,
    /// Selectively collecting performance data from unfrozen trace points, rejecting others.
    Freezing(u8),
    /// Unable to collect stat information due to TX buffer being in-flight.
    Waiting,
}

pub struct PerformanceCounter<F: 'static + Frequency> {
    overflow_count: Cell<u32>,
    counter: &'static dyn Counter<'static, Frequency = F, Ticks = Ticks32>,
    state: Cell<CollectionState>,
    no_waypoints: u8,
    tx: &'static dyn Transmit<'static>,
    tx_buffer: TakeCell<'static, [u8]>,
    stats: MapCell<[Stat; 8]>,
    t_start: Cell<u64>,
}

impl<F: Frequency> PerformanceCounter<F> {
    /// Create a performance counting instance.
    pub fn new(
        counter: &'static dyn Counter<Frequency = F, Ticks = Ticks32>,
        no_waypoints: u8,
        tx: &'static dyn Transmit<'static>,
        tx_buffer: &'static mut [u8; TX_BUFFER_BYTE_LEN],
    ) -> PerformanceCounter<F>
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

    fn configure(&'static self) {
        self.counter.set_overflow_client(self);
        self.tx.set_transmit_client(self);
    }

    /// Perform the initialization step, triggering a transfer to the host.
    pub fn start(&self) {
        // Grab the transmission buffer.
        // This should definitely be here, and start() should only run once;
        // before any transmissions have begun.
        let buffer = self.tx_buffer.take().unwrap();
        let len = serialize_init(buffer, F::frequency());
        self.tx.transmit_buffer(buffer, len);
    }

    /// Begin the freezing process, aggregating stats to send to the test host.
    pub fn freeze(&self) {
        // We must be in the collecting state to transition to the freeze.
        if self.state.get() != CollectionState::Collecting { panic!(); }
        self.state.set(CollectionState::Freezing(0));
    }

    /// Accumulate data in a stat counter.
    pub fn account(&self, id: u8, val: u32) {
        // Grab the current timestamp.
        let now = self.counter.now().into_u32() as u64
            | ((self.overflow_count.get() as u64) << 32);

        // Accumulate the quantity in the stat counter.
        // We must either be in the Collecting state or the freeze must not have reached the given `id`.
        match self.state.get() {
            // It is fine to collect stats when uninitialized,
            // just not OK to try sending them when initialization has not occured.
            CollectionState::Uninitialized
                | CollectionState::Collecting => {
                    self.stats.map(|s| s[id as usize].account(now, val));
                },

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
            // A better solution might be to use two buffers (stats and [u8]),
            // but this comes at the cost of complexity.
            CollectionState::Waiting => {  }
        }
    }

    /// Send stats to the host.
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

impl<F: 'static + Frequency> OverflowClient for PerformanceCounter<F> {
    /// Count the overflows that occur to widen the time range.
    fn overflow(&self) {
        self.overflow_count.set(self.overflow_count.get()+1);
    }
}

impl<F: Frequency> TransmitClient for PerformanceCounter<F> {
    fn transmitted_buffer(
        &self,
        tx_buffer: &'static mut [u8],
        tx_len: usize,
        rval: Result<(), ErrorCode>)
    {
        // Put the buffer back.
        self.tx_buffer.put(Some(tx_buffer));

        // Trigger another transmission if another set of stats are waiting to be sent.
        if self.state.get() == CollectionState::Waiting {
            self.send();
        }

        // System is free to start collecting samples now.
        // The stats structures are guaranteed to be free at this point.
        self.state.set(CollectionState::Collecting);
    }
}

/* Initialization payload format

Header, 1 byte
B7 - payload type bit, set to 0

Counter frequency, 4 bytes
B31:B0 - frequency of the underlying counter
 */

/* Performance data payload format

Header, 1 byte
B7 - payload type bit, set to 1

Start time, 8 bytes
B63:B0 - implementation-specific, up-to-64-bit counter value

Performance data, 12 bytes
B95:B32 - end time for data collection
B31:B0  - stat value
 */

pub const TX_BUFFER_BYTE_LEN: usize =
    // Header
    1
    // Start time
    + 8
    // Stats
    + (8 * (8 + 4));

fn serialize_init(out_buffer: &mut [u8], counter_freq: u32) -> usize {
    // Write the header.
    out_buffer[0] = 0;

    let mut b_no = 1;

    // Write the counter frequency.
    serialize_u32(&mut out_buffer[1..], counter_freq);
    b_no += 4;

    b_no
}

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
