use core::cell::Cell;

use kernel::errorcode::ErrorCode;
use kernel::hil::time::{Counter, Frequency, Ticks, Ticks32, OverflowClient};
use kernel::hil::uart::{Transmit, TransmitClient};
use kernel::platform::chip::Chip;
use kernel::platform::mpu::MPU;
use kernel::utilities::cells::{MapCell, TakeCell};
use perf_support::Accumulate;

use crate::proto;
use crate::proto::Stat;

/// Performance benchmarking instance.
pub static mut INSTANCE: Option<&'static dyn Accumulate> = None;

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
        tx_buffer: &'static mut [u8; proto::TX_BUFFER_BYTE_LEN],
    ) -> PerformanceCounter<F>
    {
        PerformanceCounter {
            overflow_count: Cell::new(0),
            counter,
            state: Cell::new(CollectionState::Uninitialized),
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

    /// Perform the benchmarking initialization, triggering a transfer to the host.
    pub unsafe fn start<C: Chip>(&'static self, chip: &C) {
        use_instance(self);
        chip.mpu().ignore_configuration();

        self.configure();
        // Grab the transmission buffer.
        // This should definitely be here, and start() should only run once;
        // before any transmissions have begun.
        let buffer = self.tx_buffer.take().unwrap();
        let len = proto::serialize_init(buffer, F::frequency());
        self.tx.transmit_buffer(buffer, len)
            .unwrap();
    }

    /// Send stats to the host.
    fn send(&self) {
        // If the transmit buffer is present, then we can begin transfer immediately.
        // When the UART is still sending the previous payload we cannot start a new send.
        if let Some(tx_buffer) = self.tx_buffer.take() {
            let len = self.stats.map(|stats| proto::serialize_stats(tx_buffer, self.t_start.get(), &*stats))
                .unwrap();
            self.tx.transmit_buffer(tx_buffer, len)
                .unwrap();

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
        _tx_len: usize,
        rval: Result<(), ErrorCode>)
    {
        // Just unwrap this to make sure it is not an error.
        let _rval_check = rval.unwrap();

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

impl<F: Frequency> Accumulate for PerformanceCounter<F> {
    fn account(&self, id: u8, val: u32) {
        // Ensure that the ID of this waypoint is valid.
        // If it is not valid, the counter could send confusing timestamps and data.
        if id >= self.no_waypoints {
            panic!();
        }

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
                if id > frozen_high {
                    self.stats.map(|s| s[id as usize].account(now, val));
                    // Decide if we can freeze this stat counter.
                    // It must be the next counter in the sequence
                    // and have reached the amount of data in the previous counter.
                    let (is_next, saturated) = (
                        frozen_high + 1 == id,
                        self.stats.map(|s| s[id as usize].accumulated() == s[frozen_high as usize].accumulated())
                            .unwrap()
                    );

                    if is_next && saturated {
                        self.state.set(CollectionState::Freezing(id));
                        // Start a transmission once we have frozen all counters.
                        if id == self.no_waypoints - 1 {
                            self.send();
                        }
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

    /// Begin the freezing process, aggregating stats to send to the test host.
    fn freeze(&self) {
        // We must be in the collecting state to transition to the freeze.
        // And if we are already freezing, there is no need to do this.
        if self.state.get() != CollectionState::Collecting {
            return;
        }

        // Find out how far down the sequence we can freeze stats.
        let highest_frozen = self.stats.map(|stats| {
            let target = stats[0].accumulated();
            let mut i: u8 = 0;
            while stats[i as usize].accumulated() == target && i < self.no_waypoints { i += 1; }

            i - 1 // Invariant: i >= 1
        }).unwrap();

        // If we are unable to freeze all stats up to self.no_waypoints,
        // then we only set the state to Freezing(index of highest frozen stat)
        // and do not trigger a transmission.
        if highest_frozen + 1 == self.no_waypoints {
            self.send()
        } else {
            self.state.set(CollectionState::Freezing(highest_frozen))
        }
    }
}

unsafe fn use_instance(instance: &'static dyn Accumulate) {
    if INSTANCE.is_some() {
        panic!();
    } else {
        INSTANCE = Some(instance);
        perf_support::use_instance(instance);
    }
}

#[macro_export]
macro_rules! count {
    ($id:expr, $val:expr) => {{
        unsafe {
            $crate::INSTANCE.unwrap()
                .account(($id), ($val));
        }
    }};

    ($id:expr, $val:expr, $check:expr) => {{
        if ($check) {
            unsafe {
                $crate::INSTANCE.unwrap()
                    .account(($id), ($val));
            }
        }
    }}
}

#[macro_export]
macro_rules! freeze {
    () => {{
        unsafe {
            $crate::INSTANCE.unwrap()
                .freeze();
        }
    }};

    ($check:expr) => {{
        if ($check) {
            unsafe {
                $crate::INSTANCE.unwrap()
                    .freeze()
            }
        }
    }}
}

/// Call for Tock-external code to provide performance data
pub extern "C" fn account_ffi(id: u8, val: u32) { count!(id, val); }
