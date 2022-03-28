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

/// Stat containers for profiling.
static mut STATS: [Stat; 8] = [Stat::new(); 8];

pub struct PerformanceCounter<CHIP: 'static + Chip, F: 'static + Frequency> {
    chip: &'static CHIP,
    overflow_count: Cell<u32>,
    counter: &'static dyn Counter<'static, Frequency = F, Ticks = Ticks32>,
    state: Cell<CollectionState>,
    no_waypoints: u8,
    tx: &'static dyn Transmit<'static>,
    tx_buffer: TakeCell<'static, [u8]>,
    t_start: Cell<u64>,
}

impl<CHIP: 'static + Chip, F: Frequency> PerformanceCounter<CHIP, F> {
    /// Create a performance counting instance.
    pub unsafe fn new(
        chip: &'static CHIP,
        counter: &'static dyn Counter<Frequency = F, Ticks = Ticks32>,
        no_waypoints: u8,
        tx: &'static dyn Transmit<'static>,
        tx_buffer: &'static mut [u8; proto::TX_BUFFER_BYTE_LEN],
    ) -> PerformanceCounter<CHIP, F>
    {
        PerformanceCounter {
            chip,
            overflow_count: Cell::new(0),
            counter,
            state: Cell::new(CollectionState::Uninitialized),
            no_waypoints,
            tx,
            tx_buffer: TakeCell::new(tx_buffer),
            t_start: Cell::new(0),
        }
    }

    fn configure(&'static self) {
        self.counter.set_overflow_client(self);
        self.tx.set_transmit_client(self);
    }

    /// Perform the benchmarking initialization, triggering a transfer to the host.
    pub unsafe fn start<C: 'static + Chip>(&'static self, chip: &C) {
        use_instance(self);
        chip.mpu().ignore_configuration();

        // Set the start value.
        self.t_start.set(self.counter.now().into_u32() as u64);

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
    ///
    /// # Safety
    /// Only call this function in an atomic context to guarantee counters will not change.
    fn send(&self) {
        // If the transmit buffer is present, then we can begin transfer immediately.
        // When the UART is still sending the previous payload we cannot start a new send.
        if let Some(tx_buffer) = self.tx_buffer.take() {
            let len = proto::serialize_stats(
                tx_buffer,
                self.t_start.get(),
                // We are effectively reading all stat container values.
                // This is fine in this function because we only call send() when all counters are frozen.
                unsafe { &STATS[0..(self.no_waypoints as usize)] });
            self.tx.transmit_buffer(tx_buffer, len)
                .unwrap();

            // Reset all stats and the the starting reference for the next round of stat collection.
            // Write to Stat containers.
            // All Stats are still frozen at this point, so this is okay,
            // as no instrumentation points will be able to write to their respective container.
            let iter = unsafe { STATS.iter_mut() };
            for s in iter {
                s.reset();
            }
            self.t_start.set((self.overflow_count.get() as u64) << 32
                             | self.counter.now().into_u32() as u64);

            // Ready to start collecting data once again.
            self.state.set(CollectionState::Collecting);
        } else {
            // We just return and have the callback trigger this for us.
            self.state.set(CollectionState::Waiting);
        }
    }
}

impl<CHIP: 'static + Chip, F: 'static + Frequency> OverflowClient for PerformanceCounter<CHIP, F> {
    /// Count the overflows that occur to widen the time range.
    fn overflow(&self) {
        self.overflow_count.set(self.overflow_count.get()+1);
    }
}

impl<CHIP: 'static + Chip, F: Frequency> TransmitClient for PerformanceCounter<CHIP, F> {
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
        let collection_state = unsafe { self.chip.atomic(|| self.state.get()) };
        if collection_state == CollectionState::Waiting {
            self.send();
        }

        // System is free to start collecting samples now.
        // The stats structures are guaranteed to be free at this point.
        unsafe { self.chip.atomic(|| self.state.set(CollectionState::Collecting)) }
    }
}

impl<CHIP: 'static + Chip, F: Frequency> Accumulate for PerformanceCounter<CHIP, F> {
    fn account(&self, id: u8, val: u32) {
        // Ensure that the ID of this waypoint is valid.
        // If it is not valid, the counter could send confusing timestamps and data.
        if id >= self.no_waypoints {
            panic!();
        }

        // This block of code is inspecting state (the CollectionState);
        // not performing the accounting atomically would introduce a race.
        // It would also be undesirable to have the timestamp collected before
        // being interrupted by some other event.
        let ma = unsafe { self.chip.atomic(|| {
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
                        // Writing to a single stat container.
                        // This is fine as long as the tester ensures that there is
                        // only one instrumentation point writing to a container at a time.
                        unsafe { STATS[id as usize].account(now, val) };
                    },

                CollectionState::Freezing(frozen_high) => {
                    if id > frozen_high {
                        // Write to a single stat container.
                        // Okay under the single-instrumentation-point assumption.
                        unsafe { STATS[id as usize].account(now, val) };

                        // Decide if we can freeze this stat counter.
                        // It must be the next counter in the sequence
                        // and have reached the amount of data in the previous counter.
                        let (is_next, saturated) = (
                            frozen_high + 1 == id,
                            // Reading from two stat containers.
                            // The read of STATS[id] is okay since its agent is doing the read.
                            // The second read is okay because it is the data for a frozen stat
                            // which will not change from under us.
                            unsafe { STATS[id as usize].accumulated() == STATS[frozen_high as usize].accumulated() }
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
            };

            STATS[0].accumulated() == 1114
        }) };

        if ma { self.freeze(); }
    }

    /// Begin the freezing process, aggregating stats to send to the test host.
    fn freeze(&self) {
        // There are a couple of reasons for this all-encompassing atomicity...
        //
        // We must at least atomically freeze the first instrumentation point.
        // This is necessary since we will shortly be using its value to decide
        // how to advance the freeze. If the value changes in the meantime, i.e.,
        // we receive additional data to account, the 0th stat would have a later timestamp
        // than the correct timestamp.
        //
        // We must also read all other stat containers' values to know how far
        // the freeze can proceed.
        //
        // We must change the collection state to one that prevents instrumentation
        // points from changing stat container values.
        let no_frozen: usize = unsafe { self.chip.atomic(|| {
            // We must be in the collecting state to transition to the freeze.
            // And if we are already freezing, there is no need to do this.
            if self.state.get() != CollectionState::Collecting {
                // A zero here will always prevent the send from occurring;
                0
            } else {
                // Find out how far down the sequence we can freeze stats.
                let highest_frozen: usize = {
                    // Decide the value all containers must reach.
                    // It is fine to read the 0th stat container because it is frozen.
                    let target = STATS[0].accumulated();

                    let mut i: usize = 0;
                    // TODO: start the iteration at 1 since 0 is guaranteed to be frozen?
                    while STATS[i].accumulated() == target && i < self.no_waypoints as usize { i += 1; }
                    i - 1
                };

                self.state.set(CollectionState::Freezing(highest_frozen as u8));
                highest_frozen + 1
            }
        }) };

        // Only trigger the transmission if we are able to freeze all stats.
        // If this is not the case, then the rest of the freeze will happen
        // incrementally as we finish accumulating data.
        if no_frozen == self.no_waypoints as usize {
            // It is OK for this call to send() to be outside of an atomic context.
            // All stat counters are frozen and will not change in the mean time.
            self.send();
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
