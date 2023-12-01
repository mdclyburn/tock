/** Hail peripheral operation batching strategies.
 */

use core::cell::Cell;

use kernel::batch;
use kernel::batch::{
    BatchController,
    BatchingState,
    PendingSyscall,
    QueueResult,
};
use kernel::hil::time;
use kernel::hil::time::{
    Alarm,
    AlarmClient,
    Ticks as _,
    Frequency as _,
};
use kernel::process::{
    FunctionCall,
    Process,
    ProcessId
};
use kernel::static_init;
use kernel::syscall::Syscall;
use kernel::process::Task;
use kernel::utilities::cells::OptionalCell;

type BatchAlarm = dyn Alarm<'static,
                            Frequency = time::Freq16KHz,
                            Ticks = time::Ticks32>;

/// Batching based on a fixed amount of time passing since the first operation arrived.
pub struct TimeWindowBatching {
    batching_state: Cell<BatchingState>,
    /// Batch window duration in milliseconds.
    window_duration_ms: usize,
    /// Alarm used for time window batching.
    batch_alarm: &'static BatchAlarm,
    /// Alarm driver applications interact with.
    alarm_driver: &'static dyn AlarmClient,
    /// Time that the batch window expires; (reference, dt).
    next_expiration: OptionalCell<(usize, usize)>,
    /// The latest unexpired timer; (reference, dt).
    latest_alarm: Cell<(usize, usize)>,
    /// Batched syscalls.
    pending_syscalls: [OptionalCell<PendingSyscall>; 30],
}

impl TimeWindowBatching {
    pub fn new(window_duration_ms: usize,
               batch_alarm: &'static BatchAlarm,
               alarm_driver: &'static dyn AlarmClient)
               -> TimeWindowBatching
    {
        TimeWindowBatching {
            batching_state: Cell::new(BatchingState::Batch),
            window_duration_ms,
            batch_alarm,
            alarm_driver,
            next_expiration: OptionalCell::empty(),
            latest_alarm: Cell::new((0, 0)),
            pending_syscalls: [
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
            ],
        }
    }

    fn open_batch_window(&self) {
        if self.next_expiration.is_none() {
            let now = self.batch_alarm.now();
            // Hard-coded for Hail using a 16kHz timer.
            let window_duration_ticks = (time::Freq16KHz::frequency() as usize / 1000)
                * self.window_duration_ms;

            // Hard-coded for Hail which has a 32-bit timer.
            self.batch_alarm.set_alarm(now, time::Ticks32::from(window_duration_ticks as u32));

            let expiration = (now.into_usize(), window_duration_ticks as usize);
            self.next_expiration.set(expiration);
            // debug!("batch window: {:?}", expiration);
        }
    }
}

impl BatchController for TimeWindowBatching {
    fn check_enqueue<'a>(&self, invoking_process: &dyn Process, syscall: &'a Syscall) -> QueueResult<'a> {
        match syscall {
            // Driver checks do not need queueing.
            Syscall::Command { driver_number: _, subdriver_number: 0, .. } =>
                QueueResult::Run(syscall),

            // Alarm driver syscalls work differently...
            // We modified the alarm capsule to not actually interact with the bottom-half.
            // So, applications can register all the alarms they want.
            // Since the kernel controls the timer, the kernel will call into the alarm capsule
            // to make sure it eventually handles expired alarms set by applications.
            //
            // Instead of queueing the syscall, we let it through and make sure to open a batch window
            // so that we will service this alarm eventually.
            //
            // Perhaps how applications use the alarms should determine the size of the batching window?
            Syscall::Command { driver_number: 0,
                               subdriver_number,
                               arg0: syscall_reference,
                               arg1: syscall_dt } =>
            {
                if *subdriver_number == batch::ALARM_COMMAND_SET_ALARM {
                    // kernel::debug!("alarm: {:?}", syscall);
                }

                // Update the instant for the latest alarm set.
                let (latest_reference, latest_dt) = self.latest_alarm.get();
                if (latest_reference + latest_dt) < (syscall_reference + syscall_dt) {
                    self.latest_alarm.set((*syscall_reference, *syscall_dt));
                }

                // Make sure the batch window is open.
                self.open_batch_window();

                // Make the kernel handle the syscall into the alarm capsule now.
                QueueResult::Run(syscall)
            },

            // All other commands should go to the queue for later execution.
            Syscall::Command { .. } => {
                let empty_slot = self.pending_syscalls.iter()
                    .find(|oc| oc.is_none())
                    .expect("pending syscall overflow");
                let pending_syscall = PendingSyscall::new(invoking_process.processid(), *syscall);
                empty_slot.set(pending_syscall);
                // Now that we have a pending syscall, we ensure that we have a batch window open.
                self.open_batch_window();
                // debug!("queued: {:?}", pending_syscall.syscall);
                QueueResult::Queued
            },

            // Any non-command syscalls should execute immediately.
            _ => QueueResult::Run(syscall),
        }
    }

    /// Remove a syscall from the queue.
    fn dequeue_syscall(&self) -> Option<(ProcessId, Syscall)> {
        let opt_oc_pnd_syscall = self.pending_syscalls.iter()
            .find(|oc| oc.is_some());

        if let Some(oc_pnd_syscall) = opt_oc_pnd_syscall {
            oc_pnd_syscall
                .take()
                .map(|pnd_syscall| (pnd_syscall.pid, pnd_syscall.syscall))
        } else {
            None
        }
    }

    /// Returns the current batching state.
    fn state(&self, _k: bool) -> BatchingState {
        self.batching_state.get()
    }

    fn notify_upcalls_completed(&self) {
        self.batching_state.set(BatchingState::RunSyscalls);
    }

    fn notify_syscalls_completed(&self) {
        self.batching_state.set(BatchingState::Batch);
        self.open_batch_window();
    }
}

impl AlarmClient for TimeWindowBatching {
    /// Batch window expiration handler.
    ///
    /// Run pending syscalls and also notify the alarm driver of expiration.
    fn alarm(&self) {
        // debug!("batch window expired");
        self.next_expiration.clear();

        // Alarm upcalls could lead to other operations becoming queued.
        // Perhaps we should execute those as well while we are executing syscalls?
        self.alarm_driver.alarm();

        // The next step is to run upcalls (and possibly collect their syscalls).
        self.batching_state.set(BatchingState::CollectUpcalls);
    }
}

/// Batching based on how we know the system will be active in the future.
pub struct ResponsiveBatching {
    current_window_size_ms: Cell<usize>,
    last_window_update: Cell<usize>,
    last_syscall: Cell<usize>,
    /// Current batching state.
    batching_state: Cell<BatchingState>,
    /// Active alarm durations.
    active_alarms: [OptionalCell<(usize, usize)>; 5],
    /// Alarm used for time window batching.
    batch_alarm: &'static BatchAlarm,
    /// Alarm driver applications interact with.
    alarm_driver: &'static dyn AlarmClient,
    /// Time that the batch window expires; (reference, dt).
    next_expiration: OptionalCell<(usize, usize)>,
    /// The latest unexpired timer; (reference, dt).
    latest_alarm: Cell<(usize, usize)>,
    /// Batched syscalls.
    pending_syscalls: [OptionalCell<PendingSyscall>; 10],
    /// Latest issuance of distinct syscalls that get batched.
    syscall_history: [OptionalCell<usize>; 10],
    syscall_history_next: Cell<usize>,
}

impl ResponsiveBatching {
    pub fn new(batch_alarm: &'static BatchAlarm,
               alarm_driver: &'static dyn AlarmClient)
               -> ResponsiveBatching
    {
        ResponsiveBatching {
            current_window_size_ms: Cell::new(Self::MAX_WINDOW_TICKS * 1_000 / 16_000),
            last_window_update: Cell::new(batch_alarm.now().into_usize()),
            last_syscall: Cell::new(batch_alarm.now().into_usize()),
            batching_state: Cell::new(BatchingState::Batch),
            active_alarms: [OptionalCell::empty(),
                            OptionalCell::empty(),
                            OptionalCell::empty(),
                            OptionalCell::empty(),
                            OptionalCell::empty()],
            batch_alarm,
            alarm_driver,
            next_expiration: OptionalCell::empty(),
            latest_alarm: Cell::new((0, 0)),
            pending_syscalls: [
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
            ],
            syscall_history: [
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
            ],
            syscall_history_next: Cell::new(0),
        }
    }

    fn syscall_queue_len(&self) -> usize {
        self.pending_syscalls.iter()
            .filter(|optc| optc.is_some())
            .count()
    }

    const MAX_WINDOW_TICKS: usize = 32_000;
    // 3200 ticks, 200 ms.
    // const MIN_WINDOW_TICKS: usize = Self::MAX_WINDOW_TICKS - (Self::MAX_WINDOW_TICKS - Self::MAX_WINDOW_TICKS * 2 / 10);
    const MIN_WINDOW_TICKS: usize = 4_000;

    fn find_optimal_window(&self, observations: &[usize]) -> usize {
        let window_size_dec = 2_000;
        let mut window_size = Self::MAX_WINDOW_TICKS - window_size_dec;
        let mut best_batch_count = 0;
        let mut best_window_size = Self::MAX_WINDOW_TICKS;

        // kernel::debug!("finding optimal window from {} obs.", observations.len());

        'window: while window_size >= Self::MIN_WINDOW_TICKS {
            // Label points on the timeline.
            let mut labels_is_core_orig: [bool; 10] = [false; 10];
            let labels_is_core: &mut [bool] = &mut labels_is_core_orig[0..observations.len()];
            let range = window_size / 2;
            // kernel::debug!("window size: {}, range: {}", window_size, range);
            'labelling: for i in 0..labels_is_core.len() {
                let t_syscall = observations[i];

                let left_in_range = if i > 0 {
                    let dt = observations[i] - observations[i-1];
                    // kernel::debug!("ldt: {}", dt);
                    dt < range
                } else {
                    false
                };

                let right_in_range = if i < observations.len()-1 {
                    let dt = observations[i+1] - observations[i];
                    // kernel::debug!("rdt: {}", dt);
                    dt < range
                } else {
                    false
                };

                labels_is_core[i] = left_in_range || right_in_range;
                // if labels_is_core[i] {
                //     kernel::debug!("@{} CORE", observations[i]);
                // } else {
                //     kernel::debug!("@{} -", observations[i]);
                // }
            }

            // Optimization to speed up processing:
            // if there are no core points in the timeline, we stop processing here.
            // There is no need to try clustering if no point is close enough to another.
            let exists_core_points: bool = labels_is_core.iter()
                .find(|b| **b == true)
                .is_some();
            if !exists_core_points {
                break 'window;
            }

            let mut batch_count = 0;
            let mut in_window = false;
            let mut anchor_i = 0;
            let it = (0..)
                .zip(observations.iter()
                     .zip(observations.iter().skip(1)));
            for (i, (oa, ob)) in it {
                let mut batch_broken = false;
                if !labels_is_core[i] {
                    // Just iterating over noise until we find a core point.
                    continue;
                } else {
                    if !in_window {
                        // Since oa is a core point, we start a batch window here.
                        in_window = true;
                        anchor_i = i;
                        batch_count += 1;
                    }

                    // We are currently in a window.
                    // If ob is noise, then it always breaks the batch.
                    if !labels_is_core[i+1] {
                        in_window = false;
                        batch_broken = true;
                    } else {
                        // oa and ob are core points, and we must determine if oa to ob breaks the batch.
                        if ob - oa > range {
                            // Batch broken.
                            in_window = false;
                            batch_broken = true;
                        }
                    }
                }

                // if batch_broken {
                //     kernel::debug!("{}..{}", anchor_i, i);
                // }
            }

            // Update the winning window, if necessary.
            // Go with the narrower window if possible to optimize response time.
            // kernel::debug!("{} ms = {} batches",
            //                window_size * 1_000 / 16_000,
            //                batch_count);
            if batch_count >= best_batch_count {
                best_batch_count = batch_count;
                best_window_size = window_size;
            }

            // Decrease the window size.
            window_size -= window_size_dec;
        }

        best_window_size
    }

    fn batch_window_duration(&self) -> usize {
        let now = self.batch_alarm.now().into_usize();
        let update_interval = Self::MAX_WINDOW_TICKS * 1_000 / 16_000 * 2 / 1000 * time::Freq16KHz::frequency() as usize;
        // let update_interval = time::Freq16KHz::frequency() as usize;

        if now - self.last_window_update.get() > update_interval {
            let mut timeline = [0usize; 10];
            let mut syscall_history_it = self.syscall_history.iter()
                .filter_map(|optc| optc.extract());

            let timeline_it = timeline.iter_mut();
            let mut op_count = 0;
            for timeline_slot in timeline_it {
                if let Some(t) = syscall_history_it.next() {
                    op_count += 1;
                    *timeline_slot = t;
                } else {
                    break;
                }
            }

            // Sort the timeline, earliest to latest.
            // Bubble sort...
            for pos in 1..timeline.len() {
                let pos = timeline.len() - pos;
                let mut greatest_i = 0;
                for i in 0..pos+1 {
                    if timeline[i] > timeline[greatest_i] {
                        greatest_i = i;
                    }
                }

                let temp = timeline[pos];
                timeline[pos] = timeline[greatest_i];
                timeline[greatest_i] = temp;
            }

            // kernel::debug!("timeline:");
            // for i in 0..timeline.len() {
            //     kernel::debug!("{}", timeline[i]);
            // }

            // kernel::debug!("intervals:");
            // let it = timeline.iter()
            //     .skip(1)
            //     .zip(timeline.iter());
            // for (a, b) in it {
            //     kernel::debug!("{} ms", (a - b) * 1000 / 16000);
            // }

            if op_count > 1 {
                // kernel::debug!("timeline:");
                // for entry in timeline.iter().copied() {
                //     kernel::debug!("@ {}", entry);
                // }

                let entry_count = timeline.iter()
                    .filter(|t| **t > 0)
                    .count();
                let optimal_window_size = self.find_optimal_window(&timeline[timeline.len()-entry_count..]);
                // kernel::debug!("optimal window size: {}", optimal_window_size);
            }
            self.last_window_update.set(now);
        }

        self.current_window_size_ms.get()
    }

    fn open_batch_window(&self) {
        if self.next_expiration.is_none() {
            let now = self.batch_alarm.now();
            let window_duration_ticks = (time::Freq16KHz::frequency() as usize / 1000)
                * self.batch_window_duration();
            self.batch_alarm.set_alarm(now, time::Ticks32::from(window_duration_ticks as u32));

            let expiration = (now.into_usize(), window_duration_ticks as usize);
            self.next_expiration.set(expiration);
            // kernel::debug!("batch window: {:?}", expiration);
        }
    }

    const MIN_SYSCALL_DIFF: usize = 50 * 16000 / 1000;

    fn add_to_history(&self, syscall: &Syscall) {

    }
}

impl BatchController for ResponsiveBatching {
    fn check_enqueue<'a>(&self, invoking_process: &dyn Process, syscall: &'a Syscall) -> QueueResult<'a> {
        self.last_syscall.set(self.batch_alarm.now().into_usize());
        match syscall {
            // Driver checks do not need queueing.
            Syscall::Command { driver_number, subdriver_number: 0, .. } => {
                // kernel::debug!("Run driver check: {}", driver_number);
                QueueResult::Run(syscall)
            },

            // Alarm driver syscalls work differently...
            // We modified the alarm capsule to not actually interact with the bottom-half.
            // So, applications can register all the alarms they want.
            // Since the kernel controls the timer, the kernel will call into the alarm capsule
            // to make sure it eventually handles expired alarms set by applications.
            //
            // Instead of queueing the syscall, we let it through and make sure to open a batch window
            // so that we will service this alarm eventually.
            //
            // Perhaps how applications use the alarms should determine the size of the batching window?
            Syscall::Command { driver_number: 0,
                               subdriver_number,
                               arg0: syscall_reference,
                               arg1: syscall_dt } =>
            {
                if *subdriver_number == batch::ALARM_COMMAND_SET_ALARM {
                    // kernel::debug!("alarm: {:?}", syscall);
                    // kernel::debug!("scheduled: {}", *syscall_reference + *syscall_dt);
                    let now = self.batch_alarm.now().into_usize();
                    // kernel::debug!("scheduled: {}", now + *syscall_dt);
                    // Set the history entry based on reference + dt.
                    // self.syscall_history[self.syscall_history_next.get()]
                    //     .set(*syscall_reference + *syscall_dt);
                    // Set the history entry based on now + dt.
                    self.syscall_history[self.syscall_history_next.get()]
                        .set(now + *syscall_dt);
                    self.syscall_history_next.set(
                        (self.syscall_history_next.get() + 1) % 10);

                    // Add the alarm to the active set.
                    let empty_slot = self.active_alarms.iter()
                        .find(|optc| optc.is_none())
                        .unwrap();
                    empty_slot.set((*syscall_reference, *syscall_dt));
                }

                // Make sure the batch window is open.
                self.open_batch_window();

                // Make the kernel handle the syscall into the alarm capsule now.
                QueueResult::Run(syscall)
            },

            // All other commands should go to the queue for later execution.
            Syscall::Command { .. } => {
                if self.batching_state.get() != BatchingState::Batch {
                    self.add_to_history(syscall);
                    QueueResult::Run(syscall)
                } else {
                    let empty_slot = self.pending_syscalls.iter()
                        .find(|oc| oc.is_none())
                        .expect("pending syscall overflow");
                    let pending_syscall = PendingSyscall::new(invoking_process.processid(), *syscall);
                    empty_slot.set(pending_syscall);
                    // Now that we have a pending syscall, we ensure that we have a batch window open.
                    self.open_batch_window();
                    self.add_to_history(syscall);
                    // kernel::debug!("queued: {:?}", pending_syscall.syscall);

                    QueueResult::Queued
                }
            },

            // Any non-command syscalls should execute immediately.
            _ => QueueResult::Run(syscall),
        }
    }

    /// Remove a syscall from the queue.
    fn dequeue_syscall(&self) -> Option<(ProcessId, Syscall)> {
        let opt_oc_pnd_syscall = self.pending_syscalls.iter()
            .find(|oc| oc.is_some());

        if let Some(oc_pnd_syscall) = opt_oc_pnd_syscall {
            oc_pnd_syscall
                .take()
                .map(|pnd_syscall| (pnd_syscall.pid, pnd_syscall.syscall))
        } else {
            None
        }
    }

    /// Returns the current batching state.
    fn state(&self, k: bool) -> BatchingState {
        let s = match self.batching_state.get() {
            // BatchingState::Batch => {
            //     if k || self.syscall_queue_len() > 1 {
            //         // Immediately shift states if there are upcalls waiting.
            //         self.batch_alarm.disarm();
            //         self.alarm();
            //         // kernel::debug!("int. ends window early");
            //         // kernel::debug!("batch size: {}", self.syscall_queue_len());

            //         BatchingState::CollectUpcalls
            //     } else {
            //         BatchingState::Batch
            //     }
            // },

            _ => self.batching_state.get(),
        };
        // kernel::debug!("batch s: {:?}", s);
        s
    }

    fn notify_upcalls_completed(&self) {
        self.batching_state.set(BatchingState::RunSyscalls);
    }

    fn notify_syscalls_completed(&self) {
        self.batching_state.set(BatchingState::Batch);
        self.open_batch_window();
    }

    // fn flush_upcalls(&self) -> bool { true }
}

const fn ms_to_ticks(ms: usize) -> usize {
    ms * 16_000 / 1000
}

impl AlarmClient for ResponsiveBatching {
    /// Batch window expiration handler.
    ///
    /// Run pending syscalls and also notify the alarm driver of expiration.
    fn alarm(&self) {
        // kernel::debug!("--- batch window expired!");

        // kernel::debug!("als:");
        // for oc in self.active_alarms.iter() {
        //     if let Some((r, dt)) = oc.extract() {
        //         kernel::debug!("{}, +{}", r, dt);
        //     }
        // }

        // kernel::debug!("hst:");
        // for oc in self.syscall_history.iter() {
        //     if let Some(t) = oc.extract() {
        //         kernel::debug!("@{}", t);
        //     }
        // }

        self.next_expiration.clear();

        // Alarm upcalls could lead to other operations becoming queued.
        // Perhaps we should execute those as well while we are executing syscalls?
        self.alarm_driver.alarm();

        // Remove expired alarms from the active alarm set.
        let now = self.batch_alarm.now().into_usize();
        let it = self.active_alarms.iter()
            .filter(|optc| optc.is_some());
        let c = self.active_alarms.iter()
            .filter(|optc| optc.is_some())
            .count();
        // kernel::debug!("now({}): {}", c, now);

        for slot in it {
            // kernel::debug!("a: {:?}", slot.extract().unwrap());
            if slot.map(|(r, dt)| (*r + *dt) < now).unwrap() {
                // kernel::debug!("removed alarm");
                slot.clear();
            }
        }

        // The next step is to run upcalls (and possibly collect their syscalls).
        self.batching_state.set(BatchingState::CollectUpcalls);
    }
}

/// Batch controller that passively observes activity and prints time-linear scanning information.
pub struct LinearScanObserver {
    alarm: &'static BatchAlarm,
    observations: [OptionalCell<(usize, Syscall)>; 10],
    next_observation_slot: Cell<usize>,
}

impl LinearScanObserver {
    pub fn new(alarm: &'static BatchAlarm) -> LinearScanObserver {
        LinearScanObserver {
            alarm,
            observations: [OptionalCell::empty(),
                           OptionalCell::empty(),
                           OptionalCell::empty(),
                           OptionalCell::empty(),
                           OptionalCell::empty(),
                           OptionalCell::empty(),
                           OptionalCell::empty(),
                           OptionalCell::empty(),
                           OptionalCell::empty(),
                           OptionalCell::empty()],
            next_observation_slot: Cell::new(0),
        }
    }

    const MIN_WINDOW_TICKS: usize = ms_to_ticks(50);
    // const MIN_WINDOW_TICKS: usize  = ms_to_ticks(500);
    const MAX_WINDOW_TICKS: usize = ms_to_ticks(1000);

    fn find_optimal_window(&self) -> usize {
        let window_size_dec = Self::MAX_WINDOW_TICKS / 10;
        let mut window_size = Self::MAX_WINDOW_TICKS - window_size_dec;
        let mut best_batch_count = 0;
        let mut best_window_size = Self::MAX_WINDOW_TICKS;

        while window_size >= Self::MIN_WINDOW_TICKS {
            // kernel::debug!("Window size {}...", window_size);
            let mut anchor = 0;
            let mut in_window = false;
            let mut batch_count = 0;

            while anchor < self.observations.len()-1 { // Do not iterate to the last item.
                let t_anchor = self.observations[anchor]
                    .map(|obs| obs.0)
                    .unwrap();

                for pos in anchor+1..self.observations.len() {
                    let t_pos = self.observations[pos]
                        .map(|obs| obs.0)
                        .unwrap();
                    let dt = t_pos - t_anchor;

                    // If dt exceeds the current window size, then the window is broken
                    // and we start a new window with the current pos as the new anchor point.
                    //
                    // Otherwise, we are still in the batch window.
                    if dt > window_size || pos == self.observations.len()-1 {
                        // kernel::debug!("  - {} (event {}) to {} (event {})",
                        //                self.observations[anchor].extract().unwrap().0,
                        //                anchor,
                        //                self.observations[pos-1].extract().unwrap().0,
                        //                pos-1);

                        in_window = false;
                        anchor = pos;
                        break;
                    } else {
                        // If we are currently in a batching window that already has 2+ events,
                        // then there is no new batch to count. Only count a new batch if this
                        // was a single-event window prior to this point.
                        if !in_window {
                            batch_count += 1;
                            in_window = true;
                        }
                    }
                }
            }

            // Update the winning window, if necessary.
            // Go with the narrower window if possible to optimize response time.
            // kernel::debug!("{} ms = {} batches",
            //                window_size * 1_000 / 16_000,
            //                batch_count);
            if batch_count >= best_batch_count {
                best_batch_count = batch_count;
                best_window_size = window_size;
            }

            // Decrease the window size.
            window_size -= window_size_dec;
        }

        best_window_size
    }
}

impl BatchController for LinearScanObserver {
    fn check_enqueue<'a>(
        &self,
        invoking_process: &dyn Process,
        syscall: &'a Syscall,
    ) -> QueueResult<'a> {
        let now = self.alarm.now().into_usize();
        // let t_previous_syscall = self.observations[previous_slot].map(|obs| now - obs.0);

        match syscall {
            Syscall::Command { driver_number, subdriver_number, .. } => {
                if *driver_number != 0 {
                    // Record the syscall observation.
                    let slot = self.next_observation_slot.get();
                    let previous_slot = if slot == 0 { 9 } else { slot - 1 };
                    let observation = (now, *syscall);

                    self.observations[slot].set(observation);
                    self.next_observation_slot.set((slot + 1) % 10);

                    if slot == 9 {
                        // kernel::debug!("Observations:");
                        for slot in self.observations.iter() {
                            if let Some((t, sc)) = slot.extract() {
                                match sc {
                                    Syscall::Command { driver_number, subdriver_number, .. } => {  },
                                        // kernel::debug!("@{} s {} ms: ({}, {})",
                                        //                t / 16_000,
                                        //                (t * 1_000 / 16_000) % 1_000,
                                        //                driver_number,
                                        //                subdriver_number),

                                    _ => {  },
                                }
                            }
                        }

                        let best_window_size = self.find_optimal_window();
                        // kernel::debug!("Optimal window: {} ms",
                        //                best_window_size * 1000 / 16_000);
                    }
                }

                QueueResult::Run(syscall)
            },

            _ => QueueResult::Run(syscall)
        }
    }

    fn dequeue_syscall(&self) -> Option<(ProcessId, Syscall)> {
        None
    }

    fn state(&self, _k: bool) -> BatchingState {
        BatchingState::Batch
    }

    fn flush_upcalls(&self) -> bool { true }

    fn notify_upcalls_completed(&self) {
    }

    fn notify_syscalls_completed(&self) {
    }
}

/// Batch controller that passively observes activity and prints DBSCAN-based batching information.
pub struct DBSCANObserver {
    alarm: &'static BatchAlarm,
    observations: [OptionalCell<(usize, Syscall)>; 10],
    next_observation_slot: Cell<usize>,
}

impl DBSCANObserver {
    pub fn new(alarm: &'static BatchAlarm) -> DBSCANObserver {
        DBSCANObserver {
            alarm,
            observations: [OptionalCell::empty(),
                           OptionalCell::empty(),
                           OptionalCell::empty(),
                           OptionalCell::empty(),
                           OptionalCell::empty(),
                           OptionalCell::empty(),
                           OptionalCell::empty(),
                           OptionalCell::empty(),
                           OptionalCell::empty(),
                           OptionalCell::empty()],
            next_observation_slot: Cell::new(0),
        }
    }

    const MIN_WINDOW_TICKS: usize = ms_to_ticks(50);
    const MAX_WINDOW_TICKS: usize = ms_to_ticks(1000);

    fn find_optimal_window(&self) -> usize {
        let window_size_dec = Self::MAX_WINDOW_TICKS / 10;
        let mut window_size = Self::MAX_WINDOW_TICKS - window_size_dec;
        let mut best_batch_count = 0;
        let mut best_window_size = Self::MAX_WINDOW_TICKS;

        while window_size >= Self::MIN_WINDOW_TICKS {
            // Label points on the timeline.
            let mut labels_is_core: [bool; 10] = [false; 10];
            let range = window_size / 2;
            for i in 0..labels_is_core.len() {
                let t_syscall = self.observations[i]
                    .map(|obs| obs.0)
                    .unwrap();

                let left_in_range = if i > 0 {
                    let dt = self.observations[i-1]
                        .map(|obs| t_syscall - obs.0)
                        .unwrap();
                    dt < range
                } else {
                    false
                };

                let right_in_range = if i < self.observations.len()-1 {
                    let dt = self.observations[i+1]
                        .map(|obs| obs.0 - t_syscall)
                        .unwrap();
                    dt < range
                } else {
                    false
                };

                labels_is_core[i] = left_in_range || right_in_range;
            }

            let mut batch_count = 0;
            let mut in_window = false;
            let mut anchor_i = 0;
            let it = (0..)
                .zip(self.observations.iter()
                     .zip(self.observations.iter().skip(1)));
            for (i, (oa, ob)) in it {
                let mut batch_broken = false;
                if !labels_is_core[i] {
                    // Just iterating over noise until we find a core point.
                    continue;
                } else {
                    if !in_window {
                        // Since oa is a core point, we start a batch window here.
                        in_window = true;
                        anchor_i = i;
                        batch_count += 1;
                    }

                    // We are currently in a window.
                    // If ob is noise, then it always breaks the batch.
                    if !labels_is_core[i+1] {
                        in_window = false;
                        batch_broken = true;
                    } else {
                        // oa and ob are core points, and we must determine if oa to ob breaks the batch.
                        let (t_oa, t_ob) = (
                            oa.map(|obs| obs.0).unwrap(),
                            ob.map(|obs| obs.0).unwrap());
                        if t_ob - t_oa > range {
                            // Batch broken.
                            in_window = false;
                            batch_broken = true;
                        }
                    }
                }

                // if batch_broken {
                //     kernel::debug!("{}..{}", anchor_i, i);
                // }
            }

            // Update the winning window, if necessary.
            // Go with the narrower window if possible to optimize response time.
            // kernel::debug!("{} ms = {} batches",
            //                window_size * 1_000 / 16_000,
            //                batch_count);
            if batch_count >= best_batch_count {
                best_batch_count = batch_count;
                best_window_size = window_size;
            }

            // Decrease the window size.
            window_size -= window_size_dec;
        }

        best_window_size
    }
}

impl BatchController for DBSCANObserver {
    fn check_enqueue<'a>(
        &self,
        invoking_process: &dyn Process,
        syscall: &'a Syscall,
    ) -> QueueResult<'a> {
        let now = self.alarm.now().into_usize();
        // let t_previous_syscall = self.observations[previous_slot].map(|obs| now - obs.0);

        match syscall {
            Syscall::Command { driver_number, subdriver_number, .. } => {
                if *driver_number != 0 {
                    // Record the syscall observation.
                    let slot = self.next_observation_slot.get();
                    let previous_slot = if slot == 0 { 9 } else { slot - 1 };
                    let observation = (now, *syscall);

                    self.observations[slot].set(observation);
                    self.next_observation_slot.set((slot + 1) % 10);

                    if slot == 9 {
                        // kernel::debug!("Observations:");
                        for slot in self.observations.iter() {
                            if let Some((t, sc)) = slot.extract() {
                                match sc {
                                    Syscall::Command { driver_number, subdriver_number, .. } => {  }
                                        // kernel::debug!("@{} s {} ms: ({}, {})",
                                        //                t / 16_000,
                                        //                (t * 1_000 / 16_000) % 1_000,
                                        //                driver_number,
                                        //                subdriver_number),

                                    _ => {  },
                                }
                            }
                        }

                        let best_window_size = self.find_optimal_window();
                        // kernel::debug!("Optimal window: {} ms",
                        //                best_window_size * 1000 / 16_000);
                    }
                }

                QueueResult::Run(syscall)
            },

            _ => QueueResult::Run(syscall)
        }
    }

    fn dequeue_syscall(&self) -> Option<(ProcessId, Syscall)> {
        None
    }

    fn state(&self, _k: bool) -> BatchingState {
        BatchingState::Batch
    }

    fn flush_upcalls(&self) -> bool { true }

    fn notify_upcalls_completed(&self) {
    }

    fn notify_syscalls_completed(&self) {
    }
}

use kernel::Kernel;
use kernel::process_thin::ThinProcess;

pub struct PrefetchTester {
    /// Current batching state.
    batching_state: Cell<BatchingState>,
    enabled: Cell<bool>,
    shadow_process: &'static ThinProcess,
}

impl PrefetchTester {
    pub unsafe fn new(
        kernel: &'static Kernel,
        processes: &'static mut [Option<&'static dyn Process>],
    ) -> PrefetchTester
    {
        let (empty_entry, pidx) = processes.iter_mut()
            .zip(0..)
            .find(|(e, _idx)| e.is_none())
            .unwrap();
        let shadow_process = static_init!(ThinProcess, ThinProcess::new(kernel, pidx));
        *empty_entry = Some(shadow_process);

        PrefetchTester {
            batching_state: Cell::new(BatchingState::Batch),
            enabled: Cell::new(true),
            shadow_process,
        }
    }
}

impl BatchController for PrefetchTester {
    fn check_enqueue<'a>(&self, invoking_process: &dyn Process, syscall: &'a Syscall) -> QueueResult<'a> {
        match syscall {
            // Driver checks do not need queueing.
            Syscall::Command { driver_number,
                               subdriver_number: 0, .. } => QueueResult::Run(syscall),

            // All other commands should go to the queue for later execution.
            Syscall::Command { driver_number,
                               subdriver_number,
                               arg0,
                               arg1 } => {
                // Check the syscall cache.
                let cache_check_result =  self.shadow_process.check_syscall_cache(
                    *driver_number, *subdriver_number, *arg0, *arg1);
                if let Some(cached_return) = cache_check_result {
                    // Get this result back to the process.
                }

                if self.enabled.get() {
                    self.enabled.set(false);
                    let (allow_address, allow_size) = self.shadow_process.reserve_buffer(1024)
                        .unwrap();

                    QueueResult::RunAlso(syscall,
                                         self.shadow_process,
                                         [
                                             Some(Syscall::ReadWriteAllow {
                                                 driver_number: 0x00005,
                                                 subdriver_number: 0,
                                                 allow_address,
                                                 allow_size,
                                             }),

                                             Some(Syscall::Command {
                                                 driver_number: 0x00005,
                                                 subdriver_number: 3,
                                                 arg0: 0,
                                                 arg1: 5120,
                                             })
                                         ])
                } else {
                    QueueResult::Run(syscall)
                }
            },

            // Any non-command syscalls should execute immediately.
            _ => QueueResult::Run(syscall),
        }
    }

    /// Remove a syscall from the queue.
    fn dequeue_syscall(&self) -> Option<(ProcessId, Syscall)> {
        None
    }

    /// Returns the current batching state.
    fn state(&self, k: bool) -> BatchingState {
        self.batching_state.get()
    }

    fn notify_upcalls_completed(&self) {
        self.batching_state.set(BatchingState::RunSyscalls);
    }

    fn notify_syscalls_completed(&self) {
        self.batching_state.set(BatchingState::Batch);
    }
}

pub struct PrefetchController {
    batching_state: Cell<BatchingState>,
    /// Batch window duration in ticks.
    window_duration_ticks: usize,
    /// Alarm used for time window batching.
    batch_alarm: &'static BatchAlarm,
    /// Withheld syscalls.
    pending_syscall: OptionalCell<(usize, PendingSyscall)>,
    extra_syscalls: [OptionalCell<Syscall>; 2],
    /// Kernel dummy process.
    shadow_process: &'static ThinProcess,
    /// Ring schedule of processes' periodic tasks.
    schedule: [(Cell<usize>, Cell<usize>); 3],
    /// Application buffers the controller is aware of.
    rw_allow_buffers: [OptionalCell<((usize, usize), *mut u8)>; 2],
    /// Last time the schedule was updated.
    last_schedule_update: Cell<usize>,
}

impl PrefetchController {
    pub unsafe fn new(window_duration_ms: usize,
                      batch_alarm: &'static BatchAlarm,
                      kernel: &'static Kernel,
                      processes: &'static mut [Option<&'static dyn Process>])
                      -> PrefetchController
    {
        let (empty_entry, pidx) = processes.iter_mut()
            .zip(0..)
            .find(|(e, _idx)| e.is_none())
            .unwrap();
        let shadow_process = static_init!(ThinProcess, ThinProcess::new(kernel, pidx));
        *empty_entry = Some(shadow_process);

        let window_duration_ticks = window_duration_ms * 16_000 / 1_000;

        PrefetchController {
            batching_state: Cell::new(BatchingState::Batch),
            window_duration_ticks,
            batch_alarm,
            pending_syscall: OptionalCell::empty(),
            extra_syscalls: [OptionalCell::empty(), OptionalCell::empty()],
            shadow_process,
            schedule: [
                (Cell::new(core::usize::MAX), Cell::new(core::usize::MAX)),
                (Cell::new(core::usize::MAX), Cell::new(core::usize::MAX)),
                (Cell::new(core::usize::MAX), Cell::new(core::usize::MAX)),
            ],
            rw_allow_buffers: [OptionalCell::empty(),
                               OptionalCell::empty()],
            last_schedule_update: Cell::new(0),
        }
    }

    pub fn configure(&'static self) {
        self.batch_alarm.set_alarm_client(self);
    }

    fn open_batch_window(&self, window_ticks: usize) {
        // If the alarm is armed, a batch window is currently open;
        // there is no need to open it again.
        if !self.batch_alarm.is_armed() {
            let now = self.batch_alarm.now();
            self.batch_alarm.set_alarm(now, time::Ticks32::from(self.window_duration_ticks as u32));
            // kernel::debug!("--- Batch window open.");
        }
    }

    /// Immediately execute the batch, ending an open window early.
    fn execute_on_batch(&self) {
        if self.batch_alarm.is_armed() {
            self.batch_alarm.disarm();
            self.batching_state.set(BatchingState::RunSyscalls);
            // kernel::debug!("--- Batch window closed.");
        }
    }

    /// Updates the schedule of periodic executions.
    fn update_schedule(&self) {
        let now = self.batch_alarm.now();
        let last_update_dt = now.into_usize() - self.last_schedule_update.get();
        // Pick up the first call to the schedule.
        // Just update the last update time since there is nothing useful to do otherwise.
        if self.last_schedule_update.get() != 0 {
            for (pid, dt) in self.schedule.iter() {
                // Make sure the entry is, in fact, valid.
                if pid.get() != core::usize::MAX {
                    // Simple subtraction, but if the next execution time expired, clear it.
                    if dt.get() < last_update_dt {
                        pid.set(core::usize::MAX);
                    } else {
                        dt.set(dt.get() - last_update_dt);
                    }
                }
            }
        }

        // Update the last updated time.
        self.last_schedule_update.set(self.batch_alarm.now().into_usize());
    }

    /// Returns the soonest expiring application timer.
    fn next_expiring_task(&self) -> Option<&(Cell<usize>, Cell<usize>)> {
        // Need an up-to-date schedule to find the next-expiring task.
        self.update_schedule();

        // Just iterate through and find the smallest dt.
        // kernel::debug!("Schedule:");
        let mut best_idx = core::usize::MAX;
        for i in 0..self.schedule.len() {
            let (pid, dt) = &self.schedule[i];
            // kernel::debug!("{} @{}", pid.get(), dt.get());
            if pid.get() != core::usize::MAX {
                if best_idx == core::usize::MAX || self.schedule[best_idx].1.get() > dt.get() {
                    best_idx = i;
                }
            }
        }

        if best_idx == core::usize::MAX {
            None
        } else {
            Some(&self.schedule[best_idx])
        }
    }

    fn forward_batch(&self) {
        // Find the closest task to expiration.
        // That will be the task to forward-batch.
        if let Some((pid, dt)) = self.next_expiring_task() {
            kernel::debug!("Next expiring: {} in {} tcs.", pid.get(), dt.get());
            // Check timing requirements here.
            // - The task must be set to fire within batch duration divided by two to balance delay and staleness.
            // There are other possible requirements that we do not consider here (see notes).
            if dt.get() <= self.window_duration_ticks * 3 / 2 {
                // kernel::debug!("...meets timing requirements.");
                // The task meets requirements.
                // Set it as the extra syscall to run.
                //
                // This strategy requires that we have some knowledge of the periodicity of tasks.
                // We use this to perform "forward" batching.
                // Here is the magical linking between periodic schedule and syscall that will run.
                //
                // EXP: evaluation setup tells us which call to set, depending on the PID.
                // In reality, we would build a schedule based on application activity and/or input
                // and choose the syscall from that more sophisticated method.
                match pid.get() {
                    // Loudness.
                    1 => {
                        kernel::debug!("Executing ADC AoT.");

                        let (allow_address, allow_size) = self.shadow_process.reserve_buffer(1024)
                            .unwrap();

                        let syscall_buffer_allow = Syscall::ReadWriteAllow {
                            driver_number: 0x00005,
                            subdriver_number: 0,
                            allow_address,
                            allow_size,
                        };

                        let syscall_sample_command = Syscall::Command {
                            driver_number: 0x00005,
                            subdriver_number: 0x3,
                            arg0: 0,
                            arg1: 2560,
                        };

                        self.extra_syscalls[0].set(syscall_buffer_allow);
                        self.extra_syscalls[1].set(syscall_sample_command);
                    },

                    2 => {
                        kernel::debug!("Executing I2C AoT.");

                        self.extra_syscalls[0].set(Syscall::Command {
                            driver_number: 0x60001,
                            subdriver_number: 0x1,
                            arg0: 0,
                            arg1: 0,
                        })
                    },

                    _ => { return; },
                };

                // Set the batch to close sooner than normal.
                let t_midpoint = (core::cmp::max(self.window_duration_ticks, dt.get())
                                  - core::cmp::min(self.window_duration_ticks, dt.get())) / 2;
                // Make sure we are sure about when batch windows are open.
                assert!(self.batch_alarm.is_armed() == false);
                self.open_batch_window(t_midpoint);
                // kernel::debug!("Forward batch @ {}", t_midpoint);
            }
        }
    }
}

impl BatchController for PrefetchController {
    fn check_enqueue<'a>(&self, invoking_process: &dyn Process, syscall: &'a Syscall) -> QueueResult<'a> {
        match syscall {
            // Driver checks do not need queueing.
            Syscall::Command { driver_number: _, subdriver_number: 0, .. } =>
                QueueResult::Run(syscall),

            // Keep track of alarm calls passing through the kernel so we know of upcoming activity.
            Syscall::Command { driver_number: 0,
                               subdriver_number,
                               arg0: syscall_reference,
                               arg1: syscall_dt } =>
            {
                if *subdriver_number == batch::ALARM_COMMAND_SET_ALARM {
                    let invoking_pid = invoking_process.processid().id();
                    // kernel::debug!("PID {} -> {} ref., {} ticks dt.",
                    //                invoking_pid,
                    //                syscall_reference,
                    //                syscall_dt);

                    // See if the application's schedule is currently tracked.
                    // If we find it, update the existing dt value with the new, reset value.
                    // DES: how to determine if a syscall is forward batching eligble?

                    // Display application not eligible.
                    if invoking_pid != 0 {
                        let matched_entry = self.schedule.iter()
                            .find(|(pid, _dt)| pid.get() == invoking_pid);
                        self.update_schedule();
                        if let Some((_pid, dt)) = matched_entry {
                            // The application's schedule is currently tracked.
                            // Update the existing dt value with the new, reset value.
                            dt.set(*syscall_dt);
                        } else {
                            // Find an empty slot.
                            let empty_entry = self.schedule.iter()
                                .find(|(pid, _dt)| pid.get() == core::usize::MAX)
                                .unwrap(); // If this does not work, then there are not enough entries in `schedule`.
                            empty_entry.0.set(invoking_pid);
                            empty_entry.1.set(*syscall_dt);
                            // kernel::debug!("Set empty entry.");
                        }

                        // kernel::debug!("Schedule:");
                        // for i in 0..self.schedule.len() {
                        //     let (pid, dt) = &self.schedule[i];
                        //     kernel::debug!("{} @{}", pid.get(), dt.get());
                        // }
                    }
                }

                // Make the kernel handle the syscall into the alarm capsule now.
                QueueResult::Run(syscall)
            },

            // All other commands may be batched or end up closing the batch if it is ready.
            Syscall::Command { driver_number, subdriver_number, arg0, arg1 } => {
                // First, see if we executed this syscall ahead of time.
                if let Some(aot_result) = self.shadow_process.check_syscall_cache(*driver_number, *subdriver_number, *arg0, *arg1) {
                    kernel::debug!("Using AoT result.");

                    // ENG/DSN: getting the buffer back to the process, if necessary.
                    // ENG/DSN: setting the callback fn() pointer correctly to the process' pointer.
                    //   It should be simpler, streamlined to know this information.

                    // Get the subscription no., allow no. for the callback.
                    let (subscribe_no, opt_allow_no) = match (driver_number, subdriver_number) {
                        (0x00005, 3) => (0, Some(0)),
                        (0x60000, 1) => (0, None),
                        (0x60001, 1) => (0, None),
                        _ => unimplemented!(),
                    };
                    // And then use that subscription no. to discover what function the process currently uses.
                    let (process_upcall_fn, app_data) = kernel::grant::subscription(invoking_process, *driver_number, subscribe_no)
                        .unwrap(); // We assume that all applications set this to something non-null.

                    // TODO: copy buffer if necessary.
                    if let Some(rw_allow_no) = opt_allow_no {
                        let dst_buffer_addr = self.rw_allow_buffers.iter()
                            .find(|optc| optc.map_or(false, |rw_buffer| rw_buffer.0 == (*driver_number, rw_allow_no)))
                            .unwrap() // Programming error, if this fails; means we did not track RW buffers properly.
                            .extract()
                            .unwrap() // Guaranteed to exist from previous find.
                            .1;
                        unsafe { // We could manipulate the size of the AoT buffer to match the destination.
                            let src_buffer = aot_result.buffer.unwrap();
                            core::ptr::copy(src_buffer.as_ptr(),
                                            dst_buffer_addr,
                                            src_buffer.len()); // Use the length of the AoT buffer, which was previously sized appropriately.
                        }
                    }

                    // Place the call on the process' task queue to execute.
                    invoking_process.enqueue_task(
                        Task::FunctionCall(
                            FunctionCall {
                                pc: process_upcall_fn.unwrap().as_ptr() as usize,
                                ..aot_result.upcall
                            }));
                    kernel::debug!("Delivered AoT result.");

                    return QueueResult::AoT;
                }

                if self.pending_syscall.is_none() {
                    // There is not currently a syscall waiting to execute.

                    // Withhold the app-requested syscall.
                    self.pending_syscall.set((self.batch_alarm.now().into_usize(),
                                              PendingSyscall::new(invoking_process.processid(), *syscall)));

                    // Consider a command to execute ahead of time.
                    self.forward_batch();
                    // If forward_batch() created an AoT batch, then it would have also opened the batch window
                    // (based on the timing of the next task).
                    // But if it did not, then we manually open it here.
                    if self.extra_syscalls[0].is_none() {
                        // kernel::debug!("Forward batch did not configure.");
                        self.open_batch_window(self.window_duration_ticks);
                    } else {
                        kernel::debug!("Forward batch configured; execute.");
                    }

                    QueueResult::Queued
                } else {
                    // Since there is a syscall already waiting to execute, run this and the pending syscall.
                    // Switch states to execute the pending syscall.
                    self.execute_on_batch();
                    QueueResult::Run(syscall)
                }
            },

            // Watch for any RW-allows to know where we can copy prefetched data.
            Syscall::ReadWriteAllow { driver_number,
                                      subdriver_number,
                                      allow_address,
                                      allow_size } => {
                // Record the RW address and size.
                let empty_slot = self.rw_allow_buffers.iter()
                    .find(|s| s.is_none())
                    .unwrap();
                let rw_allow_buffer = unsafe {
                    core::slice::from_raw_parts_mut(*allow_address as *mut u8,
                                                    *allow_size)
                        .as_mut_ptr()
                };
                empty_slot.set(((*driver_number, *subdriver_number), rw_allow_buffer));

                // ...and then allow the RW-allow to run.
                QueueResult::Run(syscall)
            },

            // Any non-command syscalls should execute immediately.
            _ => QueueResult::Run(syscall),
        }
    }

    /// Remove a syscall from the queue.
    fn dequeue_syscall(&self) -> Option<(ProcessId, Syscall)> {
        if self.pending_syscall.is_some() {
            self.pending_syscall.take()
                .map(|(t_add, p)| {
                    // let batch_delay_ms = (self.batch_alarm.now().into_usize() - t_add)
                    //     * 1000 / 16_000;
                    // kernel::debug!("Batch delay: {} ms", batch_delay_ms);

                    (p.pid, p.syscall)
                })
        } else {
            // Check the extra_syscalls.
            // Return one of these if there is something present in the cell.
            for optc_syscall in self.extra_syscalls.iter() {
                if optc_syscall.is_some() {
                    return optc_syscall
                        .take()
                        .map(|s| (self.shadow_process.processid(), s));
                }
            }

            // Or just return none if there is nothing left.
            None
        }
    }

    /// Returns the current batching state.
    fn state(&self, _k: bool) -> BatchingState {
        self.batching_state.get()
    }

    fn notify_upcalls_completed(&self) {
        self.batching_state.set(BatchingState::RunSyscalls);
    }

    fn notify_syscalls_completed(&self) {
        self.batching_state.set(BatchingState::Batch);
    }

    /// Do not withhold upcalls.
    ///
    /// Upcalls should run unrestricted in this batching controller.
    /// The hypothesis is that these small executions here have a negligible effect on energy usage.
    fn flush_upcalls(&self) -> bool { true }
}

impl AlarmClient for PrefetchController {
    /// Batch window expiration handler.
    ///
    /// Run pending syscalls and also notify the alarm driver of expiration.
    /// Works in tandem with the alarm capsule to get its own alarms while not interfering with application alarms.
    /// The batch controller takes alarm notifications and always passes them on to the alarm capsule.
    /// When an application alarm is set sooner than the expiration of the batch window,
    /// the controller does not set the alarm.
    /// It instead waits for the next alarm to fire before considering setting the alarm hardware for the batch window.
    fn alarm(&self) {
        // kernel::debug!("--- Batch window expired.");
        // Execute the batch.
        // The next step is to run upcalls (and possibly collect their syscalls).
        self.batching_state.set(BatchingState::RunSyscalls);

        self.update_schedule();
        // self.next_expiring_task()
        //     .map(|(pid, dt)| kernel::debug!("Next expiration? {}", pid.get()));
    }
}
