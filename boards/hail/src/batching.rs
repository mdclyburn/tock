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
use kernel::process::{Process, ProcessId};
use kernel::syscall::Syscall;
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
    fn check_enqueue<'a>(&self, pid: ProcessId, syscall: &'a Syscall) -> QueueResult<'a> {
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
                let pending_syscall = PendingSyscall::new(pid, *syscall);
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
    max_window_size_ms: usize,
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
    pending_syscalls: [OptionalCell<PendingSyscall>; 30],
    /// Latest issuance of distinct syscalls that get batched.
    syscall_history: [OptionalCell<(usize, (usize, usize))>; 10],
}

impl ResponsiveBatching {
    pub fn new(max_window_size_ms: usize,
               batch_alarm: &'static BatchAlarm,
               alarm_driver: &'static dyn AlarmClient)
               -> ResponsiveBatching
    {
        ResponsiveBatching {
            max_window_size_ms,
            current_window_size_ms: Cell::new(max_window_size_ms),
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
        }
    }

    fn syscall_queue_len(&self) -> usize {
        self.pending_syscalls.iter()
            .filter(|optc| optc.is_some())
            .count()
    }

    fn batch_window_duration(&self) -> usize {
        let now = self.batch_alarm.now().into_usize();
        let update_interval = self.max_window_size_ms * 2 / 1000 * time::Freq16KHz::frequency() as usize;
        // let update_interval = time::Freq16KHz::frequency() as usize;

        if now - self.last_window_update.get() > update_interval {
            let mut timeline = [0usize; 10];
            let alarm_it = self.active_alarms.iter()
                .filter_map(|optc| optc.extract())
                .map(|(r, dt)| r+dt);
            let mut syscall_history_it = self.syscall_history.iter()
                .filter_map(|optc| optc.extract())
                .map(|(t, _syscall)| t)
                .chain(alarm_it)
                .filter(|t| *t > now - update_interval);
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

            kernel::debug!("op count: {}", op_count);

            if op_count > 1 {
                // sort timeline
                let mut least_found = 0;
                for current_slot in 0..(timeline.len()-1) {
                    for maybe_slot in (current_slot+1)..(timeline.len()-1) {
                        if timeline[maybe_slot] < timeline[current_slot] {
                            let temp = timeline[maybe_slot];
                            timeline[maybe_slot] = timeline[current_slot];
                            timeline[current_slot] = temp;
                        }
                    }
                }

                kernel::debug!("timeline:");
                for slot in timeline.iter() {
                    kernel::debug!("S: {}", slot);
                }

                // apply clustering to find if there is a tigher batching window that will make the system more responsive
                let mut window = (self.max_window_size_ms * 8 / 10 * time::Freq16KHz::frequency() as usize) / 1000;
                // best window found so far
                let mut best_clusters = 0;
                let mut best_window = self.max_window_size_ms * time::Freq16KHz::frequency() as usize / 1000;
                // clustering epsilon cutoff threshold
                // let min_interval = timeline.iter()
                //     .zip(timeline[1..].iter())
                //     .filter(|(_ta, tb)| **tb > 0)
                //     .map(|(ta, tb)| *tb - *ta)
                //     .fold(self.max_window_size_ms, |acc, cur| if cur < acc { cur } else { acc });
                let min_interval = time::Freq16KHz::frequency() as usize / 1000 * 20;
                while window > min_interval {
                    let mut clusters = 0;
                    let mut in_cluster = false;

                    let it = timeline.iter()
                        .copied()
                        .zip(timeline[1..].iter().copied())
                        .filter(|(_ta, tb)| *tb > 0);
                    for (ta, tb) in it {
                        assert!(ta < tb); // should be sorted...
                        if tb - ta < window {
                            if !in_cluster {
                                in_cluster = true;
                                clusters += 1;
                            } else {
                                // we're in a cluster and we do not care that we extended the cluster
                            }
                        } else {
                            if in_cluster {
                                // end of cluster
                                in_cluster = false;
                            } else {
                                // we were not in a cluster, and we do not care that we are still not in one
                            }
                        }
                    }

                    if clusters > best_clusters {
                        best_clusters = clusters;
                        best_window = window;

                        // kernel::debug!("window size {} tc; clusters: {}, min: {} tc",
                        //                window,
                        //                clusters,
                        //                min_interval);
                    }

                    window = window * 8 / 10;
                }

                kernel::debug!("best window: {}", best_window);
                // self.current_window_size_ms.set(best_window * 1000 / time::Freq16KHz::frequency() as usize);
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
            kernel::debug!("batch window: {:?}", expiration);
        }
    }

    const MIN_SYSCALL_DIFF: usize = 50 * 16000 / 1000;

    fn add_to_history(&self, syscall: &Syscall) {
        let now = self.batch_alarm.now().into_usize();
        // Do not record quick succession of syscalls.
        if now - self.last_syscall.get() < Self::MIN_SYSCALL_DIFF  {
            if let Syscall::Command { driver_number: 0, .. } = syscall {
            } else { return; }
        }

        if let Syscall::Command { driver_number, subdriver_number, .. } = syscall {
            let history_slot = self.syscall_history.iter()
                .find(|optc| {
                    optc.is_none()
                        || optc.map(|s| s.1.0 == *driver_number && s.1.1 == *subdriver_number).unwrap()
                })
                .unwrap();

            if let Syscall::Command { driver_number: 0, subdriver_number, arg0, arg1 } = syscall {
                if *subdriver_number > 10 {
                    history_slot.set((self.batch_alarm.now().into_usize() + arg1,
                                      (0, *subdriver_number)));
                } else {
                    return;
                }
            } else {
                history_slot.set((self.batch_alarm.now().into_usize(),
                                  (*driver_number, *subdriver_number)));
            }

            kernel::debug!("history: {:?}", history_slot.extract().unwrap());
        } else {
            panic!();
        }
    }
}

impl BatchController for ResponsiveBatching {
    fn check_enqueue<'a>(&self, pid: ProcessId, syscall: &'a Syscall) -> QueueResult<'a> {
        if self.batching_state.get() != BatchingState::Batch { return QueueResult::Run(syscall); }

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
                    self.add_to_history(&Syscall::Command {
                        driver_number: 0,
                        subdriver_number: subdriver_number + 10 + pid.id(),
                        arg0: *syscall_reference,
                        arg1: *syscall_dt });

                    // Add the alarm to the active set.
                    let empty_slot = self.active_alarms.iter()
                        .find(|optc| optc.is_none())
                        .unwrap();
                    empty_slot.set((*syscall_reference, *syscall_dt));
                    for a in self.active_alarms.iter().filter_map(|o| o.extract()) {
                        kernel::debug!("set alarm: {:?}", a);
                    }
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
                let pending_syscall = PendingSyscall::new(pid, *syscall);
                empty_slot.set(pending_syscall);
                // Now that we have a pending syscall, we ensure that we have a batch window open.
                self.open_batch_window();
                self.add_to_history(syscall);
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
}

const fn ms_to_ticks(ms: usize) -> usize {
    ms * 16_000 / 1000
}

impl AlarmClient for ResponsiveBatching {
    /// Batch window expiration handler.
    ///
    /// Run pending syscalls and also notify the alarm driver of expiration.
    fn alarm(&self) {
        kernel::debug!("batch window expired");
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

/// Batch controller that passively observes activity and adapts the batching policy.
pub struct ObservantBatching {
    alarm: &'static BatchAlarm,
    observations: [OptionalCell<(usize, Syscall)>; 10],
    next_observation_slot: Cell<usize>,
}

impl ObservantBatching {
    pub fn new(alarm: &'static BatchAlarm) -> ObservantBatching {
        ObservantBatching {
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

    const MIN_WINDOW_TICKS: usize = ms_to_ticks(100);
    const MAX_WINDOW_TICKS: usize = ms_to_ticks(2_000);

    fn find_optimal_window(&self) -> usize {
        let window_size_dec = Self::MAX_WINDOW_TICKS / 10;
        let mut window_size = Self::MAX_WINDOW_TICKS - window_size_dec;
        let mut best_batch_count = 0;
        let mut best_window_size = Self::MAX_WINDOW_TICKS;

        while window_size >= Self::MIN_WINDOW_TICKS {
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
            kernel::debug!("{} ms window creates {} 2+-count batches.",
                           window_size * 1_000 / 16_000,
                           batch_count);
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

impl BatchController for ObservantBatching {
    fn check_enqueue<'a>(
        &self,
        pid: ProcessId,
        syscall: &'a Syscall,
    ) -> QueueResult<'a> {
        match syscall {
            Syscall::Command { driver_number, .. } => {
                if *driver_number != 0 {
                    // Record the syscall observation.
                    let slot = self.next_observation_slot.get();
                    let observation = (self.alarm.now().into_usize(), *syscall);
                    self.observations[slot].set(observation);
                    self.next_observation_slot.set((slot + 1) % 10);

                    if slot == 9 {
                        kernel::debug!("Observations:");
                        for slot in self.observations.iter() {
                            if let Some((t, sc)) = slot.extract() {
                                match sc {
                                    Syscall::Command { driver_number, subdriver_number, .. } =>
                                        kernel::debug!("@{} s {} ms: ({}, {})",
                                                       t / 16_000,
                                                       (t * 1_000 / 16_000) % 1_000,
                                                       driver_number,
                                                       subdriver_number),

                                    _ => {  },
                                }
                            }
                        }

                        let best_window_size = self.find_optimal_window();
                        kernel::debug!("Optimal window: {} ms",
                                       best_window_size * 1000 / 16_000);
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
