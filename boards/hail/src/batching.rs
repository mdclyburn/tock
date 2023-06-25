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
}

impl ResponsiveBatching {
    pub fn new(batch_alarm: &'static BatchAlarm,
               alarm_driver: &'static dyn AlarmClient)
               -> ResponsiveBatching
    {
        ResponsiveBatching {
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
        }
    }

    fn batch_window_duration(&self) -> usize {
        let duration_ms = self.active_alarms.iter()
            .filter_map(|optc| optc.extract())
            .map(|(_r, dt)| dt)
            .fold(0, |acc, cur| if cur < acc { cur } else { acc });

        if duration_ms == 0 { 1_000 } else { duration_ms }
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
}

impl BatchController for ResponsiveBatching {
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

                    // Add the alarm to the active set.
                    let empty_slot = self.active_alarms.iter()
                        .find(|optc| optc.is_none())
                        .expect("no more remaining empty alarm slots");
                    empty_slot.set((*syscall_reference, *syscall_dt));
                    for a in self.active_alarms.iter().filter_map(|o| o.extract()) {
                        // kernel::debug!("sa: {:?}", a);
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
        match self.batching_state.get() {
            BatchingState::Batch => {
                if k {
                    // Immediately shift states if there are upcalls waiting.
                    self.batch_alarm.disarm();
                    self.alarm();
                    // kernel::debug!("int. ends window early");

                    BatchingState::CollectUpcalls
                } else {
                    BatchingState::Batch
                }
            },

            _ => self.batching_state.get(),
        }
    }

    fn notify_upcalls_completed(&self) {
        self.batching_state.set(BatchingState::RunSyscalls);
    }

    fn notify_syscalls_completed(&self) {
        self.batching_state.set(BatchingState::Batch);
        self.open_batch_window();
    }
}

impl AlarmClient for ResponsiveBatching {
    /// Batch window expiration handler.
    ///
    /// Run pending syscalls and also notify the alarm driver of expiration.
    fn alarm(&self) {
        // kernel::debug!("batch window expired");
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
