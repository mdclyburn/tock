/** Peripheral batch scheduling
 */

use crate::process::ProcessId;
use crate::syscall::Syscall;

pub const ALARM_COMMAND_SET_ALARM: usize = 6;

/// A batched syscall.
#[derive(Clone, Copy)]
pub struct PendingSyscall {
    pub pid: ProcessId,
    pub syscall: Syscall,
}

impl PendingSyscall {
    /// Create a new batched syscall.
    pub fn new(pid: ProcessId, syscall: Syscall) -> PendingSyscall {
        PendingSyscall {
            pid,
            syscall,
        }
    }
}

/// Result of checking a syscall into the batch.
#[derive(Clone, Copy)]
pub enum QueueResult<'a> {
    /// Syscall was added to the batch.
    Queued,
    /// Syscall was not added to the batch and should be executed on immediately.
    Run(&'a Syscall),
}

#[derive(Clone, Copy, PartialEq)]
pub enum BatchingState {
    Batch,
    CollectUpcalls,
    RunSyscalls,
}

/// A batching strategy.
pub trait BatchController {
    /// Possibly check a syscall into the batch.
    fn check_enqueue<'a>(&self, pid: ProcessId, syscall: &'a Syscall) -> QueueResult<'a>;

    /// Remove a syscall from the queue.
    fn dequeue_syscall(&self) -> Option<(ProcessId, Syscall)>;

    /// Returns the current batching state.
    fn state(&self) -> BatchingState;

    /// Notify the batch controller that upcall execution is complete.
    ///
    /// This allows a state change in the batching state machine.
    /// The kernel will be able to proceed to the next step.
    /// (Perhaps make state changes automatic on querying the state?)
    fn notify_upcalls_completed(&self);

    /// Notify the batch controller that syscall execution is complete.
    ///
    /// This allows a state change in the batching state machine to start batching again.
    fn notify_syscalls_completed(&self);
}
