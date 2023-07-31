/** Peripheral batch scheduling
 */

use crate::process::{Process, ProcessId};
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

/// States of the [`BatchController`].
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum BatchingState {
    /// Informs the kernel that the controller is batching syscalls.
    ///
    /// This is generally the state the FSM is in most of the time.
    /// The kernel operates normally in this state.
    Batch,

    /// Informs the kernel to execute upcalls; the `RunSyscalls` state will soon follow.
    CollectUpcalls,

    /// Informs the kernel to empty the syscall queue.
    RunSyscalls,
}

/// A batching strategy.
pub trait BatchController {
    /// Possibly check a syscall into the batch.
    fn check_enqueue<'a>(&self, pid: ProcessId, syscall: &'a Syscall) -> QueueResult<'a>;

    /// Remove a syscall from the queue.
    fn dequeue_syscall(&self) -> Option<(ProcessId, Syscall)>;

    /// Returns the current batching state.
    fn state(&self, k: bool) -> BatchingState;

    /// Whether the kernel should allow upcalls to execute immediately.
    ///
    /// When the batch controller is in the `BatchingState::Batch` state,
    /// the kernel will call this function to check whether upcalls are also candidates for queueing.
    /// Returning `false` directs the kernel to not allow processes to run their upcalls immediately.
    /// Returning `true` directs the kernel to allow processes to run upcalls immediately.
    fn flush_upcalls(&self) -> bool { false }

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

/// A no-batching implementation.
pub type NoBatching = ();

impl BatchController for NoBatching {
    fn check_enqueue<'a>(&self, _pid: ProcessId, syscall: &'a Syscall) -> QueueResult<'a> {
        QueueResult::Run(syscall)
    }

    fn dequeue_syscall(&self) -> Option<(ProcessId, Syscall)> {
        None
    }

    /// This call always returns `BatchingState::Batch`, but `check_enqueue()` will always direct the kernel to run the syscall.
    fn state(&self, _k: bool) -> BatchingState {
        BatchingState::Batch
    }

    fn notify_upcalls_completed(&self) {  }

    fn notify_syscalls_completed(&self) {  }
}
