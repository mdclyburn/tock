/** Peripheral batch scheduling
 */

use crate::process::ProcessId;
use crate::syscall::Syscall;

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
    fn check_queue<'a>(&self, syscall: &'a Syscall) -> QueueResult<'a>;

    /// Remove a syscall from the queue.
    fn dequeue_syscall(&self) -> Option<Syscall>;

    /// Returns the current batching state.
    fn state(&self) -> BatchingState;
}
