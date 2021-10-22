//! OS testing facilities.

use crate::platform::mpu::MPU;
use crate::platform::ProcessFault;
use crate::process::Process;

/// Enables a type to hook into the process lifecycle.
#[allow(unused_variables)]
pub trait ProcessEventSubscriber {
    /// The kernel calls this function when it creates a process.
    fn created(&self, process: &dyn Process) {  }

    /// The kernel calls this function when a process is stopped.
    fn stopped(&self, process: &dyn Process) {  }

    /// The kernel calls this function when a process faults.
    fn faulted(&self, process: &dyn Process) {  }
}

impl ProcessEventSubscriber for () {  }

pub struct StackProfiler<M: 'static + MPU> {
    mpu: &'static M,
}

impl<M: MPU> StackProfiler<M> {
    pub fn new(mpu: &'static M) -> StackProfiler<M> {
        StackProfiler {
            mpu,
        }
    }
}

impl<M: MPU> ProcessEventSubscriber for StackProfiler<M> {
    /// Initializes stack usage information for a process.
    fn created(&self, process: &dyn Process) {
    }

    /// Inspects the process' stack pointer to record stack memory usage.
    ///
    /// Notes the process' stack pointer's current location
    /// and adjusts the MPU region it manipulates as necessary.
    fn stopped(&self, process: &dyn Process) {
    }
}

impl<M: MPU> ProcessFault for StackProfiler<M> {
    /// Corrects faults imposed by the profiler's MPU usage.
    ///
    /// Inspects the cause of the fault the running process hit.
    /// If it was caused by the region the profiler configured,
    /// the profiler records the stack space usage
    /// and reconfigures the MPU to allow the process to continue.
    fn process_fault_hook(&self, process: &dyn Process) -> Result<(), ()> {
        Err(())
    }
}
