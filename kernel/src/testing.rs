//! OS testing facilities.

use core::cell::Cell;

use crate::utilities::cells::OptionalCell;
use crate::platform::mpu::MPU;
use crate::platform::ProcessFault;
use crate::process::Process;

/// Enables a type to hook into the process lifecycle.
#[allow(unused_variables)]
pub trait ProcessEventSubscriber {
    /// The kernel calls this function when it creates a process.
    fn created(&self, process: &dyn Process) {  }

    /// The kernel calls this function just before starting a process.
    fn starting(&self, process: &dyn Process) {  }

    /// The kernel calls this function when a process is stopped.
    fn stopped(&self, process: &dyn Process) {  }

    /// The kernel calls this function when a process faults.
    fn faulted(&self, process: &dyn Process) {  }
}

impl ProcessEventSubscriber for () {  }

pub struct StackProfiler<M: 'static + MPU> {
    mpu: &'static M,
    mpu_subregion_state: [OptionalCell<u8>; 4],
    sp_start: Cell<usize>,
}

impl<M: MPU> StackProfiler<M> {
    pub fn new(mpu: &'static M) -> StackProfiler<M> {
        StackProfiler {
            mpu,
            mpu_subregion_state: [OptionalCell::empty(),
                                  OptionalCell::empty(),
                                  OptionalCell::empty(),
                                  OptionalCell::empty()],
            sp_start: Cell::new(0),
        }
    }
}

impl<M: MPU> ProcessEventSubscriber for StackProfiler<M> {
    /// Initializes stack usage information for a process.
    fn created(&self, process: &dyn Process) {
        // Record where the stack pointer starts;
        // this will tell us how large of an area we must track.
        let proc_sp = process.stack_pointer()
            .unwrap(); // ...If we can't tell the SP, what are we doing here?
        self.sp_start.set(proc_sp);
        let proc_stack_end = process.mem_start() as usize;

        // Create the necessary MPU regions.
        // We size them such that larger regions fit entire smaller regions in their subregion size.
        // We will not use more than three regions.
        let no_req_regions = required_regions(proc_sp - proc_stack_end);
        // Assert that there are between 1 and 4 regions for this purpose?
        for i in 0..no_req_regions {
            self.mpu_subregion_state[i].set(u8::MAX);
        }
    }

    /// Enable the stack-tracking MPU regions.
    fn starting(&self, process: &dyn Process) {
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

fn required_regions(stack_size: usize) -> usize {
    // Increase from 2 ^ 8 = 256 until we exceed provided stack size.
    // Increments of three allow entire previous regions fit inside larger ones.
    let mut exp = 8;
    while (2 << exp) < stack_size { exp += 3; }

    (exp - 8) / 3 + 1
}
