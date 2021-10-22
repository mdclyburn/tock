//! OS testing facilities.

use core::cell::Cell;

use crate::debug;
use crate::utilities::cells::OptionalCell;
use crate::platform::mpu::{
    self,
    MPU,
    Region
};
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
    /// Regions in use for stack profiling (up to 4), smallest up to largest.
    mpu_regions: [OptionalCell<Region>; 4],
    /// Currently required subregion enabled-disabled state.
    mpu_subregion_state: [OptionalCell<u8>; 4],
    sp_start: Cell<usize>,
}

impl<M: MPU> StackProfiler<M> {
    pub fn new(mpu: &'static M) -> StackProfiler<M> {
        StackProfiler {
            mpu,
            mpu_regions: [OptionalCell::empty(),
                          OptionalCell::empty(),
                          OptionalCell::empty(),
                          OptionalCell::empty()],
            mpu_subregion_state: [OptionalCell::empty(),
                                  OptionalCell::empty(),
                                  OptionalCell::empty(),
                                  OptionalCell::empty()],
            sp_start: Cell::new(0),
        }
    }

    fn region_count(&self) -> usize {
        (&self.mpu_regions).iter().fold(0, |c, opt_region| {
            if opt_region.is_some() {
                c + 1
            } else {
                c
            }
        })
    }

    /// Return the size of the region at the specified index.
    #[inline(always)]
    fn region_size(&self, region_idx: usize) -> usize {
        (2usize).pow((8 + 3 * region_idx) as u32)
    }

    /// Make the stack-tracking region smaller.
    ///
    /// Updates the internally-tracked subregion state and applies it to the MPU.
    /// All the figuring work happens in [`StackProfiler::shrink_state()`].
    fn shrink(&self, process: &dyn Process) {
        // Figure out the shrinkage.
        self.shrink_state(process, 0)
            .expect("Shrinking stack profiling MPU regions failed.");

        // Actually apply the shrink.
        // Possible optimization: only update regions that actually changed.
        for region_idx in 0..self.region_count() {
            // We'll scooch over by the size of the larger region's subregion,
            // which is the size of this entire region.
            let new_region_base = self.mpu_regions[region_idx]
                // Our two arrays _should_ have the same number of cells non-empty...
                .map(|r| r.start_address() as usize).unwrap() - self.region_size(region_idx);

            // Get rid of the old region.
            let old_region = self.mpu_regions[region_idx]
                .take().unwrap(); // ProcessEventSubscriber::created() should set this up.
            process.deallocate_mpu_region(&old_region);

            // Create the new region...
            let new_region = process.add_mpu_region(
                new_region_base as *const u8,
                self.region_size(region_idx),
                self.region_size(region_idx),
                mpu::Permissions::NoAccess).unwrap(); // Gonna take this is a no-go.
            // ...and make sure it fits our size exactly.
            assert!(new_region.start_address() as usize == new_region_base);
            assert!(new_region.size() as usize == self.region_size(region_idx));
        }
    }

    /// Compute the state to shrink stack profiling MPU region coverage.
    ///
    /// Inspects the current region/subregion state and disables the next subregion.
    ///
    /// If there is a subregion that we can disable in a region,
    /// we disable the region in the state and update the actual MPU state.
    ///
    /// If there are no more subregions in a region prior to disabling a subregion,
    /// we must readjust the base address for the region.
    /// Shrink the larger region preceding the region up for shrinkage instead.
    /// After completing the shrink for the larger region, adjust the smaller region's base.
    /// The new base of the smaller region is the start address of the subregion in the larger region we just disabled.
    fn shrink_state(&self, process: &dyn Process, region_idx: usize) -> Result<(), ()> {
        // Check that there is a configuration to modify.
        let past_end = region_idx >= self.region_count();
        let iterated_to_unused = self.mpu_subregion_state[region_idx].is_none();
        if past_end || iterated_to_unused {
            return Err(());
        }

        let subregion_state = self.mpu_subregion_state[region_idx]
            .take().unwrap(); // We just checked the state.

        // If there are subregions active in this region...
        if subregion_state > 0 {
            // Disable the edge and we good.
            self.mpu_subregion_state[region_idx].set(subregion_state << 1);
            Ok(())
        } else {
            // Can't simply disable a subregion.
            // The larger region needs to disable a subregion.
            self.shrink_state(process, region_idx+1)?;

            // Represent our new subregion state,
            // and we'll recurse to the same index to finish off the operation.
            self.mpu_subregion_state[region_idx].set(u8::MAX);
            self.shrink_state(process, region_idx)
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
        let proc_stack_end = process.mem_end() as usize;
        debug!("Initial SP: {:08X}", proc_sp);
        debug!("Stack end:  {:08X}", proc_stack_end);

        // Create the necessary MPU regions.
        // We size them such that larger regions fit entire smaller regions in their subregion size.
        // We will not use more than three regions.
        let no_req_regions = required_regions(proc_stack_end - proc_sp);
        // Assert that there are between 1 and 4 regions for this purpose?
        for i in 0..no_req_regions {
            // For regions we use, all their subregions are initially enabled.
            self.mpu_subregion_state[i].set(u8::MAX);
        }
        debug!("Using {} MPU regions for stack profiling.", no_req_regions);
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
