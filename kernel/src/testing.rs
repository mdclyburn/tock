//! OS testing facilities.

use core::cell::Cell;

use crate::debug;
use crate::utilities::cells::OptionalCell;
use crate::platform::ProcessFault;
use crate::platform::chip::{
    Chip,
    FaultReason,
};
use crate::platform::mpu::{
    self,
    MPU,
    Permissions,
    Region,
};
use crate::process::Process;
use crate::syscall::Syscall;

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

    // The kernel calls this function when a process invokes a syscall.
    fn on_syscall(&self, process: &dyn Process, syscall: &Syscall) {  }
}

impl ProcessEventSubscriber for () {  }

pub struct StackProfiler<C: 'static + Chip> {
    chip: &'static C,
    /// Regions in use for stack profiling (up to 4), smallest up to largest.
    mpu_regions: [OptionalCell<Region>; 4],
    /// Currently required subregion enabled-disabled state.
    mpu_subregion_state: [OptionalCell<u8>; 4],
    /// Initial value of the process' stack pointer and its stack size.
    stack_range: OptionalCell<(usize, usize)>,
    /// Number of bytes known required for stack operation.
    stack_allowed: Cell<usize>,
    /// Number of MPU regions we are manipulating.
    region_count: Cell<usize>,
}

impl<C: 'static + Chip> StackProfiler<C> {
    pub fn new(chip: &'static C) -> StackProfiler<C>
    {
        StackProfiler {
            chip,
            mpu_regions: [OptionalCell::empty(),
                          OptionalCell::empty(),
                          OptionalCell::empty(),
                          OptionalCell::empty()],
            mpu_subregion_state: [OptionalCell::empty(),
                                  OptionalCell::empty(),
                                  OptionalCell::empty(),
                                  OptionalCell::empty()],
            stack_range: OptionalCell::empty(),
            stack_allowed: Cell::new(0),
            region_count: Cell::new(0),
        }
    }

    fn lower_edge(&self) -> usize {
        self.mpu_regions[self.region_count.get()-1]
            .map(|r| r.start_address() as usize)
            .unwrap()
    }

    /// Return the highest address the profiling regions reach.
    fn upper_edge(&self) -> usize {
        let (base_addr, size) = self.mpu_regions[0]
            .map(|r| (r.start_address(), r.size()))
            .unwrap(); // Why would we not at least be using the smallest region size?

        // We assume that the subregions are contiguous here.
        // They really _should_ be.
        let subregions_enabled = self.mpu_subregion_state[0]
            .extract()
            .unwrap() // Why would we not at least be using the smallest region size?
            .count_ones();

        base_addr as usize + (size / 8) * subregions_enabled as usize - 1
    }

    /// Return the size of the region at the specified index.
    #[inline(always)]
    fn region_size(&self, region_idx: usize) -> usize {
        (2usize).pow((8 + 3 * region_idx) as u32)
    }

    /// Set the initial stack profiling MPU state.
    fn initialize(&self, process: &dyn Process, stack_start: usize) {
        // We may now calculate the real stack size.
        let stack_len = (process.mem_end() as usize) - stack_start;
        let stack_end = stack_start - stack_len;

        self.stack_range.set((stack_start, stack_len));
        // debug!("Stack start: {:#08X}", stack_start);
        // debug!("Stack end:   {:#08X}", stack_end);
        // debug!("Stack len:   {:#08X}", stack_len);

        // Create the necessary MPU regions.
        // We size them such that larger regions fit entire smaller regions in their subregion size.
        // We will not use more than four regions.
        let req_regions = required_regions(stack_len);
        self.region_count.set(req_regions);
        assert!(1 <= req_regions && req_regions <= 4);
        // debug!("Using {} regions for profiling.", self.region_count.get());

        for i in 0..self.region_count.get() {
            // Reverse our iteration; start with allocating the largest region.
            let region_idx = self.region_count.get() - i - 1;

            // Size of the region we require.
            let region_size = self.region_size(region_idx);
            // Where the region should start.
            // If this is the largest region, it should start as close to the stack end as possible.
            // Doing this right will set up the rest of the regions to be aligned correctly.
            //
            // Subsequent regions should start at the start address of the previous, larger region
            // plus 7/8ths the size of the larger region.
            let region_addr =
                if region_idx == (self.region_count.get() - 1) {
                    // Find out how far out of alignment we are.
                    // More specifically, we can think of this as how far past we are
                    // from the previous aligned address.
                    let unalignment_size = stack_end % region_size;
                    // We will always move _downward_, away from the end of the stack
                    // in order to keep all of the stack covered.
                    stack_end - unalignment_size
                } else {
                    let previous_region_size = self.region_size(region_idx+1);
                    let previous_region_addr = self.mpu_regions[region_idx+1]
                        .and_then(|larger_region| Some(larger_region.start_address() as usize))
                        .unwrap(); // Guaranteed to exist by the previous iteration of the loop.
                    previous_region_addr as usize + (previous_region_size / 8 * 7)
                };
            // Only the most granular region should have all subregions enabled.
            let subregion_state = if region_idx == 0 { 0b1111_1111 } else { 0b0111_1111 };

            // debug!("Requested profiling region #{} @{:#08X}, size: {} bytes, subregion state: {:08b} ",
            //        region_idx, region_addr, region_size, subregion_state);
            let region = process.add_exact_mpu_region(
                region_addr as *const u8,
                region_size,
                subregion_state,
                Permissions::NoAccess)
                .unwrap(); // If we can't do this, we shouldn't be profiling.

            // We must get exactly what we asked for.
            // debug!("Allocated profiling region #{} @{:#08X}, length {} bytes",
            //        region_idx, region.start_address() as usize, region.size());
            assert!(region.start_address() == region_addr as *const u8);
            assert!(region.size() == region_size);

            // Set region states.
            self.mpu_subregion_state[region_idx].set(subregion_state);
            self.mpu_regions[region_idx].set(region);
        }

        // Shrink the regions until we arrive at the process' stack base.
        let stopped_at = self.shrink(process, stack_start - self.stack_allowed.get())
            .expect("Initial shrink failed");
        debug!("Profiler protecting {:#08X} to {:#08X} (stack allowed: {} bytes)",
               self.lower_edge(),
               stopped_at,
               self.stack_allowed.get());
    }

    /// Make the stack-tracking region smaller.
    fn shrink(&self, process: &dyn Process, threshold_addr: usize) -> Result<usize, &'static str> {
        while self.upper_edge() > threshold_addr {
            self.__shrink_rec(process, 0)?;
        }

        Ok(self.upper_edge())
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
    fn __shrink_rec(&self, process: &dyn Process, region_idx: usize) -> Result<(), &'static str> {
        // debug!("s{}", region_idx);
        // Check that there is a configuration to modify.
        let past_end = region_idx >= self.region_count.get();
        let iterated_to_unused = self.mpu_subregion_state[region_idx].is_none();
        if past_end || iterated_to_unused { return Err("no more regions to shrink"); }

        // This region is changing soon; take it and we'll replace it later.
        let old_region = self.mpu_regions[region_idx]
            .take().unwrap(); // ProcessEventSubscriber::created() should set this up.
        let old_subregion_state = self.mpu_subregion_state[region_idx]
            .take().unwrap(); // We just checked the state.

        process.deallocate_mpu_region(&old_region)
            .or(Err("Failed to deallocate old region."))?;

        if old_subregion_state > 0 {
            // If there are subregions active in this region,
            // we can simply disable a subregion.
            let subregion_state = old_subregion_state >> 1;
            // No changes to the region itself; recreate it...
            let region = process.add_exact_mpu_region(
                old_region.start_address(),
                old_region.size(),
                subregion_state,
                mpu::Permissions::NoAccess)
                .ok_or("Failed to disable a subregion.")?;
            // ...and make sure it fits our size exactly.
            assert!(region.start_address() == old_region.start_address());
            assert!(region.size() as usize == self.region_size(region_idx));

            // Update region state.
            self.mpu_regions[region_idx].set(region);
            self.mpu_subregion_state[region_idx].set(subregion_state);
        } else {
            // Can't simply disable a subregion.
            // The larger region needs to disable a subregion.
            self.__shrink_rec(process, region_idx+1)?;

            // We'll scooch by the size of this entire region.
            let shifted_region_base = old_region.start_address() as usize - old_region.size();
            // We'll enable all subregions except the most significant.
            let shifted_region_state = 0b0111_1111;

            // Create the new region...
            let region = process.add_exact_mpu_region(
                shifted_region_base as *const u8,
                old_region.size(),
                shifted_region_state,
                mpu::Permissions::NoAccess)
                .ok_or("Failed to shift region.")?;
            // ...and make sure it fits our size exactly.
            assert!(region.start_address() as usize == shifted_region_base);
            assert!(region.size() as usize == self.region_size(region_idx));

            // Update region state.
            self.mpu_regions[region_idx].set(region);
            self.mpu_subregion_state[region_idx].set(shifted_region_state);
        }

        Ok(())
    }
}

impl<C: 'static + Chip> ProcessEventSubscriber for StackProfiler<C> {
    /// Initializes some information for a process.
    ///
    /// The stack profiler cannot do much with the on-creation event.
    /// The process hasn't even begun running, so the OS has no idea where its stack pointer is.
    /// Instead, we defer any initialization to [`ProcessEventSubscriber::on_syscall()`],
    /// and watch for the `memop` that informs the kernel where the stack is.
    fn created(&self, process: &dyn Process) {  }

    /// Enable the stack-tracking MPU regions.
    fn starting(&self, process: &dyn Process) {  }

    /// Inspects the process' stack pointer to record stack memory usage.
    ///
    /// Notes the process' stack pointer's current location
    /// and adjusts the MPU region it manipulates as necessary.
    fn stopped(&self, process: &dyn Process) {  }

    /// Watch for a process to inform the kernel where it puts its stack.
    ///
    /// Note the location of the stack, and initialize the profiling MPU regions
    /// once the process passes this debug information to the kernel.
    fn on_syscall(&self, process: &dyn Process, syscall: &Syscall) {
        match *syscall {
            Syscall::Memop { operand: 10, arg0: stack_start } => {
                // Getting this memop syscall means one of two things:
                // - The application is running for the very first time.
                // - The application has restarted and is ready to begin execution again.
                self.initialize(process, stack_start);
            },

            _ => {  }
        };
    }
}

impl<C: 'static + Chip> ProcessFault for StackProfiler<C> {
    /// Inspects faults imposed by the profiler's MPU usage.
    ///
    /// Inspects the cause of the fault the running process hit.
    /// If it was caused by the region the profiler configured,
    /// the profiler records the stack space usage
    /// and lets the process die.
    fn process_fault_hook(&self, process: &dyn Process) -> Result<(), ()> {
        if let Some(fault_reason) = self.chip.fault_reason() {
            // Chip can tell us what the fault is.
            match fault_reason {
                // Occurs when the process expectedly writes to the profiled regions.
                // We take a look at the address it attempted to access
                // and use that to determine the next upper limit.
                FaultReason::MemoryAccessViolation(addr) => {
                    debug!("Faulting on access to: {:#010X}.", addr);
                    // Access violation address must be in range of the area protected by the profiler.
                    if self.lower_edge() <= addr && addr <= self.upper_edge() {
                        let old_edge = self.upper_edge();
                        let new_edge = self.shrink(process, addr).expect("Shrink failed");
                        self.stack_allowed.set(self.stack_allowed.get() + old_edge - new_edge);
                        debug!("Shrunk {:#010X} → {:#010X}.", old_edge, new_edge);

                        Err(())
                    } else {
                        // Try looking at the stack pointer for a hint.
                        // If it is lower, then we use that value.
                        let sp = process.stack_pointer()
                            .unwrap(); // We _must_ use the stack pointer in this case.
                        if self.lower_edge() <= sp && sp <= self.upper_edge() {
                            debug!("Stack pointer looks suspect. Trying it.");
                            let old_edge = self.upper_edge();
                            let new_edge = self.shrink(process, sp).expect("Shrink failed");
                            self.stack_allowed.set(self.stack_allowed.get() + old_edge - new_edge);
                            debug!("Shrunk {:#010X} → {:#010X}.", old_edge, new_edge);

                            Err(())
                        } else {
                            // This is not on us to fix.
                            debug!("Bad access out of profiler range.");
                            Err(())
                        }
                    }
                },

                // Occurs when we apply the profiling regions after receiving the memop syscall.
                FaultReason::UnstackingAccessViolation => {
                    let sp = process.stack_pointer()
                        .unwrap(); // We _must_ use the stack pointer in this case.

                    debug!("Unstacking fault at {:#010X}.", sp);

                    // The unstacking fault occurs because the process is reading its context
                    // from a now-protected memory region.
                    //
                    // We give the process 32 bytes not because it is what the process would have naturally used,
                    // But because the stored context is still the exact value of our MPU profiling granularity.
                    self.stack_allowed.set(32);

                    Err(())
                },

                // Occurs when exception entry attempts to save the process' execution context but hits the profiling region.
                FaultReason::StackingAccessViolation => {
                    let sp = process.stack_pointer()
                        .unwrap(); // We _must_ use the stack pointer in this case.

                    // Context save had already begun before the derived exception happened,
                    // so the stack pointer is not where the process would have naturally had it.
                    // Move the SP by the 32 bytes to calculate the actual violation location.
                    let old_edge = self.upper_edge();
                    let new_edge = self.shrink(process, sp + 32).expect("Shrink failed");
                    debug!("Shrunk {:#010X} → {:#010X}.", old_edge, new_edge);
                    assert!(new_edge < old_edge);

                    Err(())
                }

                // The fault is not handled by this implementation.
                _ => Err(())
            }
        } else {
            // Chip can't tell us what the fault is,
            // an it is unlikely to be handled here.
            Err(())
        }
    }
}

fn required_regions(stack_size: usize) -> usize {
    // Increase from 2 ^ 8 = 256 until we exceed provided stack size.
    // Increments of three allow entire previous regions fit inside larger ones.
    let mut exp = 8;
    while (2 << exp) < stack_size { exp += 3; }

    (exp - 8) / 3 + 1
}
