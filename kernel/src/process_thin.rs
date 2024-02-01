use core::fmt::Write;
use core::ptr::NonNull;

use crate::debug;
use crate::kernel::Kernel;
use crate::platform::mpu::Region;
use crate::errorcode::ErrorCode;
use crate::grant;
use crate::grant::SavedUpcall;
use crate::process::{
    Error,
    FunctionCall,
    FunctionCallSource,
    Process,
    ProcessCustomGrantIdentifer,
    ProcessId,
    State,
    Task,
};
use crate::processbuffer::{
    ReadOnlyProcessBuffer,
    ReadWriteProcessBuffer,
};
use crate::syscall::{
    ContextSwitchReason,
    Syscall,
    SyscallReturn,
};
use crate::upcall::{
    Upcall,
    UpcallId,
};
use crate::utilities::cells::OptionalCell;

static mut GRANT_BUFFER_1: [u8; 128] = [0; 128];
static mut ALLOW_BUFFER_1: [u8; 1024] = [0; 1024];

/// A cache query result describing how to pass data to the application.
#[derive(Clone, Copy)]
pub enum CacheReturn {
    /// The syscall is currently outstanding.
    Pending,
    /// The syscall is present in the cache and this is the result.
    Present(FunctionCall, Option<&'static [u8]>),
}

/// An cache entry.
#[derive(Copy, Clone)]
enum CacheSlot {
    /// A call is outstanding for a syscall with a given driver and subscribe no.
    Pending(usize, usize),
    /// A call is outstanding for a syscall with a given driver and subscribe no. and a process is waiting for it.
    Requested(&'static dyn Process, usize, usize),
    /// A completed, cached result.
    Ready(FunctionCall, Option<&'static [u8]>),
}

impl CacheSlot {
    fn take_ready_cache(&self) -> CacheReturn {
        match self {
            CacheSlot::Ready(fc, buffer) => CacheReturn::Present(*fc, *buffer),

            // Called when the slot is not a ready slot.
            _ => panic!()
        }
    }
}

fn __do_not_call() -> ! {
    loop {  }
}

/// A minimal, mimicry of a [`Process`].
pub struct ThinProcess {
    pid: ProcessId,
    kernel: &'static Kernel,
    /// Driver no. and grant no. of the current allocation.
    current_allocation: OptionalCell<(usize, usize)>,
    /// Cached result.
    cached_result: OptionalCell<CacheSlot>,
}

impl ThinProcess {
    /// Create a new `ThinProcess`.
    ///
    /// The `array_idx` is the index of the process in the `PROCESSES` array.
    pub fn new(kernel: &'static Kernel, array_idx: usize) -> ThinProcess {
        ThinProcess {
            pid: ProcessId::new(kernel, 99, array_idx),
            kernel,
            current_allocation: OptionalCell::empty(),
            cached_result: OptionalCell::empty(),
        }
    }

    /// Allocate a free buffer in the thin process memory space.
    ///
    /// Why does this function exist?
    /// Make sure we have room to prefetch this incoming data anyway.
    pub fn reserve_buffer(&self, byte_len: usize) -> Result<(*mut u8, usize), ()> {
        Ok((unsafe { ALLOW_BUFFER_1.as_mut_ptr() }, byte_len))
    }

    /// Fill upcall table entries.
    ///
    /// Populate the upcall table with (invalid) non-null entries.
    /// This must happen sometime after the capsule has entered the grant for the first time
    /// but before an upcall actually happens.
    pub fn populate_upcall_table(&self) {
        let upcall_table: &mut [SavedUpcall] = unsafe {
            let upcall_count: usize = *(GRANT_BUFFER_1.as_ptr() as *const usize);
            core::slice::from_raw_parts_mut(
                (GRANT_BUFFER_1.as_ptr() as usize + core::mem::size_of::<usize>()) as *mut SavedUpcall,
                upcall_count)
        };

        for upcall_fn_addr in upcall_table.iter_mut() {
            *upcall_fn_addr = SavedUpcall {
                appdata: 0,
                fn_ptr:Some(unsafe { NonNull::new_unchecked(__do_not_call as *mut()) }),
            };
        }
    }

    pub fn cache_space_ready(&self) -> bool {
        self.cached_result.is_none()
    }

    /// Check cache for prefetched data.
    ///
    /// The caller provides arguments for the results that they are looking for.
    /// This function either returns the cached results or None.
    pub fn check_syscall_cache(
        &self,
        process: &'static dyn Process,
        driver_no: usize,
        subdriver_no: usize,
        arg0: usize,
        arg1: usize) -> Option<CacheReturn>
    {
        // debug!("Cache check for call: {:?}", (driver_no, subdriver_no));
        // And this is where we assume we can match (driver no., subdriver no.) and
        // (driver no., subscribe no.) without issues. See comment in enqueue_task().
        // We know that subscribe no. != subdriver no...
        //
        // This is not a complex process, but we show how this could likely scale in the future.
        // Perhaps drivers' implementations could inform this.
        let mapping = match (driver_no, subdriver_no) {
            (0x00005, 3) => Some((0x00005, 0)),
            (0x60001, 1) => Some((0x60001, 0)),
            _ => None,
        };

        // Check if there was a matching mapping from the above,
        // if there was, then check if there is a result for it in the cache.
        if let Some((req_driver_no, req_subscribe_no)) = mapping {
            let mapping = mapping.unwrap();
            // debug!("Checking cache for {:?}", mapping);
            // debug!("Cache {}", match self.cached_result.extract() {
            //     None => "none",
            //     Some(CacheSlot::Pending(_, _)) => "pending",
            //     Some(CacheSlot::Requested(_, _, _)) => "requested",
            //     Some(CacheSlot::Ready(_, _)) => "ready"
            // });
            let (matches, ready) = self.cached_result.map_or((false, false), |cs| {
                // debug!("A result is currently cached...");
                match cs {
                    // A process has asked to execute an operation that the AoT system has already dispatched.
                    // We take note of the process here by switching the slot's state to Requested.
                    CacheSlot::Pending(cache_driver_no, cache_subscribe_no) => {
                        if mapping == (*cache_driver_no, *cache_subscribe_no) {
                            self.cached_result.set(CacheSlot::Requested(process, *cache_driver_no, *cache_subscribe_no));
                            (true, false)
                        } else {
                            (false, false)
                        }
                    },

                    // A process has asked to execute the operation that the AoT has already dispatched,
                    // and the batch controller previously checked the cache for this result. We could
                    // just give this result right back (reduce redundant syscalls). This would require
                    // a more extensible way of tracking which processes are interested in this data.
                    CacheSlot::Requested(_process, cache_driver_no, cache_subscribe_no) => {
                        if mapping == (*cache_driver_no, *cache_subscribe_no) {
                            (true, false)
                        } else {
                            (false, false)
                        }
                    },

                    // A completed AoT request has been made and is sitting in the cache.
                    CacheSlot::Ready(fc, _buffer) => {
                        match fc.source {
                            FunctionCallSource::Driver(UpcallId { driver_num: cache_driver_no, subscribe_num: cache_subscribe_no }) => {
                                if mapping == (cache_driver_no, cache_subscribe_no) {
                                    (true, true)
                                } else {
                                    (false, false)
                                }
                            },

                            _ => (false, false)
                        }
                    }
                }
            });
            // debug!("Match = {}, ready = {}", matches, ready);

            if matches && ready {
                Some(self.cached_result
                     .take()
                     .unwrap()
                     .take_ready_cache())
            } else {
                None
            }
        } else {
            None
        }
    }

    pub fn indicate(&self, driver_no: usize, subscribe_no: usize) {
        // debug!("{}: HPEND: ({}, {})", unsafe { core::ptr::read_volatile((0x400F0800 + 0x04) as *mut u32) }, driver_no, subscribe_no);
        self.cached_result.set(CacheSlot::Pending(driver_no, subscribe_no));
    }
}

impl Process for ThinProcess {
    fn processid(&self) -> ProcessId { self.pid }

    /// Drivers' method of providing results of syscalls asynchronously.
    fn enqueue_task(&self, task: Task) -> Result<(), ErrorCode> {
        // Figure out what driver result this is.
        // For the most part, we leave much of FunctionCall the same.
        // It will only be necessary to change FunctionCall.pc to the target application's function,
        // and that will be done by another entity, (i.e., PrefetchController).
        //
        // We do have to be aware of which syscalls have RW-allowed buffers tied to them so we can
        // let the other entity know.
        let current_cache_state = self.cached_result.extract();
        match task {
            Task::FunctionCall(ref fc) => match fc.source {
                FunctionCallSource::Driver(UpcallId { driver_num, subscribe_num }) => {
                    // debug!("Got result: {:?} (currently {})", fc, match current_cache_state {
                    //     None => "none",
                    //     Some(CacheSlot::Pending(_, _)) => "pending",
                    //     Some(CacheSlot::Requested(_, _, _)) => "requested",
                    //     Some(CacheSlot::Ready(_, _)) => "ready"
                    // });
                    match (driver_num, subscribe_num) {
                        // ADC, DMA-driven sampling.
                        (0x00005, 0) => {
                            // debug!("Successfully cached ADC result.");
                            match current_cache_state {
                                None => {
                                    // debug!("{}: HREDY: ({}, {})", unsafe { core::ptr::read_volatile((0x400F0800 + 0x04) as *mut u32) }, driver_num, subscribe_num);
                                    self.cached_result.set(CacheSlot::Ready(*fc,Some(unsafe { &ALLOW_BUFFER_1 })));
                                    Ok(())
                                },

                                Some(CacheSlot::Pending(driver_no, subscribe_no)) => {
                                    // debug!("{}: HREDY: ({}, {})", unsafe { core::ptr::read_volatile((0x400F0800 + 0x04) as *mut u32) }, driver_no, subscribe_no);
                                    self.cached_result.set(CacheSlot::Ready(*fc,Some(unsafe { &ALLOW_BUFFER_1 })));
                                    Ok(())
                                },

                                // We can go ahead and hand the result to the process.
                                Some(CacheSlot::Requested(requesting_process, driver_no, subscribe_no)) => {
                                    // debug!("{}: HRDCB: ({}, {})", unsafe { core::ptr::read_volatile((0x400F0800 + 0x04) as *mut u32) }, driver_no, subscribe_no);
                                    // Rewrite the PC so the upcall goes to the process's callback
                                    // and not the dummy callback here. When the requesting process
                                    // does not specify one, we use the __do_not_call() function,
                                    // which will never return. The application will hang.
                                    let (opt_fn_ptr, _data) = grant::subscription(requesting_process, driver_no, subscribe_no);
                                    let fn_ptr = opt_fn_ptr.unwrap_or(unsafe { NonNull::new_unchecked(__do_not_call as *mut()) });
                                    let _ = requesting_process.enqueue_task(match task {
                                        Task::FunctionCall(fc) => Task::FunctionCall(FunctionCall {
                                            pc: fn_ptr.as_ptr() as usize,
                                            ..fc
                                        }),

                                        _ => panic!(), // There should always be a function call to pass.
                                    }).unwrap();

                                    self.cached_result.clear();

                                    Ok(())
                                },

                                // For some reason, the cache slot is ready and we are overwriting it?
                                _ => { Ok(()) }
                            }
                        },

                        // Temperature or humidity reading.
                        (0x60000, 0) | (0x60001, 0) => {
                            // debug!("Successfully cached I2C result.");
                            match current_cache_state {
                                None => {
                                    // debug!("{}: HREDY: ({}, {})", unsafe { core::ptr::read_volatile((0x400F0800 + 0x04) as *mut u32) }, driver_num, subscribe_num);
                                    self.cached_result.set(CacheSlot::Ready(*fc, None));
                                    Ok(())
                                },

                                Some(CacheSlot::Pending(driver_no, subscribe_no)) => {
                                    // debug!("{}: HREDY: ({}, {})", unsafe { core::ptr::read_volatile((0x400F0800 + 0x04) as *mut u32) }, driver_no, subscribe_no);
                                    self.cached_result.set(CacheSlot::Ready(*fc, None));
                                    Ok(())
                                },

                                // We can go ahead and hand the result to the process.
                                Some(CacheSlot::Requested(requesting_process, driver_no, subscribe_no)) => {
                                    // debug!("{}: HRDCB: ({}, {})", unsafe { core::ptr::read_volatile((0x400F0800 + 0x04) as *mut u32) }, driver_no, subscribe_no);
                                    requesting_process.enqueue_task(task);
                                    self.cached_result.clear();
                                    Ok(())
                                },

                                // See previous case.
                                _ => { Ok(()) },
                            }
                        }

                        // We do not handle any other syscalls.
                        _ => panic!(),
                    }
                },

                // We do not handle any other function call sources.
                _ => panic!(),
            },

            // We do not handle other types of tasks.
            _ => panic!(),
        }
    }

    fn ready(&self) -> bool { false }

    fn has_tasks(&self) -> bool { false }

    fn dequeue_task(&self) -> Option<Task> { None }

    fn remove_pending_upcalls(&self, upcall_id: UpcallId) {  }

    fn get_state(&self) -> State { State::Yielded }

    fn set_yielded_state(&self) {  }

    fn stop(&self) {  }

    fn resume(&self) {  }

    fn set_fault_state(&self) {  }

    fn get_restart_count(&self) -> usize { 0 }

    fn get_process_name(&self) -> &'static str { "thin" }

    fn terminate(&self, completion_code: u32) {  }

    fn try_restart(&self, completion_code: u32) {  }

    fn brk(&self, new_break: *const u8) -> Result<*const u8, Error> { Ok(new_break as *const u8) }

    fn sbrk(&self, increment: isize) -> Result<*const u8, Error> { Ok(0 as *const u8) }

    fn mem_start(&self) -> *const u8 { 0 as *const u8 }

    fn mem_end(&self) -> *const u8 { 0 as *const u8 }

    fn flash_start(&self) -> *const u8 { 0 as *const u8 }

    fn flash_end(&self) -> *const u8 { 0 as *const u8 }

    fn kernel_memory_break(&self) -> *const u8 { 0 as *const u8 }

    fn number_writeable_flash_regions(&self) -> usize { 0 }

    fn get_writeable_flash_region(&self, region_index: usize) -> (u32, u32) { (0, 0) }

    fn update_stack_start_pointer(&self, stack_pointer: *const u8) {  }

    fn update_heap_start_pointer(&self, heap_pointer: *const u8) {  }

    fn app_memory_break(&self) -> *const u8 { 0 as *const u8 }

    fn build_readwrite_process_buffer(
        &self,
        start_address: *mut u8,
        size: usize
    ) -> Result<ReadWriteProcessBuffer, ErrorCode> {
        let rw_buffer = unsafe {
            ReadWriteProcessBuffer::new(start_address, size, self.processid())
        };

        Ok(rw_buffer)
    }

    fn build_readonly_process_buffer(
        &self,
        start_address: *const u8,
        size: usize
    ) -> Result<ReadOnlyProcessBuffer, ErrorCode> {
        // TODO
        unimplemented!();
        Err(ErrorCode::NOSUPPORT)
    }

    unsafe fn set_byte(&self, addr: *mut u8, value: u8) -> bool { true }

    fn flash_non_protected_start(&self) -> *const u8 { 0 as *const u8 }

    fn setup_mpu(&self) {  }

    fn add_mpu_region(
        &self,
        unallocated_memory_start: *const u8,
        unallocated_memory_size: usize,
        min_region_size: usize,
    ) -> Option<Region> { None }

    fn allocate_grant(
        &self,
        grant_no: usize,
        driver_no: usize,
        size: usize,
        align: usize,
    ) -> Option<NonNull<u8>> {
        // debug!("allocate_grant({}, {}, {}, {})",
        //        grant_no,
        //        driver_no,
        //        size,
        //        align);

        self.current_allocation.set((driver_no, grant_no));
        // For now, this will not fail.
        Some(unsafe { NonNull::new_unchecked(GRANT_BUFFER_1.as_mut_ptr()) })
    }

    fn grant_is_allocated(&self, grant_no: usize) -> Option<bool> {
        // debug!("grant_is_allocated({})", grant_no);
        if let Some((_current_driver_no, current_grant_no)) = self.current_allocation.extract() {
            Some(current_grant_no == grant_no)
        } else {
            Some(false)
        }
    }

    fn allocate_custom_grant(
        &self,
        size: usize,
        align: usize,
    ) -> Option<(ProcessCustomGrantIdentifer, NonNull<u8>)> {
        unimplemented!()
    }

    fn enter_grant(
        &self,
        grant_no: usize
    ) -> Result<*mut u8, Error> {
        // debug!("enter_grant({})", grant_no);
        if let Some((current_driver_no, current_grant_no)) = self.current_allocation.extract() {
            if current_grant_no == grant_no {
                self.populate_upcall_table();
                Ok(unsafe { GRANT_BUFFER_1.as_mut_ptr() })
            } else {
                Err(Error::InactiveApp)
            }
        } else {
            Err(Error::InactiveApp)
        }
    }

    fn enter_custom_grant(
        &self,
        identifier: ProcessCustomGrantIdentifer,
    ) -> Result<*mut u8, Error> {
        unimplemented!()
    }

    fn leave_grant(&self, grant_no: usize) {  }

    fn grant_allocated_count(&self) -> Option<usize> {
        unimplemented!()
    }

    fn lookup_grant_from_driver_num(&self, driver_no: usize) -> Result<usize, Error> {
        if let Some((current_driver_no, current_grant_no)) = self.current_allocation.extract() {
            if current_driver_no == driver_no {
                Ok(current_grant_no)
            } else {
                Err(Error::AddressOutOfBounds)
            }
        } else {
            Err(Error::AddressOutOfBounds)
        }
    }

    fn is_valid_upcall_function_pointer(&self, upcall_fn: NonNull<()>) -> bool {
        unimplemented!()
    }

    fn set_syscall_return_value(&self, return_value: SyscallReturn) {  }

    fn set_process_function(&self, callback: FunctionCall) {  }

    fn switch_to(&self) -> Option<ContextSwitchReason> { None }

    fn print_memory_map(&self, writer: &mut dyn Write) {  }

    fn print_full_process(&self, writer: &mut dyn Write) {  }

    fn debug_syscall_count(&self) -> usize { 0 }

    fn debug_dropped_upcall_count(&self) -> usize { 0 }

    fn debug_timeslice_expiration_count(&self) -> usize { 0 }

    fn debug_timeslice_expired(&self) {  }

    fn debug_syscall_called(&self, last_syscall: Syscall) {  }

    fn debug_heap_start(&self) -> Option<*const u8> { None }

    fn debug_stack_start(&self) -> Option<*const u8> { None }

    fn debug_stack_end(&self) -> Option<*const u8> { None }

    fn pending_task_count(&self) -> usize { 0 }

    fn flush_pending_tasks(&self) {  }
}
