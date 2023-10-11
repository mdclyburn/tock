use core::fmt::Write;
use core::ptr::NonNull;

use crate::debug;
use crate::kernel::Kernel;
use crate::platform::mpu::Region;
use crate::errorcode::ErrorCode;
use crate::grant::SavedUpcall;
use crate::process::{
    Error,
    FunctionCall,
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

/// A cache hit result describing how to pass data to the application.
pub struct CacheReturn {
    upcall_id: UpcallId,
    args: (usize, usize, usize, usize),
}

fn __do_not_call() -> ! {
    loop {  }
}

/// A minimal, mimicry of a [`Process`].
pub struct ThinProcess {
    pid: ProcessId,
    kernel: &'static Kernel,
    current_allocation: OptionalCell<(usize, usize)>,
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

    /// Check cache for prefetched data.
    pub fn check_syscall_cache(
        &self,
        driver_no: usize,
        subdriver_no: usize,
        arg0: usize,
        arg1: usize) -> Option<CacheReturn>
    {
        None
    }
}

impl Process for ThinProcess {
    fn processid(&self) -> ProcessId { self.pid }

    fn enqueue_task(&self, task: Task) -> Result<(), ErrorCode> {
        unimplemented!()
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
