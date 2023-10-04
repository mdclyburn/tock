use core::fmt::Write;
use core::ptr::NonNull;

use crate::kernel::Kernel;
use crate::platform::mpu::Region;
use crate::errorcode::ErrorCode;
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
use crate::upcall::UpcallId;

pub struct ThinProcess {
    kernel: &'static Kernel,
}

impl Process for ThinProcess {
    fn processid(&self) -> ProcessId { ProcessId::new(self.kernel, 99, 0) }

    fn enqueue_task(&self, task: Task) -> Result<(), ErrorCode> { Ok(()) }

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
        unimplemented!();
        Err(ErrorCode::NOSUPPORT)
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
        // TODO
        unimplemented!();
        None
    }

    fn grant_is_allocated(&self, grant_no: usize) -> Option<bool> {
        // TODO
        unimplemented!();
        None
    }

    fn allocate_custom_grant(
        &self,
        size: usize,
        align: usize,
    ) -> Option<(ProcessCustomGrantIdentifer, NonNull<u8>)> { None }

    fn enter_grant(
        &self,
        grant_num: usize
    ) -> Result<*mut u8, Error> {
        // TODO: create structures in the thin process struct to mimick this...
        unimplemented!();
        Err(Error::NoSuchApp)
    }

    fn enter_custom_grant(
        &self,
        identifier: ProcessCustomGrantIdentifer,
    ) -> Result<*mut u8, Error> {
        Err(Error::NoSuchApp)
    }

    fn leave_grant(&self, grant_no: usize) {  }

    fn grant_allocated_count(&self) -> Option<usize> {
        // TODO
        unimplemented!();
        None
    }

    fn lookup_grant_from_driver_num(&self, driver_num: usize) -> Result<usize, Error> {
        // TODO
        unimplemented!();
        Err(Error::NoSuchApp)
    }

    fn is_valid_upcall_function_pointer(&self, upcall_fn: NonNull<()>) -> bool {
        true
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
