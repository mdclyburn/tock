#![no_std]

//! Code for supporting performance benchmarking.
//!
//! This crate exists to solve the dependency problem for the kernel crate.
//! Performance benchmarking must be available for the kernel, but the
//! perf crate depends on HILs within the kernel crate.

/// Performance stat-tracking facility.
pub trait Accumulate {
    /// Add a data value to the specified waypoint.
    fn account(&self, waypoint_id: u8, val: u32);

    /// Initiate a freeze to prepare to send data to the host.
    fn freeze(&self);
}

pub static mut INSTANCE: Option<&'static dyn Accumulate> = None;

/// Set the Accumulate instance.
///
/// It is likely unnecessary to call this function.
/// `perf::use_instance()` will set the instance here as well.
pub unsafe fn use_instance(acc_instance: &'static dyn Accumulate) {
    if INSTANCE.is_some() {
        // Double-set, not good.
        panic!()
    } else {
        INSTANCE = Some(acc_instance)
    }
}

#[macro_export]
macro_rules! count {
    ($id:expr, $val:expr) => {{
        let id = ($id);
        let val = ($val);
        let instance = unsafe { $crate::INSTANCE.unwrap() };
        instance.account(id, val);
    }};

    ($id:expr, $val:expr, $check:expr) => {{
        let check = ($check);
        let id = ($id);
        let val = ($val);

        if check {
            let instance = unsafe { $crate::INSTANCE.unwrap() };
            instance.account(id, val);
        }
    }}
}

#[macro_export]
macro_rules! freeze {
    () => {{
        let instance = unsafe { $crate::INSTANCE.unwrap() };
        instance.freeze();
    }};

    ($check:expr) => {{
        if ($check) {
            let instance = unsafe { $crate::INSTANCE.unwrap() };
            instance.freeze();
        }
    }}
}
