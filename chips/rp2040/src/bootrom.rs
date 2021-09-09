//! Useful data and functions contained in the RP2040 bootrom.
//!
//! Interpreted from the RP2040 datasheet.

#![allow(dead_code)]

/// Initial boot stack pointer.
const BOOT_STACK_POINTER: *const *const u32 = 0x0000_0000 as *const *const u32;

/// Boot reset function handler.
const BOOT_RESET_HANDLER: *const fn() = 0x0000_0004 as *const fn();

/// NMI handler.
const NMI_HANDLER: *const fn() = 0x0000_0008 as *const fn();

/// Hard fault handler.
const HARD_FAULT_HANDLER: *const fn() = 0x0000_000c as *const fn();

/// Magic numbers, 'M', 'u', 0x01.
const MAGIC: *const u8 = 0x0000_0010 as *const u8;

/// Bootrom version.
const VERSION: *const u8 = 0x0000_0013 as *const u8;

/// Public function lookup table (16-bit pointer).
const FUNCTION_LOOKUP_TABLE: u16 = 0x0000_0014 as u16;

/// Public data lookup table (16-bit pointer).
const PUBLIC_DATA_LOOKUP_TABLE: u16 = 0x0000_0016 as u16;

/// Pointer to the table lookup helper function (16-bit pointer).
const LOOKUP_HELPER_FUNCTION: u16 = 0x0000_0018 as u16;

/// Check bootrom magic values.
fn verify_magic() {
    let magic = unsafe { core::slice::from_raw_parts(MAGIC, 3) };
    assert!(magic[0] == 'M' as u8);
    assert!(magic[1] == 'u' as u8);
    assert!(magic[2] == 0x01u8);
}

/// Find a function from the lookup table.
unsafe fn lookup_fn(fn_code: u32) -> *const () {
    verify_magic();

    let lookup_helper: *const fn(*const u16, u32) -> *const () =
        LOOKUP_HELPER_FUNCTION as u32 as *const fn(*const u16, u32) -> *const ();
    let fn_table: *const u16 = FUNCTION_LOOKUP_TABLE as u32 as *const u16;

    (*lookup_helper)(fn_table, fn_code)
}
