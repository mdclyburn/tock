// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

//! Data structure for storing compile-time configuration options in the kernel.
//!
//! The rationale for configuration based on a `const` object is twofold.
//!
//! - In theory, Cargo features could be used for boolean-based configuration.
//!   However, these features are generally error-prone for non-trivial use
//!   cases. First, they are globally enabled as long as a dependency
//!   relationship requires a feature (even for other dependency relationships
//!   that do not want the feature). Second, code gated by a non-enabled feature
//!   isn't even type-checked by the compiler, and therefore we can end up with
//!   broken features due to refactoring code (if these features aren't tested
//!   during the refactoring), or to incompatible feature combinations.
//!
//! - Cargo features can only contain bits. On the other hand, a constant value
//!   can contain arbitrary types, which allow configuration based on integers,
//!   strings, or even more complex values.
//!
//! With a typed `const` configuration, all code paths are type-checked by the
//! compiler - even those that end up disabled - which greatly reduces the risks
//! of breaking a feature or combination of features because they are disabled
//! in tests.
//!
//! In the meantime, after type-checking, the compiler can optimize away dead
//! code by folding constants throughout the code, so for example a boolean
//! condition used in an `if` block will in principle have a zero cost on the
//! resulting binary - as if a Cargo feature was used instead. Some simple
//! experiments on generated Tock code have confirmed this zero cost in
//! practice.

/// Data structure holding compile-time configuration options.
///
/// To change the configuration, modify the relevant values in the `CONFIG`
/// constant object defined at the end of this file.
pub(crate) struct Config {
    /// Whether the kernel should trace syscalls to the debug output.
    ///
    /// If enabled, the kernel will print a message in the debug output for each
    /// system call and upcall, with details including the application ID, and
    /// system call or upcall parameters.
    pub(crate) trace_syscalls: bool,

    /// Whether the kernel should show debugging output when loading processes.
    ///
    /// If enabled, the kernel will show from which addresses processes are
    /// loaded in flash and into which SRAM addresses. This can be useful to
    /// debug whether the kernel could successfully load processes, and whether
    /// the allocated SRAM is as expected.
    pub(crate) debug_load_processes: bool,

    /// Whether the kernel should output additional debug information on panics.
    ///
    /// If enabled, the kernel will include implementations of
    /// `Process::print_full_process()` and `Process::print_memory_map()` that
    /// display the process's state in a human-readable form.
    // This config option is intended to allow for smaller kernel builds (in
    // terms of code size) where printing code is removed from the kernel
    // binary. Ideally, the compiler would automatically remove
    // printing/debugging functions if they are never called, but due to
    // limitations in Rust (as of Sep 2021) that does not happen if the
    // functions are part of a trait (see
    // https://github.com/tock/tock/issues/2594).
    //
    // Attempts to separate the printing/debugging code from the Process trait
    // have only been moderately successful (see
    // https://github.com/tock/tock/pull/2826 and
    // https://github.com/tock/tock/pull/2759). Until a more complete solution
    // is identified, using configuration constants is the most effective
    // option.
    pub(crate) debug_panics: bool,

    /// Whether the kernbel should output debug information when it is checking
    /// the cryptographic credentials of a userspace process. If enabled, the
    /// kernel will show which footers were found and why processes were started
    /// or not.
    // This config option is intended to provide some visibility into process
    // credentials checking, e.g., whether elf2tab and tockloader are generating
    // properly formatted footers.
    pub(crate) debug_process_credentials: bool,
}

/// A unique instance of `Config` where compile-time configuration options are
/// defined. These options are available in the kernel crate to be used for
/// relevant configuration. Notably, this is the only location in the Tock
/// kernel where we permit `#[cfg(x)]` to be used to configure code based on
/// Cargo features.
pub(crate) const CONFIG: Config = Config {
    trace_syscalls: cfg!(feature = "trace_syscalls"),
    debug_load_processes: cfg!(feature = "debug_load_processes"),
    debug_panics: !cfg!(feature = "no_debug_panics"),
    debug_process_credentials: cfg!(feature = "debug_process_credentials"),
};

use core::sync::atomic::{AtomicU32, Ordering};

const RTC1_COUNTER_ADDR: usize = 0x4001_1000 + 0x0504;
const RTC1_MASK: u32 = 0x00FF_FFFF;

static T_ISLE_PREP: AtomicU32 = AtomicU32::new(0);
static T_SI_PREP: AtomicU32 = AtomicU32::new(0);
static T_REG_CALL: AtomicU32 = AtomicU32::new(0);
static T_ROUND_TRIP: AtomicU32 = AtomicU32::new(0);
static T_REG_RET: AtomicU32 = AtomicU32::new(0);
static T_SI_RES: AtomicU32 = AtomicU32::new(0);
static T_ISLE_DONE: AtomicU32 = AtomicU32::new(0);

static S_ISLE_PREP: AtomicU32 = AtomicU32::new(0);
static S_SI_PREP: AtomicU32 = AtomicU32::new(0);
static S_REG_CALL: AtomicU32 = AtomicU32::new(0);
static S_RT: AtomicU32 = AtomicU32::new(0);
static S_REG_RET: AtomicU32 = AtomicU32::new(0);
static S_SI_RES: AtomicU32 = AtomicU32::new(0);
static S_ISLE_DONE: AtomicU32 = AtomicU32::new(0);

#[inline]
pub fn now() -> u32 {
    // ### Safety
    // Reads the memory-mapped nRF52840 RTC1.COUNTER register (read-only) for timing measurements.
    unsafe { core::ptr::read_volatile(RTC1_COUNTER_ADDR as *const u32) & RTC1_MASK }
}

#[inline]
fn diff(start: u32, end: u32) -> u32 {
    end.wrapping_sub(start) & RTC1_MASK
}

pub fn reset_crypto_timings() {
    T_ISLE_PREP.store(0, Ordering::Relaxed);
    T_SI_PREP.store(0, Ordering::Relaxed);
    T_REG_CALL.store(0, Ordering::Relaxed);
    T_ROUND_TRIP.store(0, Ordering::Relaxed);
    T_REG_RET.store(0, Ordering::Relaxed);
    T_SI_RES.store(0, Ordering::Relaxed);
    T_ISLE_DONE.store(0, Ordering::Relaxed);
}

#[inline]
pub fn start_isle_prep() {
    S_ISLE_PREP.store(now(), Ordering::Relaxed);
}

#[inline]
pub fn pause_isle_prep() {
    let elapsed = diff(S_ISLE_PREP.load(Ordering::Relaxed), now());
    T_ISLE_PREP.fetch_add(elapsed, Ordering::Relaxed);
}

#[inline]
pub fn resume_isle_prep() {
    S_ISLE_PREP.store(now(), Ordering::Relaxed);
}

#[inline]
pub fn end_isle_prep() {
    let elapsed = diff(S_ISLE_PREP.load(Ordering::Relaxed), now());
    T_ISLE_PREP.fetch_add(elapsed, Ordering::Relaxed);
}

#[inline]
pub fn start_si_prep() {
    S_SI_PREP.store(now(), Ordering::Relaxed);
}

#[inline]
pub fn pause_si_prep() {
    let elapsed = diff(S_SI_PREP.load(Ordering::Relaxed), now());
    T_SI_PREP.fetch_add(elapsed, Ordering::Relaxed);
}

#[inline]
pub fn resume_si_prep() {
    S_SI_PREP.store(now(), Ordering::Relaxed);
}

#[inline]
pub fn end_si_prep() {
    let elapsed = diff(S_SI_PREP.load(Ordering::Relaxed), now());
    T_SI_PREP.fetch_add(elapsed, Ordering::Relaxed);
}

#[inline]
pub fn start_reg_call() {
    S_REG_CALL.store(now(), Ordering::Relaxed);
}

#[inline]
pub fn end_reg_call() {
    let t = now();
    let elapsed = diff(S_REG_CALL.load(Ordering::Relaxed), t);
    T_REG_CALL.store(elapsed, Ordering::Relaxed);
    S_RT.store(t, Ordering::Relaxed);
}

#[inline]
pub fn start_reg_ret() {
    let t = now();
    let rt = diff(S_RT.load(Ordering::Relaxed), t);
    T_ROUND_TRIP.store(rt, Ordering::Relaxed);
    S_REG_RET.store(t, Ordering::Relaxed);
}

#[inline]
pub fn pause_reg_ret() {
    let elapsed = diff(S_REG_RET.load(Ordering::Relaxed), now());
    T_REG_RET.fetch_add(elapsed, Ordering::Relaxed);
}

#[inline]
pub fn resume_reg_ret() {
    S_REG_RET.store(now(), Ordering::Relaxed);
}

#[inline]
pub fn end_reg_ret() {
    let elapsed = diff(S_REG_RET.load(Ordering::Relaxed), now());
    T_REG_RET.fetch_add(elapsed, Ordering::Relaxed);
}

#[inline]
pub fn start_si_res() {
    S_SI_RES.store(now(), Ordering::Relaxed);
}

#[inline]
pub fn end_si_res() {
    let elapsed = diff(S_SI_RES.load(Ordering::Relaxed), now());
    T_SI_RES.store(elapsed, Ordering::Relaxed);
}

#[inline]
pub fn start_isle_done() {
    S_ISLE_DONE.store(now(), Ordering::Relaxed);
}

#[inline]
pub fn end_isle_done() {
    let elapsed = diff(S_ISLE_DONE.load(Ordering::Relaxed), now());
    T_ISLE_DONE.store(elapsed, Ordering::Relaxed);
}

pub fn show_crypto_timings() {
    let isle_prep = T_ISLE_PREP.load(Ordering::Relaxed);
    let si_prep = T_SI_PREP.load(Ordering::Relaxed);
    let reg_call = T_REG_CALL.load(Ordering::Relaxed);
    let round_trip = T_ROUND_TRIP.load(Ordering::Relaxed);
    let reg_ret = T_REG_RET.load(Ordering::Relaxed);
    let si_res = T_SI_RES.load(Ordering::Relaxed);
    let isle_done = T_ISLE_DONE.load(Ordering::Relaxed);

    let isle_total = isle_prep + isle_done;
    let si_total = si_prep + si_res;
    let reg_total = reg_call + reg_ret;
    let kernel_total = isle_total + si_total + reg_total;
    let e2e_total = kernel_total + round_trip;

    let to_us = |ticks: u32| ticks as f32 / 0.032768f32;

    crate::debug!(
        "[timing] isle_prep={}t ({:.1} us), si_prep={}t ({:.1} us), reg_call={}t ({:.1} us), round_trip={}t ({:.1} us), reg_ret={}t ({:.1} us), si_res={}t ({:.1} us), isle_done={}t ({:.1} us)",
        isle_prep, to_us(isle_prep),
        si_prep, to_us(si_prep),
        reg_call, to_us(reg_call),
        round_trip, to_us(round_trip),
        reg_ret, to_us(reg_ret),
        si_res, to_us(si_res),
        isle_done, to_us(isle_done)
    );
    crate::debug!(
        "[timing] totals: isle={}t ({:.1} us), si={}t ({:.1} us), reg={}t ({:.1} us), kernel={}t ({:.1} us), e2e={}t ({:.1} us)",
        isle_total, to_us(isle_total),
        si_total, to_us(si_total),
        reg_total, to_us(reg_total),
        kernel_total, to_us(kernel_total),
        e2e_total, to_us(e2e_total)
    );
}
