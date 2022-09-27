/*! OS-level energy management.

Tracks and informs energy-related operations on a
per-process,
per-peripheral,
per-operation basis.
Having this granularity of energy information available allows the OS to decide if and when to allow energy usage.
Any energy figures reported by this module is in microjoules and microjoules per millisecond.
 */

use crate::process::ProcessId;
use crate::hil::time;
use crate::hil::time::ConvertTicks as _;

struct PeripheralUsage;

#[derive(Debug)]
struct ProcessUsage {
    active: u32,
}

/// An event that will change system energy consumption.
#[derive(Debug)]
pub enum Event<'a> {
    /// A process has begun executing on the CPU.
    Running(&'a ProcessId),
    /// A process has stopped executing on the CPU.
    Stopped(&'a ProcessId),
    /// The kernel has decided to enter a low-power sleep state.
    Sleeping,
    /// The system has awoken from a low-power sleep state.
    Awake,
}

/// Energy accounting data.
pub struct Accounting<A: 'static + time::Frequency, B: 'static + time::Ticks> {
    time_source: &'static dyn time::Counter<'static, Frequency = A, Ticks = B>,
}

impl<A: 'static + time::Frequency, B: 'static + time::Ticks> Accounting<A, B> {
    pub fn new(
        time_source: &'static dyn time::Counter<Frequency = A, Ticks = B>
    ) -> Accounting<A, B> {
        Accounting {
            time_source,
        }
    }

    // Pass an event to the accounting system to update energy accounting data.
    pub fn process(e: Event) {
        match e {
            // The scheduler has selected a process to execute.
            // Accounting should account active energy usage to the process.
            Event::Running(pid) => {  },
            // The process the scheduler selected to run has stopped running (the reason does not matter).
            // Accounting should stop accounting active energy usage to the process.
            Event::Stopped(pid) => {  },

            _ => unimplemented!(),
        }
    }
}
