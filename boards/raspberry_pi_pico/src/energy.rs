/*! Energy accounting for the Raspberry Pi Pico.
 */

use core::cell::Cell;

use kernel::energy::DriverEnergyAccounting;
use kernel::hil::time;
use kernel::hil::time::ConvertTicks as _;
use kernel::syscall::{
    Syscall,
    SyscallReturn,
};

use capsules;

pub struct SimultaneousAccounting<A: 'static + time::Frequency,
                                  B: 'static + time::Ticks>
{
    time_source: &'static dyn time::Time<Frequency = A, Ticks = B>,
    accounted_energy: Cell<usize>,
    last_update_us: Cell<u32>,
    adc_state: Cell<u8>,
}

impl<A: 'static + time::Frequency,
     B: 'static + time::Ticks>
    SimultaneousAccounting<A, B>
{
    pub fn new(time_source: &'static dyn time::Time<Frequency = A, Ticks = B>) -> SimultaneousAccounting<A, B> {
        SimultaneousAccounting {
            time_source,
            accounted_energy: Cell::new(0),
            last_update_us: Cell::new(0),
            adc_state: Cell::new(0b0000_0000),
        }
    }

    fn update_accounting(&self) {
        let t_call = self.time_source.ticks_to_us(self.time_source.now());

        // Update accounted usage for the time since the previous update call.
        let d_prev_call = t_call - self.last_update_us.get();
        // TODO: update accounting state here.

        self.last_update_us.set(t_call);
    }
}

impl<A: 'static + time::Frequency,
     B: 'static + time::Ticks>
    DriverEnergyAccounting for SimultaneousAccounting<A, B> {
        fn on_command(&self, invocation: &Syscall, outcome: &SyscallReturn) {
            self.update_accounting();

            // Apply the state change signalled by the syscall.
            match invocation {
                Syscall::Command {
                    driver_number: driver_no,
                    subdriver_number: command_no,
                    arg0,
                    arg1
                } => {
                    match *driver_no {
                        capsules::channeled_adc::DRIVER_NUM => {
                            kernel::debug!("adc: ({}, {}, {}, {})",
                                           driver_no, command_no, arg0, arg1);
                            match command_no {
                                // Driver check, we do not care about this one.
                                0 => {  },

                                // Single ADC sample, continuous sampling request.
                                // The specified channel becomes active.
                                // It will become inactive once the upcall carrying the sample arrives.
                                1 | 2 => {
                                    let channel_no = arg0;
                                    let new_state = self.adc_state.get() | (1 << channel_no);
                                    self.adc_state.set(new_state);
                                },

                                _ => unimplemented!("unhandled command no. {} for ADC", command_no),
                            }
                        },

                        _ => {  } // Ignore all other drivers.
                    }
                },

                // Ignore all other syscalls.
                _ => {  }
            }
        }

        fn on_upcall(&self) {  }
}
