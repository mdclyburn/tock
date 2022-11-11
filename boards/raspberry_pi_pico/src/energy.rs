/*! Energy accounting for the Raspberry Pi Pico.
 */

use kernel::energy::DriverEnergyAccounting;
use kernel::hil::time;
use kernel::hil::time::ConvertTicks as _;

use capsules;

#[derive(Debug)]
struct Component {
    command_no: usize,
    args: (usize, usize),
    t_start: usize,
}

/// Peripheral usage by time.
#[derive(Debug)]
struct Usage {
    command_no: usize,
    args: (usize, usize),
    start: usize,
}

pub struct SimultaneousAccounting<A: 'static + time::Frequency,
                                  B: 'static + time::Ticks>
{
    time_source: &'static dyn time::Time<Frequency = A, Ticks = B>,
}

impl<A: 'static + time::Frequency,
     B: 'static + time::Ticks>
    SimultaneousAccounting<A, B>
{
    pub fn new(time_source: &'static dyn time::Time<Frequency = A, Ticks = B>) -> SimultaneousAccounting<A, B> {
        SimultaneousAccounting {
            time_source,
        }
    }
}

impl<A: 'static + time::Frequency,
     B: 'static + time::Ticks>
    DriverEnergyAccounting for SimultaneousAccounting<A, B> {
    fn update(&self, driver_no: usize, command_no: usize, arg0: usize, arg1: usize) {
        let t_call = self.time_source.ticks_to_us(self.time_source.now());

        match driver_no {
            capsules::channeled_adc::DRIVER_NUM => {
                kernel::debug!("accounting: ({}, {}, {}, {})",
                               driver_no,
                               command_no,
                               arg0,
                               arg1);

                // Get current active usages.

                match command_no {
                    // Driver check, we do not care about this one.
                    0 => {  },

                    // Single ADC sample.
                    1 => {

                    }

                    _ => unimplemented!("unhandled command no. {} for ADC", command_no),
                }
            },

            _ => {  } // Ignore all other calls.
        }
    }
}
