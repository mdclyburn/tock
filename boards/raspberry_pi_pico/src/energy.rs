/*! Energy accounting for the Raspberry Pi Pico.
 */

use core::cell::Cell;

use kernel;
use kernel::energy::DriverEnergyAccounting;
use kernel::hil::time;
use kernel::hil::time::ConvertTicks as _;
use kernel::process::{
    FunctionCall,
    FunctionCallSource,
};
use kernel::syscall::{
    Syscall,
    SyscallReturn,
};
use kernel::utilities::cells::MapCell;

use capsules;

/** Energy usage patterns for components.

Each component can be in an inactive or active state.
An inactive state is represented by Inactive.
Active states correspond with the other variants of the enum.

One-shot operations use the Pending and OneShot variants.
Upon invocation, the accounting system considers their usage pending
and only accounts the completed usage total once the operation successfully completes
as indicated by the underlying hardware and resulting upcall.

Operations that consume an amount of energy correlated with the length of time of their usage use the Long variant.
This variant is set on the component with the success of the syscall that activates them.

The numerical values in the active enum variants are energy values measured in microjoules and microjoules per millisecond.
 */
#[derive(Copy, Clone, Debug, PartialEq)]
enum Usage {
    Inactive,
    Pending(usize),
    OneShot(usize),
    Long(usize),
}

pub struct SimultaneousAccounting<A: 'static + time::Frequency,
                                  B: 'static + time::Ticks>
{
    time_source: &'static dyn time::Time<Frequency = A, Ticks = B>,
    /// Total energy accounted in microjoules.
    accounted_energy: Cell<u64>,
    last_update_us: Cell<usize>, // WARNING: this will overflow in a reasonable amount of time.
    adc_state: MapCell<[Usage; 5]>,
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
            adc_state: MapCell::new([Usage::Inactive; 5]),
        }
    }

    /// Updated accounted energy total.
    ///
    /// Go through all active usages and count their usage toward the accounted total.
    /// Usages in the pending state do not count toward this total.
    /// Once they move to the [`Usage::OneShot`] state, this function will count the usage
    /// and move the usage to the [`Usage::Inactive`] state.
    fn update_accounting(&self) {
        let t_call_us: usize = self.time_source.ticks_to_us(self.time_source.now()) as usize;

        // Update accounted usage for the time since the previous update call.
        let d_prev_call_us: usize = t_call_us - self.last_update_us.get();

        // Look through all tracked state and accumulate usages.
        let mut acc: usize = 0;
        acc += self.adc_state.map(|adc_state| {
            let mut acc = 0;
            for channel_state in adc_state.iter() {
                match channel_state {
                    Usage::Inactive => {  },

                    // Usage is still pending, so we are not ready to count this usage.
                    Usage::Pending(_usage) => {  },

                    // One-shot operation completed.
                    // Count its usage.
                    Usage::OneShot(usage) => acc += *usage,

                    // Long-term operation continues.
                    // Use how much time has passed to calculate its contribution.
                    Usage::Long(usage_rate) => acc += (*usage_rate * d_prev_call_us),
                };
            }

            acc
        }).unwrap();

        self.accounted_energy.set(self.accounted_energy.get() + acc as u64);
        self.last_update_us.set(t_call_us);
    }
}

impl<A: 'static + time::Frequency,
     B: 'static + time::Ticks>
    DriverEnergyAccounting for SimultaneousAccounting<A, B>
{
    fn on_command(&self, invocation: &Syscall, outcome: &SyscallReturn) {
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
                        /* The upcall was for an ADC sample.

                        For one-shot samples, mark it complete such that the next time we update,
                        we will consider this energy used and add it to the accumulated total.
                        This will be safe to push off because if an application wants to use the channel,
                        we will do the update before marking the channel as in-use.

                         */
                        // kernel::debug!("adc call: ({}, {}, {}, {})",
                        //                driver_no, command_no, arg0, arg1);
                        match command_no {
                            // Driver check, we do not care about this one.
                            0 => {  },

                            // Single ADC sample.
                            // The specified channel becomes active.
                            // It will become inactive once the upcall carrying the sample arrives.
                            1 => {
                                let channel_no = arg0;
                                self.adc_state.map(|s| { s[*channel_no] = Usage::Pending(3654) });
                            },

                            2 => {
                                let channel_no = arg0;
                                self.adc_state.map(|s| { s[*channel_no] = Usage::Long(14) });
                            },

                            // Stopping sampling on a channel.
                            // The specified channel becomes inactive.
                            // This is just a change in the state of the ADC peripheral.
                            // Note: this had better be a long-running sampling operation.
                            500 => {
                                let channel_no = arg0;
                                let current_state = self.adc_state.map(|s| s[*channel_no] )
                                    .unwrap(); // ADC state should never be empty.
                                match current_state {
                                    // The channel was inactive, yet we got a cancellation request for some reason.
                                    // This is not a problem here, so do not fault the system.
                                    // However, there is no action to take.
                                    Usage::Inactive => {  },

                                    // We do not support accounting cancellation of one-shot sampling operations.
                                    // The usage for it will be accounted on completion of the operation, still.
                                    // So, this is not part of evaluation.
                                    Usage::OneShot(_usage) => panic!("cancelling short sampling operation unsupported"),

                                    // Stopping a long-running sampling operation.
                                    // We should perform accounting up to this point and then mark this channel as inactive.
                                    Usage::Long(_rate) => {
                                        self.update_accounting();
                                        self.adc_state.map(|s| { s[*channel_no] = Usage::Inactive });
                                    },

                                    // Usage is in a pending state, yet a cancellation request came through.
                                    // The channel is not active for us anyway, so ignore it.
                                    Usage::Pending(_usage) => {  },
                                };
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

    fn on_upcall(&self, call: &FunctionCall) {
        let need_update = match call.source {
            FunctionCallSource::Driver(upcall_info) => {
                match upcall_info.driver_num {
                    capsules::channeled_adc::DRIVER_NUM => {
                        // We take a peek into the arguments since the driver uses the same callback.
                        let (_sampling_type_no, channel_no) = (
                            call.argument0,
                            call.argument1);
                        // kernel::debug!("adc upcall: {} ({}, {}, {}, {})",
                        //                upcall_info.subscribe_num,
                        //                call.argument0,
                        //                call.argument1,
                        //                call.argument2,
                        //                call.argument3);

                        // Mark the channel as one-shot if this was a pending usage.
                        // The next update will count it toward the total and mark the channel as inactive.
                        self.adc_state.map(|s| {
                            let channel_usage = &mut s[channel_no];
                            if let Usage::Pending(usage) = channel_usage {
                                *channel_usage = Usage::OneShot(*usage);
                            }
                        });

                        true
                    },

                    // Ignore all other drivers making upcalls.
                    _ => { false }
                }
            },

            // Ignore other sources not related to drivers.
            _ => { false }
        };

        // We should update energy accounting data if usage state has changed
        // as a result of a callback.
        if need_update {
            self.update_accounting();
        }
    }

    fn total_accounted(&self) -> u64 {
        self.accounted_energy.get()
    }
}
