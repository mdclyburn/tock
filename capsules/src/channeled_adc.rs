/*! ADC allowing separate access to channels.
 */

use kernel::grant::Grant;
use kernel::hil;
use kernel::process::ProcessId;
use kernel::syscall::{CommandReturn, SyscallDriver};
use kernel::utilities::cells::OptionalCell;
use kernel::errorcode::ErrorCode;

pub const DRIVER_NUM: usize = crate::driver::NUM::Adc as usize;

const MAX_CHANNEL_STATES: usize = 8;

#[derive(Clone, Copy, Debug)]
struct ChannelState {
    continuous: bool,
    client_pid: ProcessId,
}

pub struct ChanneledADC<A: 'static + hil::adc::Adc> {
    adc: &'static A,
    grant_data: Grant<(), 1>,
    channels: &'static [A::Channel],
    channel_states: [OptionalCell<ChannelState>; MAX_CHANNEL_STATES],
}

impl<A: 'static + hil::adc::Adc> ChanneledADC<A> {
    pub fn new(adc: &'static A,
               channels: &'static [A::Channel],
               grant_data: Grant<(), 1>) -> ChanneledADC<A> {
        ChanneledADC {
            adc,
            grant_data,
            channels,
            channel_states: [
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
            ],
        }
    }
}

impl<A: 'static + hil::adc::Adc> SyscallDriver for ChanneledADC<A> {
    fn command(&self,
               command_no: usize,
               r2: usize,
               r3: usize,
               pid: ProcessId) -> CommandReturn {
        match command_no {
            // Capsule exists.
            // Return the no. of channels available.
            0 => CommandReturn::success_u32(self.channels.len() as u32),

            // Single sample on a channel.
            1 => {
                let (channel_no, _r3) = (r2, r3);

                if self.channel_states[channel_no].is_some() {
                    CommandReturn::failure(ErrorCode::BUSY)
                } else {
                    match self.adc.sample(&self.channels[channel_no]) {
                        Ok(()) => {
                            self.channel_states[channel_no].set(ChannelState {
                                continuous: false,
                                client_pid: pid,
                            });
                            CommandReturn::success()
                        },

                        Err(e) => CommandReturn::failure(e),
                    }
                }
            },

            // Continous sampling on a channel.
            2 => {
                let (channel_no, frequency) = (r2, r3);

                if self.channel_states[channel_no].is_some() {
                    CommandReturn::failure(ErrorCode::BUSY)
                } else {
                    match self.adc.sample_continuous(&self.channels[channel_no], frequency as u32) {
                        Ok(()) => {
                            self.channel_states[channel_no].set(ChannelState {
                                continuous: true,
                                client_pid: pid,
                            });
                            CommandReturn::success()
                        },

                        Err(e) => CommandReturn::failure(e),
                    }
                }
            }

            // Get resolution bits.
            101 => {
                CommandReturn::success_u32(self.adc.get_resolution_bits() as u32)
            },

            // Get voltage reference mV.
            102 => {
                self.adc.get_voltage_reference_mv()
                    .map(|mv| CommandReturn::success_u32(mv as u32))
                    .unwrap_or(CommandReturn::failure(ErrorCode::NOSUPPORT))
            },

            _ => CommandReturn::failure(ErrorCode::INVAL),
        }
    }

    fn allocate_grant(&self, pid: ProcessId) -> Result<(), kernel::process::Error> {
        self.grant_data.enter(pid, |_data, _upcall_table| {  })
    }
}

impl<A: 'static + hil::adc::Adc> hil::adc::Client for ChanneledADC<A> {
    fn sample_ready(&self, sample_data: u16) {
        // We expect that the underlying ADC hardware will not use more than 12 bits.
        // The bottom half of the ADC driver will stuff the top four bits with the channel no.
        // If that means sacrificing resolution, that is okay.
        let channel_no = sample_data >> 12;
        let sample = sample_data & 0b0000_1111_1111_1111;
        let free_channel = self.channel_states[channel_no as usize].map(|cs| {
            // Schedule the upcall.
            let result = self.grant_data.enter(
                cs.client_pid,
                |_data, upcall_table| {
                    let upcall_args = (0usize, channel_no as usize, sample as usize);
                    upcall_table.schedule_upcall(0, upcall_args)
                })
                .expect("could not enter ADC grant")
                .expect("could not schedule upcall");

            // Free the channel if it is for a single sample.
            cs.continuous == false
        });
    }
}
