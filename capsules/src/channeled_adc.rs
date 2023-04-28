/*! ADC allowing separate access to channels.
 */

use kernel;
use kernel::grant::Grant;
use kernel::hil;
use kernel::process::ProcessId;
use kernel::processbuffer::{
    ReadableProcessBuffer,
    WriteableProcessBuffer,
    ReadWriteProcessBuffer,
};
use kernel::syscall::{CommandReturn, SyscallDriver};
use kernel::utilities::cells::{
    OptionalCell,
    TakeCell,
};
use kernel::errorcode::ErrorCode;

pub const DRIVER_NUM: usize = crate::driver::NUM::Adc as usize;

const MAX_CHANNEL_STATES: usize = 8;

mod grant_nos {
    pub const ALLOW_RW_SAMPLE_BUFFER_1: usize = 0;
    pub const ALLOW_RW_SAMPLE_BUFFER_2: usize = 1;

    pub const SUBSCRIBE_SAMPLING_COMPLETE: usize = 0;
}



#[derive(Clone, Copy, Debug)]
struct ChannelState {
    continuous: bool,
    client_pid: ProcessId,
}

pub struct AppData {
    sample_buffer_1: ReadWriteProcessBuffer,
    sample_buffer_2: ReadWriteProcessBuffer,
}

impl Default for AppData {
    fn default() -> AppData {
        AppData {
            sample_buffer_1: ReadWriteProcessBuffer::default(),
            sample_buffer_2: ReadWriteProcessBuffer::default(),
        }
    }
}

/// An ADC driver that allows multiple processes to access individual channels.
pub struct ChanneledADC<A: 'static + hil::adc::Adc + hil::adc::AdcHighSpeed> {
    adc: &'static A,
    grant_data: Grant<AppData, 1>,
    channels: &'static [A::Channel],
    channel_states: [OptionalCell<ChannelState>; MAX_CHANNEL_STATES],
    buffers: (TakeCell<'static, [u16]>,
              TakeCell<'static, [u16]>),
}

impl<A: 'static + hil::adc::Adc + hil::adc::AdcHighSpeed> ChanneledADC<A> {
    pub fn new(adc: &'static A,
               channels: &'static [A::Channel],
               grant_data: Grant<AppData, 1>,
               buffers: (&'static mut [u16],
                         &'static mut [u16])
    ) -> ChanneledADC<A>
    {
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
            buffers: (TakeCell::new(buffers.0),
                      TakeCell::new(buffers.1)),
        }
    }
}

impl<A: 'static + hil::adc::Adc + hil::adc::AdcHighSpeed> SyscallDriver for ChanneledADC<A> {
    fn allocate_grant(&self, pid: ProcessId) -> Result<(), kernel::process::Error> {
        self.grant_data.enter(pid, |_data, _upcall_table| {  })
    }

    fn command(&self,
               command_no: usize,
               r2: usize,
               r3: usize,
               pid: ProcessId) -> CommandReturn {
        // kernel::debug!("adc-cn: ({}, {}, {})", command_no, r2, r3);
        match (command_no, r2, r3) {
            // Capsule exists.
            // Return the no. of channels available.
            (0, _r2, _r3) => CommandReturn::success_u32(self.channels.len() as u32),

            // Single sample on a channel.
            (1, channel_no, _r3) => {
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
            (2, channel_no, frequency) => {
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
            },

            // Get resolution bits.
            (101, _r2, _r3) => {
                CommandReturn::success_u32(self.adc.get_resolution_bits() as u32)
            },

            // Get voltage reference mV.
            (102, _r2, _r3) => {
                self.adc.get_voltage_reference_mv()
                    .map(|mv| CommandReturn::success_u32(mv as u32))
                    .unwrap_or(CommandReturn::failure(ErrorCode::NOSUPPORT))
            },

            // Non-standard command no.
            // Stop sampling on a channel.
            (500, channel_no, _r3) => {
                if channel_no > self.channel_states.len() {
                    CommandReturn::failure(ErrorCode::INVAL)
                } else {
                    let opt_owner_pid: Option<ProcessId> = self.channel_states[channel_no]
                        .map(|s| s.client_pid);

                    // Check that the request came from the current owner,
                    // if the channel is currently in use.
                    if let Some(owner_pid) = opt_owner_pid {
                        if pid == owner_pid {
                            // Perform the cancellation.
                            self.channel_states[channel_no].clear();
                            match self.adc.stop_sampling_channel(channel_no) {
                                Ok(()) => {
                                    kernel::debug!("stopped sampling on {}", channel_no);
                                    CommandReturn::success()
                                },
                                Err(e) => CommandReturn::failure(e),
                            }
                        } else {
                            // Return the usual error, no difference from other error cases
                            // to prevent possibility of side-channels.
                            CommandReturn::failure(ErrorCode::INVAL)
                        }
                    } else {
                        CommandReturn::failure(ErrorCode::INVAL)
                    }
                }
            },

            // Start the experiment.
            (505, frequency, _r3) => {
                if let Some(buffer1) = self.buffers.0.take() {
                    if let Some(buffer2) = self.buffers.1.take() {
                        unsafe {
                            self.buffers.0.put(Some(core::slice::from_raw_parts_mut(buffer1.as_mut_ptr(), buffer1.len())));
                            self.buffers.1.put(Some(core::slice::from_raw_parts_mut(buffer2.as_mut_ptr(), buffer2.len())));
                        }

                        match self.adc.sample_highspeed(
                            &self.channels[0],
                            frequency as u32,
                            buffer1,
                            buffer1.len(),
                            buffer2,
                            buffer2.len())
                        {
                            Ok(()) => {
                                self.channel_states[0].set(ChannelState {
                                    continuous: false,
                                    client_pid: pid,
                                });
                                CommandReturn::success()
                            },
                            Err((rc, _buffer1, _buffer2)) => {
                                kernel::debug!("failed to start ADC experiment: {:?}", rc);
                                CommandReturn::failure(rc)
                            },
                        }
                    } else {
                        CommandReturn::failure(ErrorCode::BUSY)
                    }
                } else {
                    CommandReturn::failure(ErrorCode::BUSY)
                }
            },

            _ => CommandReturn::failure(ErrorCode::INVAL),
        }
    }

    fn allow_readwrite(
        &self,
        pid: ProcessId,
        allow_no: usize,
        mut buffer: ReadWriteProcessBuffer
    ) -> Result<ReadWriteProcessBuffer, (ReadWriteProcessBuffer, ErrorCode)> {
        let res = match allow_no {
            grant_nos::ALLOW_RW_SAMPLE_BUFFER_1 =>
                self.grant_data.enter(pid, |grant_data, _upcall_table| {
                    core::mem::swap(&mut buffer, &mut grant_data.sample_buffer_1);
                }).map_err(|_k_err| ErrorCode::FAIL),

            grant_nos::ALLOW_RW_SAMPLE_BUFFER_2 =>
                self.grant_data.enter(pid, |grant_data, _upcall_table| {
                    core::mem::swap(&mut buffer, &mut grant_data.sample_buffer_2);
                }).map_err(|_k_err| ErrorCode::FAIL),

            _ => Err(ErrorCode::INVAL),
        };

        match res {
            Ok(()) => Ok(buffer),
            Err(err) => Err((buffer, err)),
        }
    }
}

impl<A: 'static + hil::adc::Adc + hil::adc::AdcHighSpeed> hil::adc::Client for ChanneledADC<A> {
    fn sample_ready(&self, sample_data: u16) {
        // kernel::debug!("adc-cn: got sample ready");
        // We expect that the underlying ADC hardware will not use more than 12 bits.
        // The bottom half of the ADC driver will stuff the top four bits with the channel no.
        // If that means sacrificing resolution, that is okay.
        let channel_no = sample_data >> 12;
        let sample = sample_data & 0b0000_1111_1111_1111;
        let free_channel = self.channel_states[channel_no as usize].map(|cs| {
            // Schedule the upcall.
            // kernel::debug!("adc-cn: scheduling upcall for channel {}", channel_no);
            // The scheduling could fail if the sampling is too quick and there are too many samples queued up.
            // We just silently drop excess sample results.
            let _upcall_schedule_result = self.grant_data.enter(
                cs.client_pid,
                |_data, upcall_table| {
                    let sampling_type_indicator = if cs.continuous { 1 } else { 0 };
                    let upcall_args = (sampling_type_indicator, channel_no as usize, sample as usize);
                    // kernel::debug!("scheduling: ({}, {}, {})",
                    //                sampling_type_indicator,
                    //                channel_no,
                    //                sample);
                    upcall_table.schedule_upcall(0, upcall_args)
                })
                .expect("could not enter ADC grant");

            // Free the channel if it is for a single sample.
            cs.continuous == false
        }).expect("channel should have state, but does not");

        // Free up the channel for use by other applications if necessary.
        if free_channel {
            self.channel_states[channel_no as usize].clear();
        }
    }
}
