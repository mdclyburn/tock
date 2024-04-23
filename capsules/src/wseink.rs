/** WaveShare eInk 2.13-in. display, v4.
 */

use core::cell::Cell;

use kernel::collections::ring_buffer::RingBuffer;
use kernel::errorcode::ErrorCode;
use kernel::hil::gpio::{
    self,
    Interrupt,
    InterruptPin,
    Pin,
};
use kernel::hil::time::{
    Alarm,
    AlarmClient,
    ConvertTicks,
    Time
};
use kernel::hil::spi::{
    self,
    SpiMasterClient,
    SpiMasterDevice
};
use kernel::process::ProcessId;
use kernel::syscall::{CommandReturn, SyscallDriver};
use kernel::utilities::cells::{
    OptionalCell,
    TakeCell,
};

use crate::virtual_alarm::VirtualMuxAlarm;

type Result<T> = core::result::Result<T, ErrorCode>;

pub const DRIVER_NUM: usize = crate::driver::NUM::Screen as usize;

#[allow(non_upper_case_globals, unused)]
mod commands {
    pub const DeepSleepMode: u8              = 0x10;
    pub const SoftwareReset: u8              = 0x12;
    pub const MasterActivation: u8           = 0x20;
    pub const DisplayUpdateControl2: u8      = 0x22;
    pub const WriteRAM: u8                   = 0x24;
}

#[derive(Clone, Copy, Debug)]
enum Data {
    Copy(&'static [u8]),
    Buffer(usize),
    DisplayBuffer,
}

#[derive(Clone, Copy, Debug)]
enum Operation {
    /// Wait for a number of milliseconds.
    Wait(usize),
    /// Wait for the busy pin to go low.
    Await,
    /// Perform a hardware reset.
    HardwareReset,
    /// Send a command (and maybe a number of data bytes) over SPI.
    Command(u8, Option<Data>),
    /// Send data over SPI.
    Data(Data),
}

/// Display refresh method.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Refresh {
    /// Full, slower refresh.
    Full,
    /// Full, fast refresh.
    Fast,
    /// Partial, fast refresh.
    Partial,
}

/// Number of bytes necessary for the 250 x 122 display buffer.
pub const DISPLAY_BUFFER_LEN: usize = 32 * 16;

pub struct WS2C250<A: 'static + Alarm<'static>> {
    spi: &'static dyn SpiMasterDevice,

    display_buffer: TakeCell<'static, [u8]>,
    tx_command_buffer: TakeCell<'static, [u8]>,
    tx_data_buffer: TakeCell<'static, [u8]>,

    pin_reset: &'static dyn Pin,
    pin_dc: &'static dyn Pin,
    pin_busy: &'static dyn InterruptPin<'static>,

    alarm: &'static VirtualMuxAlarm<'static, A>,

    operation_queue: [OptionalCell<Operation>; 10],
    operation_queue_bounds: Cell<(usize, usize)>,
}

impl<A: 'static + Alarm<'static>> WS2C250<A> {
    const RESET_HOLD_DURATION_MS: usize = 1;
    const SPI_CLOCK_MAX: usize = 25_000;

    pub fn new(
        spi: &'static dyn SpiMasterDevice,
        display_buffer: &'static mut [u8],
        command_buffer: &'static mut [u8],
        data_buffer: &'static mut [u8],
        pin_reset: &'static dyn Pin,
        pin_dc: &'static dyn Pin,
        pin_busy: &'static dyn InterruptPin<'static>,
        alarm: &'static VirtualMuxAlarm<'static, A>,
    ) -> WS2C250<A>
    {
        for b in display_buffer.iter_mut() {
            *b = 0xFF;
        }

        WS2C250 {
            spi,
            display_buffer: TakeCell::new(display_buffer),
            tx_command_buffer: TakeCell::new(command_buffer),
            tx_data_buffer: TakeCell::new(data_buffer),
            pin_reset,
            pin_dc,
            pin_busy,
            alarm,
            operation_queue: [
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
            ],
            operation_queue_bounds: Cell::new((0, 0)),
        }
    }

    pub fn startup(&'static self) {
        let _ = self.pin_reset.make_output();
        self.pin_reset.set();

        let _ = self.pin_dc.make_output();
        self.pin_dc.clear();

        let _ = self.pin_busy.make_input();

        let r = self.spi.configure(spi::ClockPolarity::IdleLow,
                              spi::ClockPhase::SampleLeading,
                              Self::SPI_CLOCK_MAX as u32);
        if let Result::Err(e) = r {
            kernel::debug!("eink: spi configure failed ({})",
                           e as usize);
        }
        self.spi.set_client(self);

        self.alarm.set_alarm_client(self);

        self.pin_busy.set_client(self);
        self.pin_busy.enable_interrupts(gpio::InterruptEdge::EitherEdge);

        // Initial configuration.
        self.hardware_reset().unwrap();

        // Blank the screen.
        self.refresh(Refresh::Full).unwrap();

        // Initialization code (commands 0x01, 0x11, 0x44, 0x45, 0x3c)

        // Load waveform LUT (commands 0x18, 0x22, 0x20).
    }

    fn enqueue(&self, operations: &[Operation]) -> Result<()> {
        let (h, t) = self.operation_queue_bounds.get();
        let free_slots = if h == t {
            self.operation_queue.len()
        } else if h <= t {
            h + (self.operation_queue.len() - t - 1)
        } else {
            h - t - 1
        };

        if free_slots < operations.len() {
            Err(ErrorCode::NOMEM)
        } else {
            let it = self.operation_queue.iter().zip(operations.iter());
            for (dst_optc_op, src_op) in it {
                dst_optc_op.set(*src_op);
            }

            let next_t = (t + operations.len()) % self.operation_queue.len();
            self.operation_queue_bounds.set((h, next_t));

            // Start the queue if the queue was otherwise empty.
            if free_slots == self.operation_queue.len() {
                self.process_queue();
            }

            Ok(())
        }
    }

    fn dequeue(&self) -> Option<Operation> {
        let (h, t) = self.operation_queue_bounds.get();
        if h == t {
            None
        } else {
            // This should never result in a None.
            // If it does, the circular buffer head- and tail-tracking logic is wrong.
            let op = self.operation_queue[h].take();

            let next_h = (h + 1) % self.operation_queue.len();
            self.operation_queue_bounds.set((next_h, t));

            op
        }
    }

    fn dequeue_discard(&self) {
        let _operation = self.dequeue();
    }

    fn peek_operation(&self) -> &OptionalCell<Operation> {
        let (h, _t) = self.operation_queue_bounds.get();
        &self.operation_queue[h]
    }

    fn process_queue(&self) {
        self.peek_operation().map(|next_op| {
            // kernel::debug!("Next operation: {:?}", next_op);
            match next_op {
                Operation::Wait(duration_ms) => {
                    kernel::debug!("eink: waiting {} ms", duration_ms);
                    self.alarm.set_alarm(self.alarm.now(),
                                         self.alarm.ticks_from_ms(*duration_ms as u32));
                },

                Operation::Await => {
                    // No need to wait if the pin is already low.
                    if self.pin_busy.read() == false {
                        kernel::debug!("eink: no await, BUSY not set");
                        self.dequeue_discard();
                    } else {
                        kernel::debug!("eink: awaiting low BUSY pin");
                    }
                },

                Operation::HardwareReset => {
                    kernel::debug!("eink: initiating HW reset");
                    self.pin_reset.clear();
                    self.alarm.set_alarm(self.alarm.now(),
                                         self.alarm.ticks_from_ms(Self::RESET_HOLD_DURATION_MS as u32));
                },

                Operation::Command(command, opt_data) => {
                    kernel::debug!("eink: writing command {:02x}", *command);

                    // Set pin for writing command.
                    self.pin_dc.clear();

                    let tx_buffer = self.tx_command_buffer.take().unwrap();
                    tx_buffer[0] = *command;

                    if opt_data.is_some() {
                        self.spi.hold_low();
                    } else {
                        self.spi.release_low();
                    }

                    self.spi.read_write_bytes(tx_buffer, None, 1).unwrap();
                },

                Operation::Data(data) => {
                    kernel::debug!("eink: writing data");

                    // Set pin for writing data.
                    self.pin_dc.set();

                    let mut tx_len = 0;
                    let tx_buffer = match data {
                        // No work to do; the data is already in the buffer.
                        Data::Buffer(data_len) => {
                            tx_len = *data_len;
                            self.tx_data_buffer.take().unwrap()
                        },

                        Data::Copy(buf)  => {
                            let tx_buffer = self.tx_data_buffer.take().unwrap();
                            tx_len = buf.len();
                            let it = buf.iter().zip(tx_buffer.iter_mut());
                            for (srcb, dstb) in it {
                                *dstb = *srcb;
                            }

                            tx_buffer
                        },

                        Data::DisplayBuffer => {
                            let tx_buffer = self.display_buffer.take().unwrap();
                            tx_len = tx_buffer.len();

                            tx_buffer
                        },
                    };

                    self.spi.release_low();
                    self.spi.read_write_bytes(tx_buffer, None, tx_len);
                }
            }
        });
    }

    pub fn hardware_reset(&self) -> Result<()> {
        self.enqueue(&[Operation::HardwareReset,
                       Operation::Await])
    }

    pub fn turn_off(&self) -> Result<()> {
        self.enqueue(&[Operation::Command(commands::DeepSleepMode, Some(Data::Copy(&[0b0000_0001])))])
    }

    pub fn refresh(&self, refresh_type: Refresh) -> Result<()> {
        let update_sequence_option = match refresh_type {
            Refresh::Full => 0xF7,
            Refresh::Fast => 0xC7,
            Refresh::Partial => 0xFF,
        };

        self.enqueue(&[Operation::HardwareReset,
                       Operation::Await,

                       Operation::Command(commands::DisplayUpdateControl2, Some(Data::Copy(&[0xF7]))),
                       Operation::Command(commands::MasterActivation, None),
                       Operation::Await])
    }

    /// Draw something to the display.
    pub fn bah(&self) -> Result<()> {
        self.display_buffer.map_or(Err(ErrorCode::BUSY), |dbuf| {
            let opt_bw_p8 = dbuf.iter_mut()
                .skip(500)
                .skip_while(|p8| **p8 != 0)
                .next();

            if let Some(bw_p8) = opt_bw_p8 {
                *bw_p8 = 0;
            }

            Ok(())
        })
    }
}

impl<A: 'static + Alarm<'static>> SpiMasterClient for WS2C250<A> {
    fn read_write_done(
        &self,
        tx_buffer: &'static mut [u8],
        rx_buffer: Option<&'static mut [u8]>,
        _len: usize,
        _status: Result<()>)
    {
        kernel::debug!("eink: SPIRW done");

        let current_op = self.peek_operation().extract().unwrap();

        match current_op {
            Operation::Command(_command, _opt_data) => self.tx_command_buffer.put(Some(tx_buffer)),

            Operation::Data(data) => match data {
                Data::Buffer(_len) => self.tx_data_buffer.put(Some(tx_buffer)),
                Data::Copy(_src) => self.tx_data_buffer.put(Some(tx_buffer)),
                Data::DisplayBuffer => self.display_buffer.put(Some(tx_buffer)),
            },

            _ => panic!(), // Cannot figure out how to put the buffer back.
        };

        // If the current operation indicates that there is also data to write,
        // replace the current operation with a Data operation to also write the data.
        //
        // The call to process_queue() will continue on to the data write.
        match current_op {
            Operation::Command(_cmd, opt_data) => {
                if let Some(data) = opt_data {
                    kernel::debug!("eink: follow up with data write");
                    self.peek_operation().set(Operation::Data(data));
                } else {
                    kernel::debug!("eink: command-only write complete");
                    self.dequeue_discard();
                }
            },

            Operation::Data(_data) => {
                kernel::debug!("eink: data write complete");
                self.dequeue_discard();
            },

            _ => panic!(),
        }

        self.process_queue();
    }
}

impl <A: 'static + Alarm<'static>> AlarmClient for WS2C250<A> {
    fn alarm(&self) {
        // If this panics, it means that the alarm fired for us,
        // but we didn't have a respective queue item for it.
        let current_op = self.dequeue().unwrap();
        match current_op {
            Operation::HardwareReset => {
                self.pin_reset.set();
                kernel::debug!("eink: hw reset done");
            },

            Operation::Wait(ms) => kernel::debug!("eink: {} ms wait done", ms),

            _ => panic!(),
        };

        self.process_queue();
    }
}

impl <A: 'static + Alarm<'static>> gpio::Client for WS2C250<A> {
    fn fired(&self) {
        // BUSY pin changed state.
        if self.pin_busy.read() == true {
            kernel::debug!("eink: busy");
        } else {
            let peeked_op = self.peek_operation().extract();
            match peeked_op {
                // The display went busy when we supposedly were not waiting?
                None => kernel::debug!("eink: idle; was busy while driver idle"),

                // The display was busy, and we were waiting on it; the expected case.
                Some(Operation::Await) => {
                    kernel::debug!("eink: idle");
                    self.dequeue_discard();
                },

                // The display was busy, but we were not waiting on it? Bad.
                Some(op) => {
                    kernel::debug!("eink: idle; was busy while driver active!");
                }
            }
        }
    }
}

impl <A: 'static + Alarm<'static>> SyscallDriver for WS2C250<A> {
    fn allocate_grant(&self, pid: ProcessId) -> core::result::Result<(), kernel::process::Error> { Ok(()) }

    fn command(&self,
               command_no: usize,
               arg2: usize,
               arg3: usize,
               pid: ProcessId) -> CommandReturn
    {
        match (command_no, arg2, arg3) {
            // Driver check
            (0, _r2, _r3) => CommandReturn::success(),

            // Hardware reset
            (1, _r2, _r3) => {
                match self.hardware_reset() {
                    Ok(()) => CommandReturn::success(),
                    Err(e) => CommandReturn::failure(e),
                }
            },

            // Refresh
            (2, refresh_type, _r3) => {
                let refresh_type: Option<Refresh> = match refresh_type {
                    0 => Some(Refresh::Full),
                    1 => Some(Refresh::Fast),
                    2 => Some(Refresh::Partial),
                    _ => None,
                };

                if let Some(refresh_type) = refresh_type {
                    match self.refresh(refresh_type) {
                        Ok(()) => CommandReturn::success(),
                        Err(e) => CommandReturn::failure(e),
                    }
                } else {
                    return CommandReturn::failure(ErrorCode::INVAL);
                }
            },

            // Bah
            (3, _r2, _r3) => {
                match self.bah() {
                    Ok(()) => CommandReturn::success(),
                    Err(e) => CommandReturn::failure(e),
                }
            },

            (_command_no, _r2, _r3) => CommandReturn::failure(ErrorCode::INVAL),
        }
    }
}
