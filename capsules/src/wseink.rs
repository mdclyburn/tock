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
use kernel::utilities::cells::{
    OptionalCell,
    TakeCell,
};

use crate::virtual_alarm::VirtualMuxAlarm;

#[allow(non_upper_case_globals, unused)]
mod commands {
    pub const SoftwareReset: u8              = 0x12;
    pub const MasterActivation: u8           = 0x20;
    pub const DisplayUpdateControl2: u8      = 0x22;
    pub const WriteRAM: u8                   = 0x24;
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Operation {
    /// Wait for a number of milliseconds.
    Wait(usize),
    /// Wait for the busy pin to go low.
    Await,
    /// Perform a hardware reset.
    HardwareReset,
    /// Send a command (and maybe a number of data bytes) over SPI.
    Command(u8, usize),
    /// Send data over SPI.
    Data(usize),
}

pub struct WS2C250<A: 'static + Alarm<'static>> {
    spi: &'static dyn SpiMasterDevice,
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
    const SPI_CLOCK_MAX: usize = 25_000;

    pub fn new(
        spi: &'static dyn SpiMasterDevice,
        command_buffer: &'static mut [u8],
        data_buffer: &'static mut [u8],
        pin_reset: &'static dyn Pin,
        pin_dc: &'static dyn Pin,
        pin_busy: &'static dyn InterruptPin<'static>,
        alarm: &'static VirtualMuxAlarm<'static, A>,
    ) -> WS2C250<A>
    {
        WS2C250 {
            spi,
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

    const RESET_HOLD_DURATION_MS: usize = 50;

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
        self.enqueue(Operation::HardwareReset);
        self.enqueue(Operation::Command(commands::SoftwareReset, 0));
        self.enqueue(Operation::Wait(10));

        self.enqueue(Operation::Command(commands::DisplayUpdateControl2, 1));
        let _ = self.tx_data_buffer.map(|txb| {
            txb[0] = 0xF7;
        });
        self.enqueue(Operation::Command(commands::MasterActivation, 0));
        self.enqueue(Operation::Await);

        // Initialization code (commands 0x01, 0x11, 0x44, 0x45, 0x3c)

        // Load waveform LUT (commands 0x18, 0x22, 0x20).

        // Wait for the busy pin to go low.
        // self.enqueue(Operation::Await);

        // TEST
        // let _ = self.tx_data_buffer.map(|txb| {
        //     let it = ([1, 1, 1, 1, 0, 0, 0, 0]).iter()
        //         .cycle();
        //     for (dst_b, src_b) in txb.iter_mut().zip(it) {
        //         *dst_b = *src_b;
        //     }
        // }).unwrap();
        // self.enqueue(Operation::Command(commands::WriteRAM, 64));
        // self.enqueue(Operation::Await);

        self.process_queue();
    }

    fn enqueue(&self, operation: Operation) {
        let (h, t) = self.operation_queue_bounds.get();
        if (t + 1) % self.operation_queue.len() == h {
            panic!();
        } else {
            self.operation_queue[t].set(operation);

            let next_t = (t + 1) % self.operation_queue.len();
            self.operation_queue_bounds.set((h, next_t));
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

                Operation::Command(command, data_len) => {
                    kernel::debug!("eink: writing command {:02x}", *command);

                    // Set pin for writing command.
                    self.pin_dc.clear();

                    let tx_buffer = self.tx_command_buffer.take().unwrap();
                    tx_buffer[0] = *command;

                    if *data_len > 0 {
                        self.spi.hold_low();
                    } else {
                        self.spi.release_low();
                    }

                    self.spi.read_write_bytes(tx_buffer, None, 1).unwrap();
                },

                Operation::Data(len) => {
                    kernel::debug!("eink: writing data ({} bytes)", len);

                    // Set pin for writing data.
                    self.pin_dc.set();

                    let tx_buffer = self.tx_data_buffer.take().unwrap();
                    self.spi.release_low();
                    self.spi.read_write_bytes(tx_buffer, None, *len);
                }
            }
        });
    }
}

impl<A: 'static + Alarm<'static>> SpiMasterClient for WS2C250<A> {
    fn read_write_done(
        &self,
        tx_buffer: &'static mut [u8],
        rx_buffer: Option<&'static mut [u8]>,
        _len: usize,
        _status: Result<(), ErrorCode>)
    {
        kernel::debug!("eink: SPIRW done");
        if tx_buffer.len() == 1 {
            self.tx_command_buffer.put(Some(tx_buffer));
        } else {
            self.tx_data_buffer.put(Some(tx_buffer));
        }

        // If the current operation indicates that there is also data to write,
        // replace the current operation with a Data operation to also write the data.
        //
        // The call to process_queue() will continue on to the data write.
        let current_op = self.peek_operation().extract().unwrap();
        match current_op {
            Operation::Command(_cmd, data_len) => {
                kernel::debug!("eink: follow up with data write");
                self.peek_operation().set(Operation::Data(data_len));
            },

            Operation::Data(data_len) => {
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
