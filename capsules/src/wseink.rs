/** WaveShare eInk 2.13-in. display, v4.
 */

use core::cell::Cell;

use kernel::collections::ring_buffer::RingBuffer;
use kernel::errorcode::ErrorCode;
use kernel::hil::time::{
    Alarm,
    AlarmClient,
    ConvertTicks,
    Time
};
use kernel::hil::gpio::{Input, Output, Pin};
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
}

#[derive(Clone, Copy, Debug)]
enum Operation {
    /// Wait for a number of milliseconds.
    Wait(usize),
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
    pin_busy: &'static dyn Pin,

    alarm: &'static VirtualMuxAlarm<'static, A>,

    operation_queue: [OptionalCell<Operation>; 5],
    operation_queue_bounds: Cell<(usize, usize)>,
}

impl<A: 'static + Alarm<'static>> WS2C250<A> {
    const SPI_CLOCK_MAX: usize = 2_500_000;

    pub fn new(
        spi: &'static dyn SpiMasterDevice,
        command_buffer: &'static mut [u8],
        data_buffer: &'static mut [u8],
        pin_reset: &'static dyn Pin,
        pin_dc: &'static dyn Pin,
        pin_busy: &'static dyn Pin,
        alarm: &'static VirtualMuxAlarm<'static, A>,
    ) -> WS2C250<A>
    {
        let _ = pin_reset.make_output();
        let _ = pin_dc.make_output();
        let _ = pin_busy.make_input();

        pin_reset.set();
        pin_dc.clear();

        let r = spi.configure(spi::ClockPolarity::IdleLow,
                              spi::ClockPhase::SampleLeading,
                              Self::SPI_CLOCK_MAX as u32);
        if let Result::Err(e) = r {
            kernel::debug!("eink: spi configure failed ({})",
                           e as usize);
        }

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
            ],
            operation_queue_bounds: Cell::new((0, 0)),
        }
    }

    const RESET_HOLD_DURATION_MS: usize = 50;

    pub fn startup(&'static self) {
        self.spi.set_client(self);
        self.alarm.set_alarm_client(self);

        self.enqueue(Operation::HardwareReset);
        self.enqueue(Operation::Command(commands::SoftwareReset, 0));
        self.enqueue(Operation::Wait(10));

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

    fn peek_operation(&self) -> &OptionalCell<Operation> {
        let (h, _t) = self.operation_queue_bounds.get();
        &self.operation_queue[h]
    }

    fn process_queue(&self) {
        self.peek_operation().map(|next_op| {
            match next_op {
                Operation::Wait(duration_ms) => {
                    kernel::debug!("eink: waiting {} ms", duration_ms);
                    self.alarm.set_alarm(self.alarm.now(),
                                         self.alarm.ticks_from_ms(*duration_ms as u32));
                },

                Operation::HardwareReset => {
                    kernel::debug!("eink: initiating HW reset");
                    self.pin_reset.clear();
                    self.alarm.set_alarm(self.alarm.now(),
                                         self.alarm.ticks_from_ms(Self::RESET_HOLD_DURATION_MS as u32));
                },

                Operation::Command(command, data_len) => {
                    kernel::debug!("eink: writing command {:040X}", *command);

                    // Set pin for writing command.
                    self.pin_dc.clear();

                    let tx_buffer = self.tx_command_buffer.take().unwrap();
                    tx_buffer[0] = *command;

                    self.spi.read_write_bytes(tx_buffer, None, 1);
                },

                Operation::Data(len) => {
                    kernel::debug!("eink: writing data ({} bytes)", len);

                    // Set pin for writing data.
                    self.pin_dc.set();

                    let tx_buffer = self.tx_data_buffer.take().unwrap();
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
        len: usize,
        status: Result<(), ErrorCode>)
    {
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
        if let Operation::Command(_cmd, data_len) = current_op {
            self.peek_operation().set(Operation::Data(data_len));
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
