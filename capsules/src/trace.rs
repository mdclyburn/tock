use kernel::{Driver, ReturnCode};
use kernel::common::cells::TakeCell;
use kernel::hil::trace::Trace;
use kernel::hil::gpio::InterruptPin;
use kernel::hil::uart;
use kernel::hil::uart::{
    Uart,
    Parameters as UartParameters,
    TransmitClient,
};

use crate::driver;
use crate::gpio::GPIO;

pub const DRIVER_NUM: usize = driver::NUM::Trace as usize;

pub struct ParallelGPIOTrace<'a, IP: InterruptPin<'a>> {
    gpio: &'a GPIO<'a, IP>,
    pin_nos: &'a [u8],
    id_len: u8,
}

impl<'a, IP: InterruptPin<'a>> ParallelGPIOTrace<'a, IP> {
    pub fn new(gpio: &'a GPIO<'a, IP>,
               pin_nos: &'a [u8],
               id_len: u8)
               -> ParallelGPIOTrace<'a, IP>
    {
        use kernel::hil::gpio::GPIO;
        for pin_no in pin_nos {
            gpio.enable_output(*pin_no as usize);
            gpio.clear(*pin_no as usize);
        }

        ParallelGPIOTrace {
            gpio,
            pin_nos,
            id_len,
        }
    }
}

impl<'a, IP: InterruptPin<'a>> Trace for ParallelGPIOTrace<'a, IP> {
    fn signal(&self, data: &[u8], len: usize) {
        if len == 0 {
            return;
        }

        use kernel::hil::gpio::GPIO;
        let out: u16 =
            (data[0] as u16)
            | if len > 1 { data[1] as u16 } else { 0u16 } << self.id_len;
        let count = self.pin_nos.len();
        for offset in 0..count {
            self.gpio.clear(offset);
            if ((out >> offset) & 1) == 1 {
                self.gpio.set(offset);
            }

            // Signal final trace pin change.
            if offset == count - 1 {
                self.gpio.toggle(offset);
                self.gpio.toggle(offset);
            }
        }
    }
}

impl<'a, IP: InterruptPin<'a>> Driver for ParallelGPIOTrace<'a, IP> {  }

pub struct SerialUARTTrace<'a> {
    uart: &'a dyn Uart<'a>,
    tx_buffer: TakeCell<'static, [u8]>,
}

impl<'a> SerialUARTTrace<'a> {
    pub fn new(uart: &'a dyn Uart<'a>,
               tx_buffer: &'static mut [u8]) -> SerialUARTTrace<'a> {
        uart.configure(UartParameters {
            baud_rate: 115200,
            width: uart::Width::Eight,
            parity: uart::Parity::Even,
            stop_bits: uart::StopBits::One,
            hw_flow_control: false,
        });

        let serial_trace = SerialUARTTrace {
            uart,
            tx_buffer: TakeCell::new(tx_buffer),
        };

        serial_trace
    }
}

impl<'a> Trace for SerialUARTTrace<'a> {
    fn signal(&self, data: &[u8], len: usize) {
        let mut tx_buffer: Option<&'static mut [u8]> = None;
        while tx_buffer.is_none() {
            tx_buffer = self.tx_buffer.take();
        }
        let tx_buffer = tx_buffer.unwrap();

        let end = tx_buffer.len().min(len);
        for i in 0..end {
            tx_buffer[i] = data[i];
        }

        let (_return_code, _buf) = self.uart.transmit_buffer(tx_buffer, len);
    }
}

impl<'a> TransmitClient for SerialUARTTrace<'a> {
    fn transmitted_buffer(&self,
                          tx_buffer: &'static mut [u8],
                          _tx_len: usize,
                          _return_value: ReturnCode) {
        self.tx_buffer.put(Some(tx_buffer));
    }
}

impl<'a> Driver for SerialUARTTrace<'a> {  }
