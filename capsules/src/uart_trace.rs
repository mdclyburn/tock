use kernel::{Driver, ReturnCode};
use kernel::common::cells::TakeCell;
use kernel::hil::trace::Trace;
use kernel::hil::uart;
use kernel::hil::uart::{
    Uart,
    Parameters as UartParameters,
    TransmitClient,
};

use crate::driver;

pub const DRIVER_NUM: usize = driver::NUM::Trace as usize;

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
