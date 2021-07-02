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

        let data_len = tx_buffer.len().min(len);
        tx_buffer[0] = data_len as u8;
        for i in 1..data_len+1 {
            tx_buffer[i] = data[i-1];
        }

        let (_return_code, _buf) = self.uart.transmit_buffer(tx_buffer, 1+data_len);
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

#[macro_export]
macro_rules! serial_trace {
    ($name:expr, $data:expr) => {
        {
            let data: &[u8] = ($data);

            use kernel::hil::trace;
            use kernel::hil::trace::Trace;

            if trace::INSTANCE.is_some() {
                trace::INSTANCE.as_ref().unwrap()
                    .signal(data, data.len());
            }
        }
    }
}
