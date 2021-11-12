use crate::driver;

use clockwise_shared::trace::TraceData;
use kernel::{Driver, ReturnCode};
use kernel::debug;
use kernel::common::cells::TakeCell;
use kernel::hil::trace::Trace;
use kernel::hil::uart;
use kernel::hil::uart::{
    Uart,
    Parameters as UartParameters,
    TransmitClient,
};

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

        SerialUARTTrace {
            uart,
            tx_buffer: TakeCell::new(tx_buffer),
        }
    }
}

impl<'a> Trace for SerialUARTTrace<'a> {
    fn signal(&self, data: &TraceData) {
        let mut tx_buffer: Option<&'static mut [u8]> = self.tx_buffer.take();
        while tx_buffer.is_none() {
            self.uart.poll_service();
            tx_buffer = self.tx_buffer.take();
        }
        let tx_buffer = tx_buffer.unwrap();

        let data_len = data.serialize(tx_buffer);

        let (_return_code, _buf) = self.uart.transmit_buffer(tx_buffer, data_len);
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
    ($name:expr, $data:expr) => {{
        use kernel;

        let data = ($data);
        kernel::hil::trace::signal(data);
    }}
}
