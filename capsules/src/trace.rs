use kernel::Driver;
use kernel::common::cells::MapCell;
use kernel::hil::gpio_trace::GPIOTrace;
use kernel::hil::gpio::InterruptPin;

use crate::driver;
use crate::gpio::GPIO;

pub const DRIVER_NUM: usize = driver::NUM::Trace as usize;
pub static mut INSTANCE: MapCell<&dyn GPIOTrace> = MapCell::empty();

pub struct Trace<'a, IP: InterruptPin<'a>> {
    gpio: &'a GPIO<'a, IP>,
    pin_nos: &'a [u8],
    id_len: u8,
}

impl<'a, IP: InterruptPin<'a>> Trace<'a, IP> {
    pub fn new(gpio: &'a GPIO<'a, IP>,
               pin_nos: &'a [u8],
               id_len: u8)
               -> Trace<'a, IP>
    {
        Trace {
            gpio,
            pin_nos,
            id_len,
        }
    }
}

impl<'a, IP: InterruptPin<'a>> GPIOTrace for Trace<'a, IP> {
    fn signal(&self, _id: u8, _other_data: Option<u8>) {
    }
}

impl<'a, IP: InterruptPin<'a>> Driver for Trace<'a, IP> {  }
