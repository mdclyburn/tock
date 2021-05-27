use kernel::hil::gpio_trace::GPIOTrace;
use kernel::hil::gpio::InterruptPin;

use crate::gpio::GPIO;

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
