use kernel::Driver;
use kernel::hil::trace::Trace;
use kernel::hil::gpio::InterruptPin;

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
        ParallelGPIOTrace {
            gpio,
            pin_nos,
            id_len,
        }
    }
}

impl<'a, IP: InterruptPin<'a>> Trace for ParallelGPIOTrace<'a, IP> {
    fn signal(&self, id: u8, other_data: Option<u8>) {
        let out: u16 =
            (id as u16)
            | ((other_data.unwrap_or(0) as u16) << self.id_len);
        for offset in 0..self.pin_nos.len() {
            if (out >> offset) == 1 {
                // Set the pin to high.
            } else {
                // Set the pin to low.
            }
        }
    }
}

impl<'a, IP: InterruptPin<'a>> Driver for ParallelGPIOTrace<'a, IP> {  }
