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