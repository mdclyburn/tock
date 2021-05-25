use kernel::hil::gpio::Output;
use kernel::hil::gpio_trace::GPIOTrace;

pub struct Trace<'a> {
    out_pins: &'a [&'a dyn Output],
    id_len: u8,
}

impl<'a> Trace<'a> {
    pub fn new(
        out_pins: &'a [&'a dyn Output],
        id_len: u8) -> Trace<'a>
    {
        Trace {
            out_pins,
            id_len,
        }
    }
}

impl<'a> GPIOTrace for Trace<'a> {
    fn signal(&self, id: u8, other_data: Option<u8>) {
        // When id >> self.id_len != 0, id is out of range.
        // Could that be problematic during runtime?
        for offset in 0..self.id_len {
            if (id >> offset) & 1 == 1 {
                self.out_pins[offset as usize].set();
            } else {
                self.out_pins[offset as usize].clear();
            }
        }

        // Set upper pins according to other supplied data.
        // Always clear them if no data is provided.
        let out_pin_count: u8 = self.out_pins.len() as u8;
        if let Some(val) = other_data {
            for offset in self.id_len..out_pin_count {
                let val_bit_offset = offset - self.id_len;
                if (val >> val_bit_offset) & 1 == 1{
                    self.out_pins[offset as usize].set();
                } else {
                    self.out_pins[offset as usize].clear();
                }
            }
        } else {
            for offset in self.id_len..out_pin_count {
                self.out_pins[offset as usize].clear();
            }
        }
    }
}
