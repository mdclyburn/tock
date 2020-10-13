use kernel::hil::spi;

pub struct Rfm69<'a> {
    spi: &'a dyn spi::SpiMasterDevice,
}

impl<'a> Rfm69<'a> {
    pub fn new(s: &'a dyn spi::SpiMasterDevice) -> Rfm69 {
        Rfm69 {
            spi: s,
        }
    }
}
