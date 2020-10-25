use kernel::common::cells::TakeCell;
use kernel::hil::spi;
use kernel::{AppId, Driver, ReturnCode};

use core::convert::From;

pub const DRIVER_NUM: usize = crate::driver::NUM::Ism as usize;

/// Radio operating mode.
enum OpMode {
    Sleep = 0,
    Standby = 1,
    FrequencySynthesizer = 2,
    Transmit = 3,
    Receive = 4,
}

impl From<usize> for OpMode {
    fn from(x: usize) -> OpMode {
        match x {
            0 => OpMode::Sleep,
            1 => OpMode::Standby,
            2 => OpMode::FrequencySynthesizer,
            3 => OpMode::Transmit,
            4 => OpMode::Receive,
            _ => OpMode::Sleep,
        }
    }
}

/// Driver for communicating with the RFM69HCW radio over SPI.
pub struct Rfm69<'a> {
    spi: &'a dyn spi::SpiMasterDevice,
    buffer: TakeCell<'static, [u8]>,
}

impl<'a> Rfm69<'a> {
    pub fn new(s: &'a dyn spi::SpiMasterDevice, buffer: &'static mut [u8]) -> Rfm69<'a> {
        Rfm69 {
            spi: s,
            buffer: TakeCell::new(buffer),
        }
    }

    /// Reset and configure the radio.
    fn reset(&self) -> ReturnCode {
        self.spi.configure(spi::ClockPolarity::IdleLow, spi::ClockPhase::SampleLeading, 5000);
        ReturnCode::SUCCESS
    }

    /// Change the radio operating mode.
    fn set_mode(&self, mode: OpMode) -> ReturnCode {
        if let Some(buffer) = self.buffer.take() {
            buffer[0] = 0x01 | 128;
            buffer[1] = match mode {
                OpMode::Sleep => 0b000,
                OpMode::Standby => 0b001,
                OpMode::FrequencySynthesizer => 0b010,
                OpMode::Transmit => 0b011,
                OpMode::Receive => 0b100,
                _ => 0,
            };

            self.spi.read_write_bytes(buffer, None, 2)
        } else {
            ReturnCode::EBUSY
        }
    }
}

impl<'a> spi::SpiMasterClient for Rfm69<'a> {
    fn read_write_done(
        &self,
        write_buffer: &'static mut [u8],
        _read_buffer: Option<&'static mut [u8]>,
        _len: usize) {
        self.buffer.put(Some(write_buffer));
    }
}

impl<'a> Driver for Rfm69<'a> {
    fn command(&self, minor_num: usize, r2: usize, r3: usize, caller_id: AppId) -> ReturnCode {
        match minor_num {
            0 => ReturnCode::SUCCESS,
            1 => self.reset(),
            2 => {
                let (mode, _) = (r2, r3);
                self.set_mode(OpMode::from(mode))
            },
            _ => ReturnCode::ENOSUPPORT,
        }
    }
}
