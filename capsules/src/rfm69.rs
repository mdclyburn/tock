use kernel::hil::spi;
use kernel::{AppId, Driver, ReturnCode};

use core::convert::Into;

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

pub struct Rfm69<'a> {
    spi: &'a dyn spi::SpiMasterDevice,
}

impl<'a> Rfm69<'a> {
    pub fn new(s: &'a dyn spi::SpiMasterDevice) -> Rfm69 {
        Rfm69 {
            spi: s,
        }
    }

    fn reset(&self) -> ReturnCode {
        self.spi.configure(spi::ClockPolarity::IdleLow, spi::ClockPhase::SampleLeading, 5000);
        ReturnCode::SUCCESS
    }

    fn set_mode(&self, _mode: OpMode) -> ReturnCode {
        ReturnCode::SUCCESS
    }
}

impl<'a> Driver for Rfm69<'a> {
    fn command(&self, minor_num: usize, r2: usize, r3: usize, caller_id: AppId) -> ReturnCode {
        match minor_num {
            0 => ReturnCode::SUCCESS,
            1 => self.setup(),
            2 => {
                let (mode, _) = (r2, r3);
                self.set_mode(OpMode::from(mode))
            },
            _ => ReturnCode::ENOSUPPORT,
        }
    }
}
