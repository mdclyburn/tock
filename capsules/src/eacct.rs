/// Energy accounting in Tock

use kernel::{AppId, Driver, ReturnCode};
use kernel::common::cells::TakeCell;

pub const DRIVER_NUM: usize = crate::driver::NUM::EnergyAccounting as usize;

pub struct EnergyAccount<'a, Adc>
    where Adc: kernel::hil::adc::Adc + kernel::hil::adc::AdcHighSpeed {
    adc: &'a Adc,
    acc: TakeCell<'a, [usize]>,
}

impl<'a, Adc> EnergyAccount<'a, Adc>
    where Adc: kernel::hil::adc::Adc + kernel::hil::adc::AdcHighSpeed {
    pub fn new(adc: &'a Adc, acc: &'static mut [usize])
               -> EnergyAccount<'a, Adc> {
        EnergyAccount {
            adc: adc,
            acc: TakeCell::new(acc),
        }
    }
}

impl<'a, Adc> Driver for EnergyAccount<'a, Adc>
    where Adc: kernel::hil::adc::Adc + kernel::hil::adc::AdcHighSpeed {
    fn command(&self, minor_num: usize, r2: usize, r3: usize, caller_id: AppId) -> ReturnCode {
        match minor_num {
            _ => ReturnCode::ENOSUPPORT
        }
    }
}
