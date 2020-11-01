/// Energy accounting capsule in Tock

use kernel::{AppId, Driver, ReturnCode};
use kernel::common::cells::TakeCell;
use kernel::hil::eacct::EnergyAccounting;
use kernel::hil::time::{Alarm, AlarmClient};

use crate::virtual_alarm::VirtualMuxAlarm;

pub const DRIVER_NUM: usize = crate::driver::NUM::EnergyAccounting as usize;

pub struct EnergyAccount<'a, Adc, A: Alarm<'a>>
    where Adc: kernel::hil::adc::Adc + kernel::hil::adc::AdcHighSpeed {
    adc: &'a Adc,
    alarm: &'a VirtualMuxAlarm<'a, A>,
    acc: TakeCell<'a, [usize]>,
}

impl<'a, Adc, A: Alarm<'a>> EnergyAccount<'a, Adc, A>
    where Adc: kernel::hil::adc::Adc + kernel::hil::adc::AdcHighSpeed {
    pub fn new(adc: &'a Adc, alarm: &'a VirtualMuxAlarm<'a, A>, acc: &'static mut [usize])
               -> EnergyAccount<'a, Adc, A> {
        EnergyAccount {
            adc: adc,
            alarm: alarm,
            acc: TakeCell::new(acc),
        }
    }
}

impl<'a, Adc, A: Alarm<'a>> Driver for EnergyAccount<'a, Adc, A>
    where Adc: kernel::hil::adc::Adc + kernel::hil::adc::AdcHighSpeed {
    fn command(&self, minor_num: usize, r2: usize, r3: usize, caller_id: AppId) -> ReturnCode {
        match minor_num {
            _ => ReturnCode::ENOSUPPORT
        }
    }
}

impl<'a, Adc, A: Alarm<'a>> AlarmClient for EnergyAccount<'a, Adc, A>
    where Adc: kernel::hil::adc::Adc + kernel::hil::adc::AdcHighSpeed {
    fn alarm(&self) {
    }
}

impl<'a, Adc, A: Alarm<'a>> EnergyAccounting for EnergyAccount<'a, Adc, A>
where Adc: kernel::hil::adc::Adc + kernel::hil::adc::AdcHighSpeed {
}
