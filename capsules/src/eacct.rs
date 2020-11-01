/// Energy accounting capsule in Tock

use kernel::{AppId, Driver, ReturnCode};
use kernel::common::cells::MapCell;
use kernel::common::list::{List, ListLink, ListNode};
use kernel::hil::eacct::{EnergyAccounting, Heuristic};
use kernel::hil::time::{Alarm, AlarmClient};

use crate::virtual_alarm::VirtualMuxAlarm;

pub const DRIVER_NUM: usize = crate::driver::NUM::EnergyAccounting as usize;

struct Entry<'a> {
    app_id: AppId,
    used: usize,
    next: ListLink<'a, Entry<'a>>,
}

impl<'a> Entry<'a> {
    pub fn new(id: AppId) -> Entry<'a> {
        Entry {
            app_id: id,
            used: 0,
            next: ListLink::empty(),
        }
    }
}

impl<'a> ListNode<'a, Entry<'a>> for Entry<'a> {
    fn next(&self) -> &ListLink<'a, Entry<'a>> {
        &self.next
    }
}

pub struct EnergyAccount<'a, Adc, A: Alarm<'a>>
    where Adc: kernel::hil::adc::Adc + kernel::hil::adc::AdcHighSpeed {
    adc: &'a Adc,
    alarm: &'a VirtualMuxAlarm<'a, A>,
    stats: List<'a, Entry<'a>>,
    timer_metadata: MapCell<AppId>,
}

impl<'a, Adc, A: Alarm<'a>> EnergyAccount<'a, Adc, A>
    where Adc: kernel::hil::adc::Adc + kernel::hil::adc::AdcHighSpeed {
    pub fn new(adc: &'a Adc, alarm: &'a VirtualMuxAlarm<'a, A>)
               -> EnergyAccount<'a, Adc, A> {
        EnergyAccount {
            adc: adc,
            alarm: alarm,
            stats: List::new(),
            timer_metadata: MapCell::empty(),
        }
    }
}

impl<'a, Adc, A: Alarm<'a>> Driver for EnergyAccount<'a, Adc, A>
    where Adc: kernel::hil::adc::Adc + kernel::hil::adc::AdcHighSpeed {
    fn command(&self, minor_num: usize, r2: usize, r3: usize, caller_id: AppId) -> ReturnCode {
        match minor_num {
            0 => ReturnCode::SUCCESS,
            _ => ReturnCode::ENOSUPPORT
        }
    }
}

impl<'a, Adc, A: Alarm<'a>> AlarmClient for EnergyAccount<'a, Adc, A>
    where Adc: kernel::hil::adc::Adc + kernel::hil::adc::AdcHighSpeed {
    fn alarm(&self) {
        if let Some(app_id) = self.timer_metadata.take() {
            // Take a measurement and account it to the given application.
            self.measure(app_id, Heuristic::Instant);
        }
    }
}

impl<'a, Adc, A: Alarm<'a>> EnergyAccounting for EnergyAccount<'a, Adc, A>
where Adc: kernel::hil::adc::Adc + kernel::hil::adc::AdcHighSpeed {
    fn measure(&self, app: AppId, how: Heuristic) {
        match how {
            Heuristic::Instant => {
                // Take a measurement now.
            },

            Heuristic::After(_delay) => {
                // Set the timer instead and we'll come back here later.
            },
        }
    }
}
