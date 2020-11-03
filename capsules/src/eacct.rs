/// Energy accounting capsule in Tock

use kernel::{AppId, Driver, ReturnCode};
use kernel::common::cells::MapCell;
use kernel::common::list::{List, ListLink, ListNode};
use kernel::hil::adc::{
    Client as AdcClient,
    HighSpeedClient as AdcHighSpeedClient,
};
use kernel::hil::eacct::{EnergyAccounting, Heuristic};
use kernel::hil::time::{Alarm, AlarmClient, Time};

use crate::virtual_alarm;
use crate::virtual_alarm::VirtualMuxAlarm;

pub const DRIVER_NUM: usize = crate::driver::NUM::EnergyAccounting as usize;

// Short-hand for ADC traits.
pub trait CombinedAdc: kernel::hil::adc::Adc + kernel::hil::adc::AdcHighSpeed {  }
impl<T: kernel::hil::adc::Adc + kernel::hil::adc::AdcHighSpeed> CombinedAdc for T {  }

struct Entry<'a> {
    app_id: AppId,
    used: MapCell<usize>,
    next: ListLink<'a, Entry<'a>>,
}

impl<'a> Entry<'a> {
    pub fn new(id: AppId) -> Entry<'a> {
        Entry {
            app_id: id,
            used: MapCell::new(0),
            next: ListLink::empty(),
        }
    }
}

impl<'a> ListNode<'a, Entry<'a>> for Entry<'a> {
    fn next(&self) -> &ListLink<'a, Entry<'a>> {
        &self.next
    }
}

pub struct EnergyAccount<'a, Adc: CombinedAdc, A: Alarm<'a>> {
    adc: &'a Adc,
    adc_channel: &'a <Adc as kernel::hil::adc::Adc>::Channel,
    alarm: &'a VirtualMuxAlarm<'a, A>,
    stats: List<'a, Entry<'a>>,
    status: MapCell<Heuristic>,
}

impl<'a, Adc: CombinedAdc, A: Alarm<'a>> EnergyAccount<'a, Adc, A> {
    pub fn new(adc: &'a Adc, adc_channel: &'a Adc::Channel, alarm: &'a VirtualMuxAlarm<'a, A>)
               -> EnergyAccount<'a, Adc, A> {
        EnergyAccount {
            adc: adc,
            adc_channel: adc_channel,
            alarm: alarm,
            stats: List::new(),
            status: MapCell::empty(),
        }
    }

    fn account(&self, app_id: AppId, sample: u16) {
        let find_res = self.stats.iter().find(|entry| {
            entry.app_id == app_id
        });

        if let Some(entry) = find_res {
            entry.used.replace(sample as usize);
        } else {
            // Need to add app ID entry to the list.
        }
    }
}

impl<'a, Adc: CombinedAdc, A: Alarm<'a>> Driver for EnergyAccount<'a, Adc, A> {
    fn command(&self, minor_num: usize, r2: usize, r3: usize, caller_id: AppId) -> ReturnCode {
        match minor_num {
            0 => ReturnCode::SUCCESS,
            _ => ReturnCode::ENOSUPPORT
        }
    }
}

impl<'a, Adc: CombinedAdc, A: Alarm<'a>> AlarmClient for EnergyAccount<'a, Adc, A> {
    /// Handle time-delayed samples.
    fn alarm(&self) {
        self.alarm.disarm(); // Not handling this return code.

        let _return_code = self.status.map_or(ReturnCode::EINVAL, |status| {
            match status {
                // Sample(s) time!
                Heuristic::After(_app_id, _delay) => self.adc.sample(self.adc_channel),
                Heuristic::Recurrent(_app_id, _delay) => self.adc.sample(self.adc_channel),

                // Not sure why we're here... Let's just stop.
                _ => ReturnCode::EINVAL
            }
        });
    }
}

impl<'a, Adc: CombinedAdc, A: Alarm<'a>> AdcClient for EnergyAccount<'a, Adc, A> {
    /// Handle current sensor sample coming back from the ADC.
    fn sample_ready(&self, sample: u16) {
        // Finally take the status since we will be done with it
        // (except as not needed, like with Recurrent).
        if let Some(status) = self.status.take() {
            match status {
                Heuristic::Instant(app_id) => self.account(app_id, sample),
                Heuristic::After(app_id, _delay) => self.account(app_id, sample),
                Heuristic::Recurrent(app_id, interval) => {
                    // Put this back to happen again.
                    self.status.put(Heuristic::Recurrent(app_id, interval));
                    self.account(app_id, sample);
                }
            }
        }
    }
}

impl<'a, Adc: CombinedAdc, A: Alarm<'a>> AdcHighSpeedClient for EnergyAccount<'a, Adc, A> {
    fn samples_ready(&self, samples: &'static mut [u16], length: usize) {
        //  Use samples to attribute energy usage.
    }
}

impl<'a, Adc: CombinedAdc, A: Alarm<'a>> EnergyAccounting for EnergyAccount<'a, Adc, A> {
    fn measure(&self, how: Heuristic) -> ReturnCode {
        if self.status.is_some() {
            // Something is already in progress.
            ReturnCode::EBUSY
        } else {
            self.status.put(how);

            match how {
                // Take a measurement now.
                Heuristic::Instant(_app_id) => self.adc.sample(self.adc_channel),

                // Set the timer instead and we'll come back here later.
                Heuristic::After(_app_id, delay) => {
                    self.alarm.set_alarm(self.alarm.now(), virtual_alarm::VirtualMuxAlarm::<'a, A>::ticks_from_ms(delay));
                    ReturnCode::SUCCESS
                },

                // Set the timer instead and we'll come back here later... and again... and again...
                Heuristic::Recurrent(_app_id, interval) => {
                    // self.alarm.set_alarm(self.alarm.now(), self.alarm.now().wrapping_add(interval));
                    ReturnCode::SUCCESS
                },
            }
        }
    }
}
