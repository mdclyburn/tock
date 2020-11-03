/// Energy accounting capsule in Tock

use kernel::{AppId, Driver, ReturnCode};
use kernel::common::cells::{MapCell, TakeCell};
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

pub struct Entry {
    app_id: AppId,
    used: MapCell<usize>,
}

impl Entry {
    fn new(id: AppId, used: usize) -> Entry {
        Entry {
            app_id: id,
            used: MapCell::new(used),
        }
    }
}

pub struct EnergyAccount<'a, Adc: CombinedAdc, A: Alarm<'a>> {
    adc: &'a Adc,
    adc_channel: &'a <Adc as kernel::hil::adc::Adc>::Channel,
    alarm: &'a VirtualMuxAlarm<'a, A>,
    no_entries: usize,
    entries: TakeCell<'a, [Option<Entry>]>,
    status: MapCell<Heuristic>,
}

impl<'a, Adc: CombinedAdc, A: Alarm<'a>> EnergyAccount<'a, Adc, A> {
    pub fn new(adc: &'a Adc,
               adc_channel: &'a Adc::Channel,
               alarm: &'a VirtualMuxAlarm<'a, A>,
               entries: &'a mut [Option<Entry>],
               no_entries: usize)
               -> EnergyAccount<'a, Adc, A> {
        EnergyAccount {
            adc: adc,
            adc_channel: adc_channel,
            alarm: alarm,
            no_entries: no_entries,
            entries: TakeCell::new(entries),
            status: MapCell::empty(),
        }
    }

    /// Add data to the running statistics.
    fn account(&self, app_id: AppId, sample: u16) {
        self.entries.map(|entries| {
            let find_res = entries.iter()
                .filter(|opt| opt.is_some())
                .map(|opt| opt.as_ref().unwrap())
                .find(|entry| entry.app_id == app_id);

            if let Some(entry) = find_res {
                entry.used.replace(sample as usize);
            } else {
                for i in 0..self.no_entries {
                    if entries[i].is_none() {
                        entries[i] = Some(Entry::new(app_id, sample as usize));
                    }
                }
            }
        });
    }

    /// Retrieve the usage for a given application.
    fn usage_of(&self, app_id: AppId) -> Option<usize> {
        self.entries.map_or(None, |entries| {
            let find_res = entries.iter()
                .filter(|opt| opt.is_some())
                .map(|opt| opt.as_ref().unwrap())
                .find(|entry| entry.app_id == app_id);

            if let Some(entry) = find_res {
                entry.used.map(|used| *used)
            } else {
                None
            }
        })
    }
}

impl<'a, Adc: CombinedAdc, A: Alarm<'a>> Driver for EnergyAccount<'a, Adc, A> {
    fn command(&self, minor_num: usize, r2: usize, r3: usize, caller_id: AppId) -> ReturnCode {
        match minor_num {
            // It exists.
            0 => ReturnCode::SUCCESS,

            // Usage for given app ID.
            5 => if let Some(usage) = self.usage_of(caller_id) {
                ReturnCode::SuccessWithValue { value: usage }
            } else {
                ReturnCode::SuccessWithValue { value: 0 }
            },

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
