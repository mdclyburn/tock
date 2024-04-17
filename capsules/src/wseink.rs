/** WaveShare eInk 2.13-in. display, v4.
 */

use kernel::hil::time::{Alarm, AlarmClient};
use kernel::hil::gpio::{Input, Output, Pin};
use kernel::hil::spi::{self, SpiMasterDevice};

use crate::virtual_alarm::VirtualMuxAlarm;

pub struct WS2C250<A: 'static + Alarm<'static>> {
    spi: &'static dyn SpiMasterDevice,
    pin_reset: &'static dyn Pin,
    pin_dc: &'static dyn Pin,
    pin_busy: &'static dyn Pin,
    alarm: &'static VirtualMuxAlarm<'static, A>,
}

impl<A: 'static + Alarm<'static>> WS2C250<A> {
    pub fn new(
        spi: &'static dyn SpiMasterDevice,
        pin_reset: &'static dyn Pin,
        pin_dc: &'static dyn Pin,
        pin_busy: &'static dyn Pin,
        alarm: &'static VirtualMuxAlarm<'static, A>,
    ) -> WS2C250<A>
    {
        let _ = pin_reset.make_output();
        let _ = pin_dc.make_output();
        let _ = pin_busy.make_input();

        pin_reset.clear();
        pin_dc.clear();

        WS2C250 {
            spi,
            pin_reset,
            pin_dc,
            pin_busy,
            alarm,
        }
    }
}
