/*! Digital audio HIL
 */

use crate::errorcode::ErrorCode;

pub enum State {
    Idle,
    Playing,
}

pub trait DigitalAudioInterface {
    fn play(&'static self, buffer: &'static mut [u16]) -> Result<(), (&'static mut [u16], ErrorCode)>;

    fn state(&self) -> State;
}

pub trait DigitalAudioClient {
    fn playback_finished(&'static self, buffer: &'static mut [u16]);
}
