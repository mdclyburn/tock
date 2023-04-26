use kernel::errorcode::ErrorCode;
use kernel::hil::digital_audio::{
    DigitalAudioClient,
    DigitalAudioInterface,
};
use kernel::process::ProcessId;
use kernel::syscall::{
    CommandReturn,
    SyscallDriver,
};
use kernel::utilities::cells::TakeCell;

pub const DRIVER_NUM: usize = crate::driver::NUM::Audio as usize;

pub struct AudioPlayer {
    dai: &'static dyn DigitalAudioInterface,
    buffer: TakeCell<'static, [u16]>,
}

impl AudioPlayer {
    pub fn new(dai: &'static dyn DigitalAudioInterface,
               buffer: &'static mut [u16])
               -> AudioPlayer
    {
        AudioPlayer {
            dai,
            buffer: TakeCell::new(buffer),
        }
    }
}

impl DigitalAudioClient for AudioPlayer {
    fn playback_finished(&self, buffer: &'static mut [u16]) {
        self.buffer.put(Some(buffer));
        kernel::debug!("Audio player got buffer back.");
    }
}

impl SyscallDriver for AudioPlayer {
    fn allocate_grant(&self, pid: ProcessId) -> Result<(), kernel::process::Error> {
        Ok(())
    }

    fn command(&self,
               command_no: usize,
               r2: usize,
               r3: usize,
               pid: ProcessId) -> CommandReturn {
        match (command_no, r2, r3) {
            (0, _, _) => CommandReturn::success(),

            // Send the audio.
            (10, _, _) => {
                if self.buffer.is_some() {
                    let buffer = self.buffer.take().unwrap();
                    match self.dai.play(buffer) {
                        Ok(_) => CommandReturn::success(),
                        Err((buffer, e)) => {
                            self.buffer.put(Some(buffer));
                            CommandReturn::failure(e)
                        },
                    }
                } else {
                    CommandReturn::failure(ErrorCode::BUSY)
                }
            },

            _ => CommandReturn::failure(ErrorCode::NOSUPPORT),
        }
    }
}
