/*! RFM69 ISM radio.
 *
 * The RFM69 is a flexible radio that operates in the industry, science, and medical (ISM) band.
 * It offers a host of configuration settings, including flexible packet configuration and data encryption.
 * The host communicates with the radio over an SPI interface.
 */

use core::cell::Cell;

use kernel::{ErrorCode, ProcessId};
use kernel::grant::{
    AllowRoCount,
    AllowRwCount,
    Grant,
    UpcallCount,
};
use kernel::hil::gpio;
use kernel::hil::spi;
use kernel::hil::spi::SpiMasterDevice;
use kernel::hil::time;
use kernel::hil::time::ConvertTicks as _;
use kernel::syscall::{
    CommandReturn,
    SyscallDriver,
    SyscallReturn,
};
use kernel::utilities::cells::TakeCell;

pub const DRIVER_NUM: usize = crate::driver::NUM::Ism as usize;

type Result<T> = core::result::Result<T, RadioError>;

#[derive(Debug)]
enum RadioError {
    Busy,
    Inconsistent,
    System(ErrorCode),
}

/// Register addresses.
#[allow(non_upper_case_globals, unused)]
mod register {
    pub const FIFO: u8                = 0x00;
    pub const OpMode: u8              = 0x01;
    pub const PALevel: u8             = 0x11;
    pub const DIOMapping0: u8         = 0x25;
    pub const DIOMapping1: u8         = 0x26;
    pub const IRQFlags1: u8           = 0x27;
    pub const IRQFlags2: u8           = 0x28;
    pub const SyncConfig: u8          = 0x2E;
}

/// Packet format, either fixed- or variable-length.
#[derive(Clone, Copy)]
enum PacketFormat {
    /// Packets are of a fixed length.
    Fixed(u8),
    /// Packets can vary in length.
    Variable,
}

/// RFM69 per-app grant data.
pub struct AppData {
    /// Whether receive mode is active for the application.
    awaiting_rx: bool,
    /// Bit rate setting (see datasheet for valid values.
    bit_rate: u16,
    /// Packet format used by the application.
    packet_format: PacketFormat,
    /// Synchronization word.
    sync_word: u64,
    /// Node and broadcast address for filtering.
    address: Option<(u8, Option<u8>)>,
    /// AES encryption key.
    enc_key: Option<[u8; 16]>,
}

impl Default for AppData {
    fn default() -> AppData {
        AppData {
            awaiting_rx: false,
            // Use 150 kbps.
            bit_rate: 0x00D5,
            packet_format: PacketFormat::Variable,
            // This is the default sync word.
            sync_word: 1 << (7 * 8),
            address: None,
            enc_key: None,
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Status {
    Idle,
    WriteRegister(u8, u8),
    ConfirmRegister(u8),
    ModifyRegister(u8, u8, u8),
}

#[derive(Clone, Copy)]
enum Mode {
    Sleep,
    Standby,
    Transmit,
    Receive,
}

impl From<Mode> for u8 {
    fn from(mode: Mode) -> u8 {
        use Mode::*;
        match mode {
            Sleep => 0,
            Standby => 1,
            Transmit => 3,
            Receive => 4,
        }
    }
}

/// Helper trait for obtaining a configurable output GPIO pin.
pub trait ResetPin: 'static + gpio::Configure + gpio::Output {  }
impl<T: 'static + gpio::Configure + gpio::Output> ResetPin for T {  }

/// Helper trait for obtaining a configurable input GPIO pin.
pub trait InterruptPin: 'static + gpio::Configure + gpio::Interrupt<'static> {  }
impl<T: 'static + gpio::Configure + gpio::Interrupt<'static>> InterruptPin for T {  }

/// RFM69 ISM radio driver.
pub struct RFM69<A: 'static + time::Frequency, B: 'static + time::Ticks> {
    grants: Grant<AppData, UpcallCount<1>, AllowRoCount<0>, AllowRwCount<1>>,
    spi: &'static dyn SpiMasterDevice,
    interrupt_pin: &'static dyn InterruptPin,
    reset_pin: &'static dyn ResetPin,
    time_source: &'static dyn time::Time<Frequency = A, Ticks = B>,
    buffers: (TakeCell<'static, [u8]>, TakeCell<'static, [u8]>),
    status: Cell<Status>,
}

impl<A: 'static + time::Frequency, B: 'static + time::Ticks> RFM69<A, B> {
    /// Create a new instance of the driver.
    pub fn new(
        grants: Grant<AppData, UpcallCount<1>, AllowRoCount<0>, AllowRwCount<1>>,
        spi: &'static dyn SpiMasterDevice,
        interrupt_pin: &'static dyn InterruptPin,
        reset_pin: &'static dyn ResetPin,
        time_source: &'static dyn time::Time<Frequency = A, Ticks = B>,
        buffers: (&'static mut [u8; 2], &'static mut [u8; 2]),
    ) -> RFM69<A, B>
    {
        // Configure pins.
        reset_pin.make_output();
        reset_pin.clear();
        interrupt_pin.make_input();
        interrupt_pin.enable_interrupts(gpio::InterruptEdge::RisingEdge);

        // Configure SPI.
        spi.configure(spi::ClockPolarity::IdleLow, spi::ClockPhase::SampleLeading, 1000)
            .unwrap();

        let (rbuf, wbuf) = buffers;

        RFM69 {
            grants,
            spi,
            interrupt_pin,
            reset_pin,
            time_source,
            buffers: (TakeCell::new(rbuf), TakeCell::new(wbuf)),
            status: Cell::new(Status::Idle),
        }
    }

    /// Ensure the radio is present and put it to sleep.
    pub fn initialize(&'static self) {
        // Reset the radio and synchronously wait.
        self.reset_pin.set();
        self.busy_wait(1);
        self.reset_pin.clear();
        self.busy_wait(5);

        self.spi.set_client(self);

        // Place the radio in sleep.
    }

    #[inline]
    fn busy_wait(&self, duration_ms: u32) {
        let t_end = self.time_source.now()
            .wrapping_add(self.time_source.ticks_from_ms(duration_ms));
        loop {
            if self.time_source.now() > t_end { break; }
        }
    }

    fn read(&self, address: u8) -> Result<()> {
        let (rbuf, wbuf) = (self.buffers.0.take().ok_or(RadioError::Busy)?,
                            self.buffers.1.take().ok_or(RadioError::Busy)?);
        wbuf[0] = 0b0111_1111 & address;

        if let Err((error, buf_a, buf_b)) = self.spi.read_write_bytes(wbuf, Some(rbuf), 2) {
            self.buffers.0.put(Some(buf_a));
            self.buffers.1.put(buf_b);
            Err(RadioError::System(error))
        } else {
            Ok(())
        }
    }

    fn write(&self, address: u8, val: u8) -> Result<()> {
        let (rbuf, wbuf) = (self.buffers.0.take().ok_or(RadioError::Busy)?,
                            self.buffers.1.take().ok_or(RadioError::Busy)?);
        *wbuf.get_mut(0).unwrap() = 0b1000_0000 | address;
        *wbuf.get_mut(1).unwrap() = val;

        if let Err((error, buf_a, buf_b)) = self.spi.read_write_bytes(wbuf, Some(rbuf), 2) {
            self.buffers.0.put(Some(buf_a));
            self.buffers.1.put(buf_b);
            Err(RadioError::System(error))
        } else {
            self.status.set(Status::WriteRegister(address, val));
            Ok(())
        }
    }

    /// Update bits in a register.
    ///
    /// Change only the bits in the mask.
    /// `val` will be shifted up to proper offset in the mask.
    fn modify(&self, address: u8, mask: u8, val: u8) -> Result<()> {
        if self.status.get() != Status::Idle {
            Err(RadioError::Busy)
        } else {
            assert!(mask != 0);
            let mut s = 0;
            while (mask >> s) & 1 != 1 { s += 1; }

            self.status.set(Status::ModifyRegister(address, mask, val << s));
            self.read(address).or_else(|e| {
                self.status.set(Status::Idle);
                Err(e)
            })
        }
    }

    fn process_callback(&self) -> Result<()> {
        use Status::*;
        let current_status = self.status.get();
        match current_status {
            // Somehow, the driver was doing something yet the status reflects it as being idle.
            // This is a logic bug for the driver.
            Idle => panic!(),

            // Completed writing the requested register to a specific value.
            // Read the value back to confirm that it is, in fact, correct.
            WriteRegister(addr, val) => {
                self.status.set(Status::ConfirmRegister(val));
                self.read(addr)
            },

            // Completed reading a register to confirm a value.
            // Compare the value to make sure it matches up.
            ConfirmRegister(written) => {
                self.status.set(Status::Idle);
                let actual = self.buffers.0.map(|buf| *buf.get(1).unwrap()).unwrap();
                if written == actual {
                    Ok(())
                } else {
                    Err(RadioError::Inconsistent)
                }
            },

            // Completed reading the current register value.
            // Update the register's current value and perform the write.
            ModifyRegister(addr, mask, val) => {
                let current = self.buffers.0.map(|buf| *buf.get(1).unwrap()).unwrap();
                let new_val = (current & !mask) | val;
                self.write(addr, new_val)
            }
        }
    }

    fn set_mode(&self, target_mode: Mode) -> Result<()> {
        let mode_val = u8::from(target_mode);
        self.modify(register::OpMode, 0b00011100, mode_val)
    }
}

impl<A: 'static + time::Frequency, B: 'static + time::Ticks> spi::SpiMasterClient for RFM69<A, B> {
    fn read_write_done(
        &self,
        write_buffer: &'static mut [u8],
        read_buffer: Option<&'static mut [u8]>,
        _len: usize,
        status: core::result::Result<(), ErrorCode>)
    {
        self.buffers.0.put(read_buffer);
        self.buffers.1.put(Some(write_buffer));

        if let Err(e) = status {
            kernel::debug!("SPI failed: {:?}", e);
        } else {
            // Perform the next step of the operation.
            if let Err(e) = self.process_callback() {
                kernel::debug!("Radio callback processing failed: {:?}", e);
            }
        }
    }
}

impl<A: 'static + time::Frequency, B: 'static + time::Ticks> SyscallDriver for RFM69<A, B> {
    fn allocate_grant(&self, pid: ProcessId) -> core::result::Result<(), kernel::process::Error> {
        self.grants.enter(pid, |_, _| {  })
    }
}
