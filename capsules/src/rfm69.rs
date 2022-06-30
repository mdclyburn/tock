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
    pub const LNA: u8                 = 0x18;
    pub const RxBW: u8                = 0x19;
    pub const AFCBW: u8               = 0x1A;
    pub const DIOMapping0: u8         = 0x25;
    pub const DIOMapping1: u8         = 0x26;
    pub const IRQFlags1: u8           = 0x27;
    pub const RSSIThresh: u8          = 0x29;
    pub const IRQFlags2: u8           = 0x28;
    pub const PreambleMSB: u8         = 0x2C;
    pub const PreambleLSB: u8         = 0x2D;
    pub const SyncConfig: u8          = 0x2E;
    pub const PacketConfig1: u8       = 0x37;
    pub const FIFOThresh: u8          = 0x3C;
    pub const TestDAGC: u8            = 0x6F;

    /// Register masks.
    pub mod mask {
        pub const OpMode_Mode: u8 = 0b00011100;

        // Refer to section 3.3.7 of datasheet.
        pub const PALevel_PA0On: u8 = 0b10000000;
        pub const PALevel_PA1On: u8 = 0b01000000;
        pub const PALevel_PA2On: u8 = 0b00100000;
        pub const PALevel_OutputPower: u8 = 0b00011111;

        // See table 21 and table 22.
        pub const DIOMapping0_DIO0: u8 = 0b11000000;
        pub const DIOMapping0_DIO1: u8 = 0b00110000;
        pub const DIOMapping0_DIO2: u8 = 0b00001100;
        pub const DIOMapping0_DIO3: u8 = 0b00000011;
        pub const DIOMapping1_DIO4: u8 = 0b11000000;
        pub const DIOMapping1_DIO5: u8 = 0b00110000;

        pub const IRQFlags1_ModeReady: u8 = 0b10000000;
        pub const IRQFlags1_RXReady: u8 = 0b01000000;
        pub const IRQFlags1_TXReady: u8 = 0b00100000;

        pub const IRQFlags2_FIFOFull: u8 = 0b10000000;
        pub const IRQFlags2_FIFONotEmpty: u8 = 0b01000000;
        pub const IRQFlags2_PacketSent: u8 = 0b00001000;

        pub const SyncConfig_SyncOn: u8 = 0b10000000;
        pub const SyncConfig_SyncSize: u8 = 0b00111000;
    }
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

/// State of the split-phase operation the driver is doing.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Operation {
    /// Writing a value to a register, (address, value).
    Write(u8, u8),
    /// Checking that a read value matches expected value, (expected value).
    Confirm(u8),
    /// Updating a value in a register, (address, mask, shifted value).
    Modify(u8, u8, u8),
}

/// Overall status of the driver.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Status {
    /// Driver is not doing anything.
    Idle,
    /// In the middle of a read/write/modify operation.
    Transaction(Operation),
    /// Radio is in receive mode.
    Receive,
    /// Radio is in transmit mode.
    Transmit,
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
    time_source: &'static dyn time::Counter<'static, Frequency = A, Ticks = B>,
    buffers: (TakeCell<'static, [u8]>, TakeCell<'static, [u8]>),
    status: Cell<Status>,
    pending: [Cell<Option<Operation>>; 8],
}

impl<A: 'static + time::Frequency, B: 'static + time::Ticks> RFM69<A, B> {
    /// Create a new instance of the driver.
    pub fn new(
        grants: Grant<AppData, UpcallCount<1>, AllowRoCount<0>, AllowRwCount<1>>,
        spi: &'static dyn SpiMasterDevice,
        interrupt_pin: &'static dyn InterruptPin,
        reset_pin: &'static dyn ResetPin,
        time_source: &'static dyn time::Counter<Frequency = A, Ticks = B>,
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
            pending: [
                Cell::new(None),
                Cell::new(None),
                Cell::new(None),
                Cell::new(None),
                Cell::new(None),
                Cell::new(None),
                Cell::new(None),
                Cell::new(None),
            ],
        }
    }

    /// Ensure the radio is present and put it to sleep.
    pub fn initialize(&'static self) {
        if !self.time_source.is_running() {
            self.time_source.start().unwrap();
        }

        // Reset the radio and synchronously wait.
        self.reset_pin.set();
        self.busy_wait(1);
        self.reset_pin.clear();
        self.busy_wait(5);

        self.spi.set_client(self);
        self.interrupt_pin.set_client(self);

        // Start setting the recommended settings.
        self.pending[0].set(Some(Operation::Write(register::LNA, 0x88)));
        self.pending[1].set(Some(Operation::Write(register::RxBW, 0x55)));
        self.pending[2].set(Some(Operation::Write(register::AFCBW, 0x8B)));
        self.pending[3].set(Some(Operation::Write(register::RSSIThresh, 0xE4)));
        self.pending[4].set(Some(Operation::Write(register::TestDAGC, 0x30)));
        self.pending[5].set(Some(Operation::Write(register::PreambleLSB, 0x40)));
        // And put the radio into sleep mode.
        self.pending[6].set(Some(Operation::Modify(register::OpMode, register::mask::OpMode_Mode, u8::from(Mode::Sleep))));
        self.start_queue().unwrap();
    }

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
        rbuf[0] = 0xEE; rbuf[1] = 0xEE;
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

        self.status.set(Status::Transaction(Operation::Write(address, val)));
        if let Err((error, buf_a, buf_b)) = self.spi.read_write_bytes(wbuf, Some(rbuf), 2) {
            self.status.set(Status::Idle);
            self.buffers.0.put(Some(buf_a));
            self.buffers.1.put(buf_b);
            Err(RadioError::System(error))
        } else {
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

            self.status.set(Status::Transaction(Operation::Modify(address, mask, val << s)));
            self.read(address).or_else(|e| {
                self.status.set(Status::Idle);
                Err(e)
            })
        }
    }

    fn start_queue(&self) -> Result<()> {
        // Get the first operation off of the queue and start the operations.
        // This must exist, if not, there is a bug in the driver.
        let operation = self.pending[0].get().unwrap();
        match operation {
            Operation::Write(addr, val) => self.write(addr, val),
            Operation::Modify(addr, mask, val) => self.modify(addr, mask, val),
            // Invalid operation queued up.
            _ => panic!(),
        }
    }

    fn process_callback(&self) -> Result<()> {
        use Status::*;
        let current_status = self.status.get();
        match current_status {
            Transaction(operation) => match operation {
                // Completed writing the requested register to a specific value.
                // Read the value back to confirm that it is, in fact, correct.
                Operation::Write(addr, val) => {
                    // Remove the write from the pending queue.
                    self.pending.iter()
                        .find(|w| {
                            if let Some(op) = w.get() {
                                match op {
                                    Operation::Write(op_addr, _val) => op_addr == addr,
                                    Operation::Modify(op_addr, _mask, _val) => op_addr == addr,
                                    // Should only see writes and modifies in the queue.
                                    _ => panic!(),
                                }
                            } else {
                                false
                            }
                        })
                        .map_or_else(
                            || { kernel::debug!("Last command was not in queue."); },
                            |entry| { entry.set(None); });

                    self.status.set(Status::Transaction(Operation::Confirm(val)));
                    self.read(addr)
                },

                // Completed reading a register to confirm a value.
                // Compare the value to make sure it matches up.
                Operation::Confirm(written) => {
                    self.status.set(Status::Idle);
                    let actual = self.buffers.0.map(|buf| *buf.get(1).unwrap()).unwrap();
                    if written == actual {
                        // Possibly pull a pending write off the queue.
                        let mut next = self.pending.iter()
                            .filter(|w| w.get().is_some())
                            .map(|w| w.get())
                            .nth(0)
                            .unwrap_or(None);
                        if let Some(pending_write) = next {
                            match pending_write {
                                Operation::Write(addr, val) => self.write(addr, val),
                                Operation::Modify(addr, mask, val) => self.modify(addr, mask, val),
                                // A pending operation that is not write or modify made it into the queue.
                                // This is a logic bug.
                                // The driver should only place Write or Modify operations into the queue.
                                _ => panic!(),
                            }
                        } else {
                            Ok(())
                        }
                    } else {
                        kernel::debug!("Inconsistent values (exp. v. actual): {:#X} != {:#X}", written, actual);
                        Err(RadioError::Inconsistent)
                    }
                },

                // Completed reading the current register value.
                // Update the register's current value and perform the write.
                Operation::Modify(addr, mask, val) => {
                    let current = self.buffers.0.map(|buf| *buf.get(1).unwrap()).unwrap();
                    let new_val = (current & !mask) | val;
                    self.write(addr, new_val)
                }
            }

            // Driver was not doing an SPI operation yet received an interrupt.
            // This is a logic bug for the driver.
            _ => panic!()
        }
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
    fn command(&self, command_no: usize, r2: usize, r3: usize, pid: ProcessId) -> CommandReturn {
        match command_no {
            // Driver check.
            0 => CommandReturn::success(),
            _ => CommandReturn::failure(ErrorCode::INVAL),
        }
    }

    fn allocate_grant(&self, pid: ProcessId) -> core::result::Result<(), kernel::process::Error> {
        self.grants.enter(pid, |_, _| {  })
    }
}

impl<A: 'static + time::Frequency, B: 'static + time::Ticks> gpio::Client for RFM69<A, B> {
    fn fired(&self) {
        // Interrupt for GPIO pin fired.
        // Reason depends on the radio's operating mode,
        // which corresponds to the state of the driver.
        match self.status.get() {
            // Radio/driver is not doing anything, nor were we expecting an interrupt.
            Status::Idle => {  },

            // Driver in the middle of reading/writing registers.
            // This is also an unexpected state to be in and receive an interrupt.
            Status::Transaction(_op) => {  },

            // Radio is in receive mode.
            // The interrupt means we have received a packet.
            Status::Receive => unimplemented!(),

            // Radio is in transmit mode.
            // The interrupt means we have completed transmitting a packet.
            Status::Transmit => unimplemented!(),
        }
    }
}
