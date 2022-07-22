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
use kernel::processbuffer::{
    ReadableProcessBuffer as _,
    WriteableProcessBuffer as _,
};
use kernel::syscall::{
    CommandReturn,
    SyscallDriver,
};
use kernel::utilities::cells::{OptionalCell, TakeCell};

pub const DRIVER_NUM: usize = crate::driver::NUM::Ism as usize;

type Result<T> = core::result::Result<T, RadioError>;

#[derive(Debug)]
enum RadioError {
    Busy,
    Inconsistent,
    NoReadBuffer,
    NoWriteBuffer,
    Process(kernel::process::Error),
    System(ErrorCode),
    QueueFull,
}

/// Register addresses.
#[allow(non_upper_case_globals, unused)]
mod register {
    pub const FIFO: u8                = 0x00;
    pub const OpMode: u8              = 0x01;
    pub const BitrateMSB: u8          = 0x03;
    pub const BitrateLSB: u8          = 0x04;
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
    pub const SyncValue1: u8          = 0x2F;
    pub const PacketConfig1: u8       = 0x37;
    pub const PayloadLength: u8       = 0x38;
    pub const FIFOThresh: u8          = 0x3C;
    pub const PacketConfig2: u8       = 0x3D;
    pub const AESKey1: u8             = 0x3E;
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

        pub const PacketConfig1_PacketFormat: u8 = 0b10000000;

        pub const PacketConfig2_AESOn: u8 = 0b00000001;

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

/// Grant numbers.
mod grant_nos {
    /// FIFO data exchange buffer.
    ///
    /// Applications share this buffer with the driver to move data to and from the FIFO.
    /// When transmitting data, the driver reads the packet from this buffer.
    /// When receiving data, the driver writes the packet to this buffer.
    pub const ALLOW_RW_FIFO_BUFFER: usize = 0;

    /// Transmission completed upcall.
    pub const SUBSCRIBE_TX_COMPLETE: usize = 0;

    //// Reception completed upcall.
    pub const SUBSCRIBE_RX_COMPLETE: usize = 1;
}

/// RFM69 per-app grant data.
pub struct AppData {
    /// Bit rate setting (see datasheet for bit rate calculation).
    bit_rate: u16,
    /// Packet format used by the application.
    packet_format: PacketFormat,
    /// Synchronization word.
    ///
    /// First item is the sync word length in bytes minus one.
    /// Second item is the sync word.
    sync_word: Option<(u8, u64)>,
    /// Node and broadcast address for filtering.
    address: Option<(u8, Option<u8>)>,
    /// AES encryption key.
    enc_key: Option<[u8; 16]>,
}

impl Default for AppData {
    fn default() -> AppData {
        AppData {
            // Default to 19.2 kbps.
            bit_rate: 0x0683,
            packet_format: PacketFormat::Variable,
            sync_word: None,
            address: None,
            enc_key: None,
        }
    }
}

const SYNC_WORD_DEFAULT: u64 = 0x01010101_01010101;

/// State of the split-phase operation the driver is doing.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Operation {
    /// Writing a value to a register (address, value).
    WriteRegister(u8, u8),
    /// Updating a value in a register (address, mask, value, current value).
    ModifyRegister(u8, u8, u8, Option<u8>),
    /// Write the data from the application's buffer into the FIFO.
    FIFOWrite,
    /// Read the data from FIFO into the application's buffer.
    FIFORead,
}

/// Operating status of the radio.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Status {
    /// Driver is not doing anything.
    Idle,
    /// Radio is transmitting a packet.
    Transmitting,
    /// Radio is listening for packets.
    Receiving,
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

const FIFO_LENGTH: usize = 66;

/// RFM69 ISM radio driver.
pub struct RFM69<A: 'static + time::Frequency, B: 'static + time::Ticks> {
    grants: Grant<AppData, UpcallCount<1>, AllowRoCount<0>, AllowRwCount<1>>,
    spi: &'static dyn SpiMasterDevice,
    interrupt_pin: &'static dyn InterruptPin,
    reset_pin: &'static dyn ResetPin,
    time_source: &'static dyn time::Counter<'static, Frequency = A, Ticks = B>,
    buffers: (TakeCell<'static, [u8]>, TakeCell<'static, [u8]>),
    status: Cell<Status>,
    pending: [Cell<Option<Operation>>; 64],
    fifo_write_pending: Cell<bool>,
    configured_for: OptionalCell<ProcessId>,
    receive_for: OptionalCell<ProcessId>,
}

impl<A: 'static + time::Frequency, B: 'static + time::Ticks> RFM69<A, B> {
    /// Create a new instance of the driver.
    pub fn new(
        grants: Grant<AppData, UpcallCount<1>, AllowRoCount<0>, AllowRwCount<1>>,
        spi: &'static dyn SpiMasterDevice,
        interrupt_pin: &'static dyn InterruptPin,
        reset_pin: &'static dyn ResetPin,
        time_source: &'static dyn time::Counter<Frequency = A, Ticks = B>,
        buffers: (&'static mut [u8; FIFO_LENGTH+1], &'static mut [u8; FIFO_LENGTH+1]),
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
                Cell::new(None), Cell::new(None), Cell::new(None), Cell::new(None),
                Cell::new(None), Cell::new(None), Cell::new(None), Cell::new(None),
                Cell::new(None), Cell::new(None), Cell::new(None), Cell::new(None),
                Cell::new(None), Cell::new(None), Cell::new(None), Cell::new(None),
                Cell::new(None), Cell::new(None), Cell::new(None), Cell::new(None),
                Cell::new(None), Cell::new(None), Cell::new(None), Cell::new(None),
                Cell::new(None), Cell::new(None), Cell::new(None), Cell::new(None),
                Cell::new(None), Cell::new(None), Cell::new(None), Cell::new(None),
                Cell::new(None), Cell::new(None), Cell::new(None), Cell::new(None),
                Cell::new(None), Cell::new(None), Cell::new(None), Cell::new(None),
                Cell::new(None), Cell::new(None), Cell::new(None), Cell::new(None),
                Cell::new(None), Cell::new(None), Cell::new(None), Cell::new(None),
                Cell::new(None), Cell::new(None), Cell::new(None), Cell::new(None),
                Cell::new(None), Cell::new(None), Cell::new(None), Cell::new(None),
                Cell::new(None), Cell::new(None), Cell::new(None), Cell::new(None),
                Cell::new(None), Cell::new(None), Cell::new(None), Cell::new(None),
            ],
            fifo_write_pending: Cell::new(false),
            configured_for: OptionalCell::<ProcessId>::empty(),
            receive_for: OptionalCell::<ProcessId>::empty(),
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
        self.interrupt_pin.make_input();
        self.interrupt_pin.set_floating_state(gpio::FloatingState::PullDown);
        self.interrupt_pin.set_client(self);
        self.interrupt_pin.enable_interrupts(gpio::InterruptEdge::RisingEdge);

        // Start setting the recommended settings.
        let recommended_settings = [
            (register::LNA, 0x88),
            (register::RxBW, 0x55),
            (register::AFCBW, 0x8B),
            (register::RSSIThresh, 0xE4),
            (register::TestDAGC, 0x30),
            (register::PreambleLSB, 0xB0),
        ];
        for (addr, val) in recommended_settings {
            self.queue_write(addr, val).unwrap();
        }
        // And put the radio into sleep mode.
        self.queue_mode_change(Mode::Sleep).unwrap();
        self.execute_queue().unwrap();
    }

    fn busy_wait(&self, duration_ms: u32) {
        let t_end = self.time_source.now()
            .wrapping_add(self.time_source.ticks_from_ms(duration_ms));
        loop {
            if self.time_source.now() > t_end { break; }
        }
    }

    fn read(&self, address: u8) -> Result<()> {
        let (rbuf, wbuf) = (self.buffers.0.take().ok_or(RadioError::NoReadBuffer)?,
                            self.buffers.1.take().ok_or(RadioError::NoWriteBuffer)?);
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
        let (rbuf, wbuf) = (self.buffers.0.take().ok_or(RadioError::NoReadBuffer)?,
                            self.buffers.1.take().ok_or(RadioError::NoWriteBuffer)?);
        *wbuf.get_mut(0).unwrap() = 0b1000_0000 | address;
        *wbuf.get_mut(1).unwrap() = val;

        if let Err((error, buf_a, buf_b)) = self.spi.read_write_bytes(wbuf, Some(rbuf), 2) {
            // Consider whatever operation is underway just failed.
            unimplemented!()
        } else {
            Ok(())
        }
    }

    fn execute_queue(&self) -> Result<()> {
        // Find the first non-None operation on the queue and execute it.
        if let Some(o) = self.pending.iter().find(|op| op.get().is_some()) {
            // Validated that this is a Some variant from the find() closure.
            let operation = o.get().unwrap();
            kernel::debug!("E: {:?}", operation);
            match operation {
                Operation::WriteRegister(addr, val) => self.write(addr, val),

                Operation::ModifyRegister(addr, _mask, _val, None) => self.read(addr),

                Operation::ModifyRegister(addr, mask, val, Some(current)) => {
                    assert!(mask != 0);
                    let mut s = 0;
                    while (mask >> s) & 1 != 1 { s += 1; }
                    self.write(addr, (current & (!mask)) | (val << s))
                },

                Operation::FIFOWrite => {
                    let pid = self.configured_for.extract().unwrap();
                    // Copy data from the application into the radio FIFO.
                    let grant_result = self.grants.enter(pid, |_grant, ko_data| {
                        ko_data.get_readwrite_processbuffer(grant_nos::ALLOW_RW_FIFO_BUFFER)?
                            .enter(|ro_buffer| {
                                if ro_buffer.len() > FIFO_LENGTH {
                                    Err(RadioError::System(ErrorCode::INVAL))
                                } else {
                                    let wbuf = self.buffers.1.take().unwrap();
                                    wbuf[0] = 0b1000_0000; // Write to FIFO address.
                                    ro_buffer.copy_to_slice(&mut wbuf[1..1+ro_buffer.len()]);
                                    self.buffers.1.put(Some(wbuf));
                                    Ok(ro_buffer.len())
                                }
                            })
                    }).unwrap();

                    // The grant operations yield a result wrapping the message length
                    // doubly-nested by results.
                    match grant_result {
                        Ok(len_result) => {
                            let data_len = len_result?;
                            // Write the data into the FIFO.
                            // If either of the buffers are missing, there is a bug because
                            // we were just handling the write buffer, and this function gets
                            // called by the read_write_done function, which puts buffers back.
                            let (rbuf, wbuf) = (self.buffers.0.take().unwrap(),
                                                self.buffers.1.take().unwrap());
                            // And this one... produces some complex error management issues
                            // should we handle a failure here. Likely do a callback to the
                            // app to notify it that the transmission failed.
                            // kernel::debug!("Writing {} bytes of FIFO data.", data_len);
                            self.status.set(Status::Transmitting);
                            // +1 for the address of the FIFO before FIFO contents.
                            self.spi.read_write_bytes(wbuf, Some(rbuf), 1+data_len).unwrap();
                        },

                        Err(err) => match err {
                            // If these errors are the cause, the driver stops the system here.
                            kernel::process::Error::KernelError
                                | kernel::process::Error::AlreadyInUse => panic!(),

                            // All other errors should cancel the operation.
                            // Leave the driver in the idle state.
                            kernel::process::Error::AddressOutOfBounds
                                | kernel::process::Error::OutOfMemory
                                | kernel::process::Error::NoSuchApp
                                | kernel::process::Error::InactiveApp => {
                                    // Do not rely on the earlier set.
                                    self.status.set(Status::Idle);
                                    self.fifo_write_pending.set(false);
                                    kernel::debug!("RFM69: grant action failed: {:?}", err);
                                }
                        }
                    };

                    Ok(())
                }

                _ => unimplemented!(),
            }
        } else {
            // Nothing to do.
            Ok(())
        }
    }

    fn queue(&self, operation: Operation) -> Result<()> {
        for i in 0..self.pending.len() {
            if self.pending[i].get().is_none() {
                self.pending[i].set(Some(operation));
                return Ok(());
            }
        }

        Err(RadioError::QueueFull)
    }

    #[inline]
    fn queue_write(&self, address: u8, val: u8) -> Result<()> {
        self.queue(Operation::WriteRegister(address, val))
    }

    #[inline]
    fn queue_modify(&self, address: u8, mask: u8, val: u8) -> Result<()> {
        self.queue(Operation::ModifyRegister(address, mask, val, None))
    }

    #[inline]
    fn queue_mode_change(&self, mode: Mode) -> Result<()> {
        self.queue_modify(register::OpMode, register::mask::OpMode_Mode, u8::from(mode))?;

        Ok(())
    }

    #[inline]
    fn driver_busy(&self) -> bool {
        // Buffers are present.
        let have_buffers = self.buffers.0.is_some() && self.buffers.1.is_some();

        // No pending register operations.
        let pending_queue_empty = self.pending.iter()
            .find(|slot| slot.get().is_some())
            .is_none();

        !have_buffers || !pending_queue_empty
    }

    /// Queue commands to configure the radio for an application.
    fn queue_configuration(&self, pid: ProcessId) -> Result<()> {
        // Make sure the driver is not busy doing anything else at the moment.
        if self.driver_busy() {
            Err(RadioError::Busy)
        } else {
            // Check the current configuration.
            // Apply the application's configuration if the app has updated its configuration
            // or a different app has used the radio since.
            if Some(pid) != self.configured_for.extract() {
                // Update configuration.
                self.grants.enter(pid, |grant, _ko_data| {
                    // Bit rate.
                    self.queue_write(register::BitrateMSB, (grant.bit_rate >> 8) as u8)?;
                    self.queue_write(register::BitrateLSB, (grant.bit_rate & 0xFF) as u8)?;

                    // Packet format.
                    self.queue_modify(
                        register::PacketConfig1,
                        register::mask::PacketConfig1_PacketFormat,
                        // Also update the payload length value if fixed-length.
                        if let PacketFormat::Fixed(p_len) = grant.packet_format {
                            self.queue_write(register::PayloadLength, p_len)?;
                            0 // Evaluate zero for fixed-length in PacketFormat.
                        } else {
                            1 // Evaluate one for variable-length in PacketFormat.
                        })?;

                    // AES encryption.
                    self.queue_modify(
                        register::PacketConfig2,
                        register::mask::PacketConfig2_AESOn,
                        if let Some(ref enc_key) = grant.enc_key {
                            for (byte, offset) in enc_key.iter().copied().zip(0..) {
                                self.queue_write(register::AESKey1 + offset, byte)?;
                            }
                            1 // Evaluate one for AES on.
                        } else {
                            0 // Evaluate zero for AES off.
                        })?;

                    // Sync word.
                    self.queue_modify(
                        register::SyncConfig,
                        register::mask::SyncConfig_SyncOn,
                        if let Some((s_len, word)) = grant.sync_word {
                            self.queue_modify(
                                register::SyncConfig,
                                register::mask::SyncConfig_SyncSize,
                                s_len)?;
                            for offset in 0..(s_len+1) {
                                self.queue_write(
                                    register::SyncValue1 + offset,
                                    ((word >> (8 * offset)) & 0xFF) as u8)?;
                            }

                            1 // Evaluate one for sync on.
                        } else {
                            0 // Evaluate zero for sync off.
                        })?;

                    Ok(())
                }).unwrap()?;

                self.configured_for.set(pid);
            }

            Ok(())
        }
    }

    fn transmit(&self, pid: ProcessId) -> Result<()> {
        self.status.set(Status::Transmitting);
        self.queue_configuration(pid)?;
        // Upon completing the register updates, we need to write to the FIFO afterwards.
        self.queue(Operation::FIFOWrite)?;
        self.fifo_write_pending.set(true);
        self.queue_mode_change(Mode::Transmit)?;
        self.execute_queue()
    }

    fn receive(&self, pid: ProcessId) -> Result<()> {
        self.queue_configuration(pid)?;
        self.receive_for.set(pid);
        self.queue_mode_change(Mode::Receive)?;
        self.execute_queue()
    }

    /// Clear the configured_for value if it matches the given PID.
    fn invalidate_configuration(&self, pid: ProcessId) {
        if let Some(configured_pid) = self.configured_for.extract() {
            if configured_pid == pid {
                self.configured_for.clear();
            }
        }
    }

    fn process_callback(&self) -> Result<()> {
        let current_operation = self.pending.iter()
            .find(|op| op.get().is_some())
            .unwrap(); // There _must_ be an operation in the queue.

        match current_operation.get().unwrap() {
            // Completed writing the requested register to a specific value.
            // The operation is complete, so remove it from the pending queue.
            Operation::WriteRegister(_addr, _val) => {
                current_operation.set(None);
                Ok(())
            },

            // Read phase of the modify operation.
            // Completed reading the current register value.
            // Update the Operation with a current value.
            // The callback will continue execution of the queue.
            Operation::ModifyRegister(addr, mask, val, None) => {
                let current = self.buffers.0.map(|buf| buf[1]).unwrap();
                current_operation.set(Some(Operation::ModifyRegister(addr, mask, val, Some(current))));
                Ok(())
            },

            // Completed modifying the requested register.
            // The operation is complete, so remove it from the queue.
            Operation::ModifyRegister(_addr, _mask, _val, Some(_cur)) => {
                current_operation.set(None);
                Ok(())
            }

            // FIFO write complete.
            // The operation is complete, so remove it from the pending queue.
            Operation::FIFOWrite => {
                current_operation.set(None);
                Ok(())
            },

            // FIFO read complete.
            // The buffer must be copied to the application the driver received for.
            Operation::FIFORead => {
                let rx_pid = self.receive_for.extract().unwrap();
                let rbuf = self.buffers.0.take().unwrap();
                let copy_result = self.grants.enter(rx_pid, |_data, ko_data| {
                    match ko_data.get_readwrite_processbuffer(grant_nos::ALLOW_RW_FIFO_BUFFER) {
                        Ok(ko_buffer) => {
                            // Copy up to either the shared buffer's length or the FIFO size,
                            // whichever buffer is the smaller of the two.
                            let copy_len = core::cmp::min(ko_buffer.len(), FIFO_LENGTH);
                            ko_buffer.mut_enter(|rw_slice| {
                                // Skip the first byte of the read buffer, that is a
                                // useless byte "received" simultaneous to the read command.
                                (rw_slice[..copy_len]).copy_from_slice(&rbuf[1..(1+copy_len)]);
                            }).unwrap(); // Is it possible for the application to die between entering the grant and here?

                            // Schedule an upcall with the application.
                            ko_data.schedule_upcall(grant_nos::SUBSCRIBE_RX_COMPLETE, (copy_len, 0, 0)).unwrap();
                        },

                        Err(err) => {
                            match err {
                                // If these errors are the cause, the driver stops the system here.
                                kernel::process::Error::KernelError
                                    | kernel::process::Error::AlreadyInUse => panic!(),

                                // All other errors should cancel the operation.
                                // Leave the driver in the idle state.
                                kernel::process::Error::AddressOutOfBounds
                                    | kernel::process::Error::OutOfMemory
                                    | kernel::process::Error::NoSuchApp
                                    | kernel::process::Error::InactiveApp => {
                                        // Do not rely on the earlier set.
                                        self.status.set(Status::Idle);
                                        self.fifo_write_pending.set(false);
                                        kernel::debug!("RFM69: grant action failed: {:?}", err);
                                    }
                            }
                        }
                    };
                });
                self.buffers.0.put(Some(rbuf));

                if let Err(err) = copy_result {
                    match err {
                        kernel::process::Error::NoSuchApp => {
                            // This is fine, the application died in the meantime.
                            // Put the driver back into the idle state.
                            self.status.set(Status::Idle);
                            Ok(())
                        },

                        _ => {
                            kernel::debug!("Failed to copy received packet: {:?}", err);
                            Err(RadioError::System(ErrorCode::FAIL))
                        },
                    }
                } else {
                    Ok(())
                }
            },
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
            // Process the callback to finish the operation and start the next operation.
            let res = self.process_callback().and(self.execute_queue());
            // Perform the next step of the operation.
            if let Err(e) = res {
                kernel::debug!("Radio callback processing failed: {:?}, (currently {:?})", e, self.status.get());
            }
        }
    }
}

impl<A: 'static + time::Frequency, B: 'static + time::Ticks> SyscallDriver for RFM69<A, B> {
    fn command(&self, command_no: usize, r2: usize, r3: usize, pid: ProcessId) -> CommandReturn {
        // kernel::debug!("command_no: {:#2X}, r2 = {:#2X}, r3 = {:#2X}", command_no, r2, r3);

        // `config_change` gets set to true when a configuration change happens and
        // configuration may need to be updated on the radio.
        let (result, config_change): (CommandReturn, bool) = match (command_no, r2, r3) {
            // Driver check.
            (0, _, _) => (CommandReturn::success(), false),

            // Send the current buffer as a packet.
            (10, _, _) => {
                // The radio is only available for transmission if either
                // the radio is idle or if it is only receiving on behalf
                // of an application (may be the same application).
                let status = self.status.get();
                let available = status == Status::Idle || status == Status::Receiving;
                if !available {
                    (CommandReturn::failure(ErrorCode::BUSY), false)
                } else {
                    match self.transmit(pid) {
                        Ok(_) => (CommandReturn::success(), false),
                        Err(_e) => (CommandReturn::failure(ErrorCode::FAIL), false),
                    }
                }
            },

            // Set synchronization word length.
            // If R2 is ZERO, disables the sync word.
            (40, sync_length, _) => {
                if 0 == sync_length || sync_length > 7 {
                    (CommandReturn::failure(ErrorCode::INVAL), false)
                } else {
                    self.grants.enter(pid, |data, _ko_data| {
                        if sync_length == 0 {
                            data.sync_word = None;
                            (CommandReturn::success(), true)
                        } else {
                            data.sync_word = Some(
                                ((sync_length - 1) as u8,
                                 data.sync_word.map(|(l, s)| s).unwrap_or(SYNC_WORD_DEFAULT)));
                            (CommandReturn::success(), true)
                        }
                    }).unwrap_or((CommandReturn::failure(ErrorCode::FAIL), false))
                }
            },

            // Set synchronization word.
            // If both parameters are ZERO, disables the sync word.
            (41, sync_msb, sync_lsb) => {
                let new_sync_word: u64 = ((sync_msb as u64) << 32) | sync_lsb as u64;

                self.grants.enter(pid, |data, _ko_data| {
                    if let Some((len, _old_word)) = data.sync_word {
                        data.sync_word = Some((len, new_sync_word));
                        if self.configured_for.map_or(false, |p| pid == *p) {
                            self.configured_for.clear();
                        }

                        (CommandReturn::success(), true)
                    } else {
                        // The sync word was set to None.
                        // The length needs to be set first.
                        (CommandReturn::failure(ErrorCode::INVAL), false)
                    }
                }).unwrap_or((CommandReturn::failure(ErrorCode::FAIL), false))
            },

            // Set the bit rate.
            (42, bit_rate, _) => {
                self.grants.enter(pid, |data, _ko_data| {
                    data.bit_rate = (bit_rate & 0xFFFF) as u16;
                    (CommandReturn::success(), true)
                }).unwrap_or((CommandReturn::failure(ErrorCode::FAIL), false))
            }

            // Set the packet format.
            (45, sel, packet_len) => {
                self.grants.enter(pid, |d, _ko_d| {
                    match (sel, packet_len) {
                        // Fixed length.
                        (0, len) => if len < 1 || 66 < len {
                            (CommandReturn::failure(ErrorCode::INVAL), false)
                        } else {
                            d.packet_format = PacketFormat::Fixed(len as u8);
                            (CommandReturn::success(), true)
                        },

                        // Variable length.
                        (1, _len) => {
                            d.packet_format = PacketFormat::Variable;
                            (CommandReturn::success(), true)
                        },

                        (_, _len) => (CommandReturn::failure(ErrorCode::INVAL), false),
                    }
                }).unwrap_or((CommandReturn::failure(ErrorCode::FAIL), false))
            },

            // Set node address, broadcast address.
            // r2 = node address; set to 256 to disable filtering.
            // r3 = broadcast address; set to 256 to disable broadcast filtering.
            (50, addr, baddr) => {
                self.grants.enter(pid, |d, _ko_d| {
                    if addr == 256 {
                        d.address = None;
                        (CommandReturn::success(), true)
                    } else if addr <= 255 {
                        if baddr <= 255 {
                            d.address = Some((addr as u8, Some(baddr as u8)));
                            (CommandReturn::success(), true)
                        } else if baddr == 256 {
                            d.address = Some((addr as u8, None));
                            (CommandReturn::success(), true)
                        } else {
                            (CommandReturn::failure(ErrorCode::INVAL), false)
                        }
                    } else {
                        (CommandReturn::failure(ErrorCode::INVAL), false)
                    }
                }).unwrap_or((CommandReturn::failure(ErrorCode::INVAL), false))
            },

            // Set encryption key.
            // r2 = byte index (0 to 15).
            // r3 = value
            (60, idx, val) => {
                if idx >= 16 || val > 255 {
                    (CommandReturn::failure(ErrorCode::INVAL), false)
                } else {
                    self.grants.enter(pid, |d, _ko_d| {
                        d.enc_key.get_or_insert([0; 16])[idx] = val as u8;
                        (CommandReturn::success(), true)
                    }).unwrap_or((CommandReturn::failure(ErrorCode::FAIL), false))
                }
            },

            // Clear and disable the encryption key.
            (61, _, _) => {
                self.grants.enter(pid, |d, _ko_d| {
                    d.enc_key = None;
                    (CommandReturn::success(), true)
                }).unwrap_or((CommandReturn::failure(ErrorCode::FAIL), false))
            },

            // Receive packets on behalf of the application.
            (100, _, _) => {
                if let Some(current_rx_pid) = self.receive_for.extract() {
                    if current_rx_pid == pid {
                        // The radio is already receiving packets for the application.
                        (CommandReturn::failure(ErrorCode::ALREADY), false)
                    } else {
                        // The radio is busy receiving packets for another application.
                        (CommandReturn::failure(ErrorCode::BUSY), false)
                    }
                } else {
                    (CommandReturn::failure(ErrorCode::NOSUPPORT), false)
                }
            }

            _ => (CommandReturn::failure(ErrorCode::INVAL), false),
        };

        if config_change {
            self.invalidate_configuration(pid);
        }

        result
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
            // Radio was supposedly idle and it issued an interrupt on DIO0.
            // This means that the radio was _actually_ in either receive or transmit mode.
            // This is a logic bug.
            Status::Idle => panic!(),

            // Radio is in transmit mode.
            // The interrupt means we have completed transmitting a packet.
            // Set the state back to Idle and return to sleep mode.
            Status::Transmitting => {
                let pid = self.configured_for.extract().unwrap();
                // Let the application know the transmission completed.
                self.grants.enter(pid, |_data, ko_data| {
                    ko_data.schedule_upcall(grant_nos::SUBSCRIBE_TX_COMPLETE, (0, 0, 0))
                }).unwrap().unwrap();

                self.status.set(Status::Idle);
                // If the radio was previously listening for another application,
                // then go back into receive mode, otherwise, the radio should sleep.
                if let Some(rx_pid) = self.receive_for.extract() {
                    self.receive(rx_pid);
                } else {
                    self.queue_mode_change(Mode::Sleep).unwrap();
                    self.execute_queue().unwrap();
                }
            },

            // Radio is in receive mode.
            // The interrupt means the radio has received a packet.
            // Start an SPI transaction to read the FIFO.
            Status::Receiving => {
                // If either of these buffers are missing, there is a bug in the logic.
                let (rbuf, wbuf) = (self.buffers.0.take().unwrap(),
                                    self.buffers.1.take().unwrap());
                wbuf[0] = 0b0111_1111 & register::FIFO;

                if let Err((err, wbuf, rbuf)) = self.spi.read_write_bytes(wbuf, Some(rbuf), wbuf.len()) {
                    self.buffers.0.put(Some(wbuf));
                    self.buffers.1.put(rbuf);
                    kernel::debug!("Receiving packet failed: {:?}.", err);
                }
            },
        }
    }
}
