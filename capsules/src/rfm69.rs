/*! RFM69 ISM radio.
 *
 * The RFM69 is a flexible radio that operates in the industry, science, and medical (ISM) band.
 * It offers a host of configuration settings, including flexible packet configuration and data encryption.
 * The host communicates with the radio over an SPI interface.
 */

use kernel::ProcessId;
use kernel::grant::{
    AllowRoCount,
    AllowRwCount,
    Grant,
    UpcallCount,
};
use kernel::hil::gpio;
use kernel::hil::spi::SpiMasterDevice;
use kernel::hil::time;
use kernel::hil::time::ConvertTicks as _;
use kernel::syscall::{
    CommandReturn,
    SyscallDriver,
    SyscallReturn,
};

pub const DRIVER_NUM: usize = crate::driver::NUM::Ism as usize;

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
}

impl<A: 'static + time::Frequency, B: 'static + time::Ticks> RFM69<A, B> {
    /// Create a new instance of the driver.
    pub fn new(
        grants: Grant<AppData, UpcallCount<1>, AllowRoCount<0>, AllowRwCount<1>>,
        spi: &'static dyn SpiMasterDevice,
        interrupt_pin: &'static dyn InterruptPin,
        reset_pin: &'static dyn ResetPin,
        time_source: &'static dyn time::Time<Frequency = A, Ticks = B>,
    ) -> RFM69<A, B>
    {
        // Configure pins.
        reset_pin.make_output();
        reset_pin.clear();
        interrupt_pin.make_input();
        interrupt_pin.enable_interrupts(gpio::InterruptEdge::RisingEdge);

        RFM69 {
            grants,
            spi,
            interrupt_pin,
            reset_pin,
            time_source,
        }
    }

    /// Ensure the radio is present and put it to sleep.
    pub fn initialize(&self) {
        // Reset the radio and synchronously wait.
        self.reset_pin.set();
        self.busy_wait(1);
        self.reset_pin.clear();
        self.busy_wait(5);
    }

    #[inline]
    fn busy_wait(&self, duration_ms: u32) {
        let t_end = self.time_source.now()
            .wrapping_add(self.time_source.ticks_from_ms(duration_ms));
        loop {
            if self.time_source.now() > t_end { break; }
        }
    }
}

impl<A: 'static + time::Frequency, B: 'static + time::Ticks> SyscallDriver for RFM69<A, B> {
    fn allocate_grant(&self, pid: ProcessId) -> Result<(), kernel::process::Error> {
        self.grants.enter(pid, |_, _| {  })
    }
}
