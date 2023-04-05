//! Direct memory access.

use crate::errorcode::ErrorCode;

/// Size of each DMA transfer operation.
#[derive(Copy, Clone)]
#[repr(u32)]
pub enum TransferSize {
    /// One byte.
    Byte = 1,
    /// Two bytes.
    HalfWord = 2,
    /// Four bytes.
    Word = 4,
}

#[derive(Copy, Clone)]
pub enum SourcePeripheral {
    /// Analog-to-digial converter.
    ADC,
}

#[derive(Copy, Clone)]
pub enum TargetPeripheral {
    /// Hardware-dependent peripheral.
    Custom(u8),
}

#[derive(Copy, Clone)]
pub enum TransferKind {
    /// Memory-to-memory transfer (e.g. RAM to RAM, ROM to RAM, etc).
    MemoryToMemory(usize, usize),
    /// Memory-to-peripheral (e.g., RAM to DAC).
    MemoryToPeripheral(usize, TargetPeripheral),
    /// Peripheral-to-memory.
    PeripheralToMemory(SourcePeripheral, usize),
}

/// Configurable parameters for DMA channels.
#[derive(Copy, Clone)]
pub struct Parameters {
    /// Transfer source and target.
    pub kind: TransferKind,
    /// Number of transfers to perform.
    pub transfer_count: usize,
    /// Size of each transfer.
    pub transfer_size: TransferSize,
    /// Increase read address by `transfer_size` after each transfer.
    pub increment_on_read: bool,
    /// Increase write address by `transfer_size` after each transfer.
    pub increment_on_write: bool,
    /// Service this channel before non-high priority channels.
    pub high_priority: bool,
}

pub trait DMA {
    /// Configure and enable a DMA channel.
    fn configure(&'static self,
                 params: &Parameters) -> Result<&'static dyn DMAChannel, ErrorCode>;

    /// Stop and disable a DMA channel.
    fn stop(&'static self, channel_no: usize) -> Result<(), ErrorCode>;
}

pub trait DMAChannel {
    /// Return the channel's number.
    fn channel_no(&self) -> usize;

    /// Start a transfer on an idle DMA channel.
    fn start(&self, buffer: &'static mut [usize]) -> Result<(), ErrorCode>;

    /// Poll to check for a completed DMA transfer.
    fn poll(&self) -> Option<&'static mut [usize]>;

    /// Assign a client interrupt processing will notify when a transfer completes for this DMA channel.
    fn set_client(&self, client: &'static dyn DMAClient);
}

/// DMA-related callbacks.
pub trait DMAClient {
    fn transfer_done(&self, channel: &dyn DMAChannel, buffer: &'static mut [usize]);
}
