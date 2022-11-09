use kernel;
use kernel::hil;
use kernel::utilities::registers::interfaces::{ReadWriteable, Readable};
use kernel::utilities::registers::{register_bitfields, register_structs, ReadWrite};
use kernel::utilities::{
    cells::{MapCell, OptionalCell},
    StaticRef
};
use kernel::ErrorCode;

register_structs! {
    /// Control and data interface to SAR ADC
    AdcRegisters {
        /// ADC Control and Status
        (0x000 => cs: ReadWrite<u32, CS::Register>),
        /// Result of most recent ADC conversion
        (0x004 => result: ReadWrite<u32, RESULT::Register>),
        /// FIFO control and status
        (0x008 => fcs: ReadWrite<u32, FCS::Register>),
        /// Conversion result FIFO
        (0x00C => fifo: ReadWrite<u32, FIFO::Register>),
        /// Clock divider. If non-zero, CS_START_MANY will start conversions
        /// at regular intervals rather than back-to-back.
        /// The divider is reset when either of these fields are written.
        /// Total period is 1 + INT + FRAC / 256
        (0x010 => div: ReadWrite<u32, DIV::Register>),
        /// Raw Interrupts
        (0x014 => intr: ReadWrite<u32, INTR::Register>),
        /// Interrupt Enable
        (0x018 => inte: ReadWrite<u32, INTE::Register>),
        /// Interrupt Force
        (0x01C => intf: ReadWrite<u32, INTE::Register>),
        /// Interrupt status after masking & forcing
        (0x020 => ints: ReadWrite<u32, INTE::Register>),
        (0x024 => @END),
    }
}
register_bitfields![u32,
CS [
    /// Round-robin sampling. 1 bit per channel. Set all bits to 0 to disable.
    /// Otherwise, the ADC will cycle through each enabled channel in a
    /// The first channel to be sampled will be the one currently indica
    /// AINSEL will be updated after each conversion with the newly-sele
    RROBIN OFFSET(16) NUMBITS(5) [],
    /// Select analog mux input. Updated automatically in round-robin mode.
    AINSEL OFFSET(12) NUMBITS(3) [],
    /// Some past ADC conversion encountered an error. Write 1 to clear.
    ERR_STICKY OFFSET(10) NUMBITS(1) [],
    /// The most recent ADC conversion encountered an error; result is undefined or nois
    ERR OFFSET(9) NUMBITS(1) [],
    /// 1 if the ADC is ready to start a new conversion. Implies any previous conversion
    /// 0 whilst conversion in progress.
    READY OFFSET(8) NUMBITS(1) [],
    /// Continuously perform conversions whilst this bit is 1. A new conversion will sta
    START_MANY OFFSET(3) NUMBITS(1) [],
    /// Start a single conversion. Self-clearing. Ignored if start_many is asserted.
    START_ONCE OFFSET(2) NUMBITS(1) [],
    /// Power on temperature sensor. 1 - enabled. 0 - disabled.
    TS_EN OFFSET(1) NUMBITS(1) [],
    /// Power on ADC and enable its clock.
    /// 1 - enabled. 0 - disabled.
    EN OFFSET(0) NUMBITS(1) []
],
RESULT [

    RESULT OFFSET(0) NUMBITS(12) []
],
FCS [
    /// DREQ/IRQ asserted when level >= threshold
    THRESH OFFSET(24) NUMBITS(4) [],
    /// The number of conversion results currently waiting in the FIFO
    LEVEL OFFSET(16) NUMBITS(4) [],
    /// 1 if the FIFO has been overflowed. Write 1 to clear.
    OVER OFFSET(11) NUMBITS(1) [],
    /// 1 if the FIFO has been underflowed. Write 1 to clear.
    UNDER OFFSET(10) NUMBITS(1) [],

    FULL OFFSET(9) NUMBITS(1) [],

    EMPTY OFFSET(8) NUMBITS(1) [],
    /// If 1: assert DMA requests when FIFO contains data
    DREQ_EN OFFSET(3) NUMBITS(1) [],
    /// If 1: conversion error bit appears in the FIFO alongside the result
    ERR OFFSET(2) NUMBITS(1) [],
    /// If 1: FIFO results are right-shifted to be one byte in size. Enables DMA to byte
    SHIFT OFFSET(1) NUMBITS(1) [],
    /// If 1: write result to the FIFO after each conversion.
    EN OFFSET(0) NUMBITS(1) []
],
FIFO [
    /// 1 if this particular sample experienced a conversion error. Remains in the same
    ERR OFFSET(15) NUMBITS(1) [],

    VAL OFFSET(0) NUMBITS(12) []
],
DIV [
    /// Integer part of clock divisor.
    INT OFFSET(8) NUMBITS(16) [],
    /// Fractional part of clock divisor. First-order delta-sigma.
    FRAC OFFSET(0) NUMBITS(8) []
],
INTR [
    /// Triggered when the sample FIFO reaches a certain level.
    /// This level can be programmed via the FCS_THRESH field.
    FIFO OFFSET(0) NUMBITS(1) []
],
INTE [
    /// Triggered when the sample FIFO reaches a certain level.
    /// This level can be programmed via the FCS_THRESH field.
    FIFO OFFSET(0) NUMBITS(1) []
],
INTF [
    /// Triggered when the sample FIFO reaches a certain level.
    /// This level can be programmed via the FCS_THRESH field.
    FIFO OFFSET(0) NUMBITS(1) []
],
INTS [
    /// Triggered when the sample FIFO reaches a certain level.
    /// This level can be programmed via the FCS_THRESH field.
    FIFO OFFSET(0) NUMBITS(1) []
]
];
const ADC_BASE: StaticRef<AdcRegisters> =
    unsafe { StaticRef::new(0x4004C000 as *const AdcRegisters) };

#[allow(dead_code)]
#[repr(u32)]
#[derive(Copy, Clone, PartialEq)]
pub enum Channel {
    Channel0 = 0b00000,
    Channel1 = 0b00001,
    Channel2 = 0b00010,
    Channel3 = 0b00011,
    Channel4 = 0b00100,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum SamplingType {
    Single,
    Periodic,
}

#[derive(Clone, Copy)]
struct ChannelInfo {
    sampling_type: SamplingType,
    frequency: u32,
    fracn: u32,
    fracd: u32,
}

impl ChannelInfo {
    fn setup(sampling_type: SamplingType,
             frequency: u32,
             fracd: u32,
    ) -> ChannelInfo {
        ChannelInfo {
            sampling_type,
            frequency,
            fracn: 0,
            fracd,
        }
    }
}

pub struct Adc {
    registers: StaticRef<AdcRegisters>,
    channel_info: [MapCell<ChannelInfo>; 5],
    client: OptionalCell<&'static dyn hil::adc::Client>,
}

impl Adc {
    pub const fn new() -> Self {
        Self {
            registers: ADC_BASE,
            channel_info: [
                MapCell::empty(),
                MapCell::empty(),
                MapCell::empty(),
                MapCell::empty(),
                MapCell::empty(),
            ],
            client: OptionalCell::empty(),
        }
    }

    pub fn init(&self) {
        self.registers.cs.modify(CS::EN::SET);
        while !self.registers.cs.is_set(CS::READY) {}
    }

    pub fn disable(&self) {
        self.registers.cs.modify(CS::EN::CLEAR);
    }

    fn enable_interrupt(&self) {
        self.registers.fcs.modify(FCS::EN::SET);
        self.registers.fcs.modify(FCS::THRESH.val(1));
        self.registers.inte.modify(INTE::FIFO::SET);
    }

    fn disable_interrupt(&self) {
        self.registers.inte.modify(INTE::FIFO::CLEAR);
    }

    fn enable_temperature(&self) {
        self.registers.cs.modify(CS::TS_EN::SET);
    }

    pub fn handle_interrupt(&self) {
        // Find out which channel the sample is for, then check its fractional pacing.
        // If it overflows, we report the sample, otherwise, we drop it.
        let channel_no = self.registers.cs.read(CS::AINSEL);
        // Make sure we are still actually sampling for the channel.
        let channel_info = &self.channel_info[channel_no as usize];
        if channel_info.is_some() {
            let stop_sampling = channel_info.map(|channel| {
                // Add to the fractional pacing.
                // If this is a single sample, or if we reach the denominator, we report the sample upwards.
                channel.fracn = channel.fracn + 1;
                let report_sample =
                    channel.fracn == channel.fracd
                    || channel.sampling_type == SamplingType::Single;
                if report_sample {
                    channel.fracn = 0;
                    self.client.map(|c| c.sample_ready(self.sample_with_channel_no(channel_no as u16)));
                } else {
                    self.discard_sample();
                }

                channel.sampling_type == SamplingType::Single
            }).unwrap();

            // No more sampling for this channel if it is a single sample.
            if stop_sampling {
                let new_channel_mask = self.registers.cs.read(CS::RROBIN) ^ (1 << channel_no);
                self.registers.cs.modify(CS::RROBIN.val(new_channel_mask));
                let _disabled_channel = channel_info.take();
                // Stop the ADC if there are not active channels.
                if new_channel_mask == 0 {
                    self.registers.cs.modify(CS::START_MANY::CLEAR);
                }
            }
        } else {
            kernel::debug!("sample ready for unconfigured channel {}", channel_no);
            self.discard_sample();
        }
    }

    /// Read a new sample and stuff the channel no. in the top four bits to avoid changing the trait interface.
    fn sample_with_channel_no(&self, channel_no: u16) -> u16 {
        let sample = self.registers.fifo.read(FIFO::VAL) as u16;
        ((channel_no as u16) << 12)
            | (sample & 0b0000_1111_1111_1111)
    }

    /// Discard the top sample in the FIFO.
    #[inline(always)]
    #[allow(unused_variables)]
    fn discard_sample(&self) {
        let unwanted_sample = self.registers.fifo.read(FIFO::VAL) as u16;
    }

    fn max_requested_frequency(&self) -> u32 {
        self.channel_info.iter()
            .filter(|ci| ci.is_some())
            .map(|ci| ci.map(|c| c.frequency).unwrap())
            .max()
            .unwrap_or(0)
    }

    fn configure_sampling(&self,
                          channel: &Channel,
                          frequency: u32,
                          sampling_type: SamplingType
    ) -> Result<(), ErrorCode> {
        let channel_no = *channel as usize;
        // Cannot sample on the requested channel if it is already sampling.
        if self.channel_info[channel_no].is_some() {
            Err(ErrorCode::BUSY)
        } else if sampling_type == SamplingType::Periodic && frequency == 0 { // Reject 0 sampling frequency.
            Err(ErrorCode::INVAL)
        } else {
            // Cease all sampling.
            self.registers.cs.modify(CS::START_MANY::CLEAR);

            let max_frequency = self.max_requested_frequency();
            // Check if there is a new max sampling frequency.
            // If so, we must reconfigure all other channels and reset fractional pacing.
            // We only need to reconfigure if it is a periodic sampling request.
            let (max_frequency, reconfigure) = if sampling_type != SamplingType::Single && frequency > max_frequency {
                (frequency, true)
            } else {
                (max_frequency, false)
            };

            // Set up the new sampling channel information.
            self.channel_info[channel_no].replace(
                ChannelInfo::setup(sampling_type, frequency, max_frequency));

            // Set up the new sampling.
            // Only periodic sampling affects the sampling frequency.
            // Single samples do not count because they are so ephemeral.
            if reconfigure {
                let active_periodic_channel_count = self.channel_info.iter()
                    .filter(|ci| ci.is_some())
                    .map(|ci| ci.map(|c| if c.sampling_type == SamplingType::Periodic { 1 } else { 0 }).unwrap())
                    .fold(0, |cur, i| cur + i);
                let clock_frequency = 125_000_000;
                let agg_frequency = core::cmp::max(max_frequency * active_periodic_channel_count as u32, 1);
                kernel::debug!("Serving active channels requires sampling at {} hz.", agg_frequency);
                let cycles_per_sample = clock_frequency / agg_frequency;
                let cycles_per_sample = if cycles_per_sample < 95 { 95 } else { cycles_per_sample };
                let cycles_per_sample = if cycles_per_sample > u16::MAX as u32 { u16::MAX as u32 } else { cycles_per_sample };
                kernel::debug!("Required cycles per sample: {} cy.", cycles_per_sample);
                self.registers.div.modify(DIV::INT.val(cycles_per_sample));
                self.registers.fcs.modify(FCS::THRESH.val(1)
                                          + FCS::EN::SET);

                // Reconfigure the rest of the channels.
                let samples_per_sec = clock_frequency / cycles_per_sample
                    / active_periodic_channel_count;
                kernel::debug!("Per-channel approx. rate: {} S/s.", samples_per_sec);
                if reconfigure {
                    let iter = self.channel_info.iter().zip(0..);
                    for (ch, i) in iter {
                        let _ = ch.map(|c| {
                            c.fracn = 0;
                            c.fracd = core::cmp::max(samples_per_sec / c.frequency, 1);
                            kernel::debug!(" - chan. no. {} will take 1 out of every {} smps.", i, c.fracd);
                        });
                    }
                }
            }

            // Enable the specified channels.
            let enabled_mask: u32 = self.channel_info.iter()
                .enumerate()
                .filter(|(_i, ci)| ci.is_some())
                .map(|(i, _ci)| i)
                .fold(0, |cur, i| cur | (1 << i));
            self.registers.cs.modify(CS::RROBIN.val(enabled_mask));
            // Set the first channel to sample to be the one we newly configured.
            self.registers.cs.modify(CS::AINSEL.val(channel_no as u32));

            self.enable_interrupt();
            self.registers.cs.modify(CS::START_MANY::SET);

            Ok(())
        }
    }
}

impl hil::adc::Adc for Adc {
    type Channel = Channel;

    fn sample(&self, channel: &Self::Channel) -> Result<(), ErrorCode> {
        self.configure_sampling(channel, self.max_requested_frequency(), SamplingType::Single)
    }

    fn sample_continuous(
        &self,
        channel: &Self::Channel,
        frequency: u32,
    ) -> Result<(), ErrorCode> {
        self.configure_sampling(channel, frequency, SamplingType::Periodic)
    }

    fn stop_sampling(&self) -> Result<(), ErrorCode> {
        self.disable_interrupt();
        self.registers.cs.modify(CS::START_MANY::CLEAR);
        self.registers.cs.modify(CS::START_ONCE::CLEAR);

        // TODO: add support for cancelling for a single channel through the stack.
        for ch in self.channel_info.iter() {
            let _disabled_channel = ch.take();
        }

        Ok(())
    }

    fn get_resolution_bits(&self) -> usize {
        12
    }

    fn get_voltage_reference_mv(&self) -> Option<usize> {
        Some(3300)
    }

    fn set_client(&self, client: &'static dyn hil::adc::Client) {
        self.client.set(client);
    }
}
