use crate::rcc;
use crate::rcc::{PeripheralClock, PeripheralClockType};
use core::cell::Cell;
use kernel::hil;
use kernel::hil::dma::{DMAChannel, DMAClient};
use kernel::hil::time::{Frequency, Time};
use kernel::platform::chip::ClockInterface;
use kernel::utilities::cells::{MapCell, OptionalCell, TakeCell};
use kernel::utilities::registers::interfaces::{ReadWriteable, Readable};
use kernel::utilities::registers::{register_bitfields, ReadOnly, ReadWrite};
use kernel::utilities::StaticRef;
use kernel::ErrorCode;

use crate::dma::DMA;
use crate::tim2::{CCConfig, Tim2};

pub trait EverythingClient: hil::adc::Client + hil::adc::HighSpeedClient {}
impl<C: hil::adc::Client + hil::adc::HighSpeedClient> EverythingClient for C {}

#[repr(C)]
struct AdcRegisters {
    sr: ReadWrite<u32, SR::Register>,
    cr1: ReadWrite<u32, CR1::Register>,
    cr2: ReadWrite<u32, CR2::Register>,
    smpr1: ReadWrite<u32, SMPR1::Register>,
    smpr2: ReadWrite<u32, SMPR2::Register>,
    jofr1: ReadWrite<u32, JOFR::Register>,
    jofr2: ReadWrite<u32, JOFR::Register>,
    jofr3: ReadWrite<u32, JOFR::Register>,
    jofr4: ReadWrite<u32, JOFR::Register>,
    htr: ReadWrite<u32, HTR::Register>,
    ltr: ReadWrite<u32, LTR::Register>,
    sqr1: ReadWrite<u32, SQR1::Register>,
    sqr2: ReadWrite<u32, SQR2::Register>,
    sqr3: ReadWrite<u32, SQR3::Register>,
    jsqr: ReadWrite<u32, JSQR::Register>,
    jdr1: ReadOnly<u32, JDR::Register>,
    jdr2: ReadOnly<u32, JDR::Register>,
    jdr3: ReadOnly<u32, JDR::Register>,
    jdr4: ReadOnly<u32, JDR::Register>,
    dr: ReadOnly<u32, DR::Register>,
}

#[repr(C)]
struct AdcCommonRegisters {
    csr: ReadOnly<u32, CSR::Register>,
    ccr: ReadWrite<u32, CCR::Register>,
    cdr: ReadOnly<u32, CDR::Register>,
}

register_bitfields![u32,
    /// Status register
    SR [
        /// Overrun
        OVR OFFSET(5) NUMBITS(1) [],
        /// Regular channel start flag
        STRT OFFSET(4) NUMBITS(1) [],
        /// Injected channel start flag
        JSTRT OFFSET(3) NUMBITS(1) [],
        /// Injected channel end of conversion
        JEOC OFFSET(2) NUMBITS(1) [],
        /// Regular channel end of conversion
        EOC OFFSET(1) NUMBITS(1) [],
        /// Analog watchdog flag
        AWD OFFSET(0) NUMBITS(1) []
    ],
    /// Control register 1
    CR1 [
        /// Overrun interrupt enable
        OVRIE OFFSET(26) NUMBITS(1) [],
        /// Resolution
        RES OFFSET(24) NUMBITS(2) [],
        /// Analog watchdog enable on regular channels
        AWDEN OFFSET(23) NUMBITS(1) [],
        /// Analog watchdog enable on injected channels
        JAWDEN OFFSET(22) NUMBITS(1) [],
        /// Discontinuous mode channel count
        DISCNUM OFFSET(13) NUMBITS(3) [],
        /// Discontinuous mode on injected channels
        JDISCEN OFFSET(12) NUMBITS(1) [],
        /// Discontinuous mode on regular channels
        DISCEN OFFSET(11) NUMBITS(1) [],
        /// Automatic injected group conversion
        JAUTO OFFSET(10) NUMBITS(1) [],
        /// Enable the watchdog on a single channel in scan mode
        AWDSGL OFFSET(9) NUMBITS(1) [],
        /// Scan mode
        SCAN OFFSET(8) NUMBITS(1) [],
        /// Interrupt enable for injected channels
        JEOCIE OFFSET(7) NUMBITS(1) [],
        /// Analog watchdog interrupt enable
        AWDIE OFFSET(6) NUMBITS(1) [],
        /// Interrupt enable for EOC
        EOCIE OFFSET(5) NUMBITS(1) [],
        /// Analog watchdog channel select bits
        AWDCH OFFSET(0) NUMBITS(4) []
    ],
    /// Control register 2
    CR2 [
        /// Start conversion of regular channels
        SWSTART OFFSET(30) NUMBITS(1) [],
        /// External trigger enable for regular channels
        EXTEN OFFSET(28) NUMBITS(2) [
            DISABLED = 0b00,
            RISING = 0b01,
            FALLING = 0b10,
            BOTH = 0b11,
        ],
        /// External event select for regular group
        EXTSEL OFFSET(24) NUMBITS(4) [
            TIM1_CC1 = 0b0000,
            TIM1_CC2 = 0b0001,
            TIM1_CC3 = 0b0010,

            TIM2_CC2 = 0b0011,
            TIM2_CC3 = 0b0100,
            TIM2_CC4 = 0b0101,
            TIM2_TRGO = 0b0110,

            TIM3_CC1 = 0b0111,
            TIM3_TRGO = 0b1000,

            TIM4_CC4 = 0b1001,

            TIM5_CC1 = 0b1010,
            TIM5_CC2 = 0b1011,
            TIM5_CC3 = 0b1100,

            TIM8_CC1 = 0b1101,
            TIM8_TRGO = 0b1110,

            EXTI_LINE11 = 0b1111,
        ],
        /// Start conversion of injected channels
        JSWSTART OFFSET(22) NUMBITS(1) [],
        /// External trigger enable for injected channels
        JEXTEN OFFSET(20) NUMBITS(2) [],
        /// External event select for injected group
        JEXTSEL OFFSET(16) NUMBITS(4) [],
        /// Data alignment
        ALIGN OFFSET(11) NUMBITS(1) [],
        /// End of conversion selection
        EOCS OFFSET(10) NUMBITS(1) [],
        /// DMA disable selection (for single ADC mode)
        DDS OFFSET(9) NUMBITS(1) [],
        /// Direct memory access mode (for single ADC mode)
        DMA OFFSET(8) NUMBITS(1) [],
        /// Continuous conversion
        CONT OFFSET(1) NUMBITS(1) [],
        /// A/D Converter ON / OFF
        ADON OFFSET(0) NUMBITS(1) []
    ],
    /// Sample time register 1
    SMPR1 [
        /// Channel x sampling time selection
        SMP18 OFFSET(24) NUMBITS(3) [],
        SMP17 OFFSET(21) NUMBITS(3) [],
        SMP16 OFFSET(18) NUMBITS(3) [],
        SMP15 OFFSET(15) NUMBITS(3) [],
        SMP14 OFFSET(12) NUMBITS(3) [],
        SMP13 OFFSET(9) NUMBITS(3) [],
        SMP12 OFFSET(6) NUMBITS(3) [],
        SMP11 OFFSET(3) NUMBITS(3) [],
        SMP10 OFFSET(0) NUMBITS(3) []
    ],
    /// Sample time register 2
    SMPR2 [
        /// Channel x sampling time selection
        SMP9 OFFSET(27) NUMBITS(3) [],
        SMP8 OFFSET(24) NUMBITS(3) [],
        SMP7 OFFSET(21) NUMBITS(3) [],
        SMP6 OFFSET(18) NUMBITS(3) [],
        SMP5 OFFSET(15) NUMBITS(3) [],
        SMP4 OFFSET(12) NUMBITS(3) [],
        SMP3 OFFSET(9) NUMBITS(3) [],
        SMP2 OFFSET(6) NUMBITS(3) [],
        SMP1 OFFSET(3) NUMBITS(3) [],
        SMP0 OFFSET(0) NUMBITS(3) []
    ],
    /// injected channel data offsetregister x
    JOFR [
        /// Data offsetfor injected channel x
        JOFFSET OFFSET(0) NUMBITS(12) []
    ],
    /// Watchdog higher threshold register
    HTR [
        /// Analog watchdog higher threshold
        HT OFFSET(0) NUMBITS(12) []
    ],
    /// Watchdog lower threshold register
    LTR [
        /// Analog watchdog lower threshold
        LT OFFSET(0) NUMBITS(12) []
    ],
    /// Regular sequence register 1
    SQR1 [
        /// Regular channel sequence length
        L OFFSET(20) NUMBITS(3) [],
        /// 16th conversion in regular sequence
        SQ16 OFFSET(15) NUMBITS(5) [],
        /// 15th conversion in regular sequence
        SQ15 OFFSET(10) NUMBITS(5) [],
        /// 14th conversion in regular sequence
        SQ14 OFFSET(5) NUMBITS(5) [],
        /// 13th conversion in regular sequence
        SQ13 OFFSET(0) NUMBITS(5) []
    ],
    /// Regular sequence register 2
    SQR2 [
        /// 12th conversion in regular sequence
        SQ12 OFFSET(25) NUMBITS(5) [],
        /// 11th conversion in regular sequence
        SQ11 OFFSET(20) NUMBITS(5) [],
        /// 10th conversion in regular sequence
        SQ10 OFFSET(15) NUMBITS(5) [],
        /// 9th conversion in regular sequence
        SQ9 OFFSET(10) NUMBITS(5) [],
        /// 8th conversion in regular sequence
        SQ8 OFFSET(5) NUMBITS(5) [],
        /// 7th conversion in regular sequence
        SQ7 OFFSET(0) NUMBITS(5) []
    ],
    /// Regular sequence register 3
    SQR3 [
        /// 6th conversion in regular sequence
        SQ6 OFFSET(25) NUMBITS(5) [],
        /// 5th conversion in regular sequence
        SQ5 OFFSET(20) NUMBITS(5) [],
        /// 4th conversion in regular sequence
        SQ4 OFFSET(15) NUMBITS(5) [],
        /// 3rd conversion in regular sequence
        SQ3 OFFSET(10) NUMBITS(5) [],
        /// 2nd conversion in regular sequence
        SQ2 OFFSET(5) NUMBITS(5) [],
        /// 1st conversion in regular sequence
        SQ1 OFFSET(0) NUMBITS(5) []
    ],
    /// Injected sequence register
    JSQR [
        /// Note:  When JL[1:0]=3 (4 injected conversions in the sequencer), the ADC converts the channels
        ///      in the following order: JSQ1[4:0], JSQ2[4:0], JSQ3[4:0], and JSQ4[4:0].
        ///      When JL=2 (3 injected conversions in the sequencer), the ADC converts the channels in the
        ///      following order: JSQ2[4:0], JSQ3[4:0], and JSQ4[4:0].
        ///      When JL=1 (2 injected conversions in the sequencer), the ADC converts the channels in
        ///      starting from JSQ3[4:0], and then JSQ4[4:0].
        ///      When JL=0 (1 injected conversion in the sequencer), the ADC converts only JSQ4[4:0]
        ///      channel.
        /// Injected sequence length
        JL OFFSET(20) NUMBITS(2) [],
        /// 4th conversion in injected sequence
        JSQ4 OFFSET(15) NUMBITS(5) [],
        /// 3rd conversion in injected sequence
        JSQ3 OFFSET(15) NUMBITS(5) [],
        /// 2nd conversion in injected sequence
        JSQ2 OFFSET(15) NUMBITS(5) [],
        /// 1st conversion in injected sequence
        JSQ1 OFFSET(15) NUMBITS(5) []
    ],
    /// Injected data register x
    JDR [
        /// Injected data
        JDATA OFFSET(0) NUMBITS(16) []
    ],
    /// Regular data register
    DR [
        /// Regular data
        DATA OFFSET(0) NUMBITS(16) []
    ],
    /// Common status register
    CSR [
        /// Overrun flag of ADC1
        OVR1 OFFSET(5) NUMBITS(1) [],
        /// Regular channel Start flag of ADC1
        STRT1 OFFSET(4) NUMBITS(1) [],
        /// Injected channel Start flag of ADC1
        JSTRT1 OFFSET(3) NUMBITS(1) [],
        /// Injected channel end of conversion of ADC1
        JEOC1 OFFSET(2) NUMBITS(1) [],
        /// End of conversion of ADC1
        EOC1 OFFSET(1) NUMBITS(1) [],
        /// Analog watchdog flag of ADC1
        AWD1 OFFSET(0) NUMBITS(1) []
    ],
    /// Common control register
    CCR [
        /// Temperature sensor and VREFINT enable
        TSVREFE OFFSET(23) NUMBITS(1) [],
        /// VBAT enable
        VBATE OFFSET(22) NUMBITS(1) [],
        /// ADC prescaler
        ADCPRE OFFSET(16) NUMBITS(2) [
            PCLKDIV2 = 0b00,
            PCLKDIV4 = 0b01,
            PCLKDIV6 = 0b10,
            PCLKDIV8 = 0b11,
        ]
    ],

    /// Common regular data register
    CDR [
        OVR3 OFFSET(21) NUMBITS(1) [],
        STRT3 OFFSET(20) NUMBITS(1) [],
        JSTRT3 OFFSET(19) NUMBITS(1) [],
        JEOC3 OFFSET(18) NUMBITS(1) [],
        EOC3 OFFSET(17) NUMBITS(1) [],
        AWD3 OFFSET(16) NUMBITS(1) [],

        OVR2 OFFSET(13) NUMBITS(1) [],
        STRT2 OFFSET(12) NUMBITS(1) [],
        JSTRT2 OFFSET(11) NUMBITS(1) [],
        JEOC2 OFFSET(10) NUMBITS(1) [],
        EOC2 OFFSET(9) NUMBITS(1) [],
        AWD2 OFFSET(8) NUMBITS(1) [],

        OVR1 OFFSET(5) NUMBITS(1) [],
        STRT1 OFFSET(4) NUMBITS(1) [],
        JSTRT1 OFFSET(3) NUMBITS(1) [],
        JEOC1 OFFSET(2) NUMBITS(1) [],
        EOC1 OFFSET(1) NUMBITS(1) [],
        AWD1 OFFSET(0) NUMBITS(1) [],
    ],
];

const ADC1_BASE: StaticRef<AdcRegisters> =
    unsafe { StaticRef::new(0x4001_2000 as *const AdcRegisters) };

const ADC2_BASE: StaticRef<AdcRegisters> =
    unsafe { StaticRef::new(0x4001_2100 as *const AdcRegisters) };

const ADC3_BASE: StaticRef<AdcRegisters> =
    unsafe { StaticRef::new(0x4001_2200 as *const AdcRegisters) };

const ADC_COMMON_BASE: StaticRef<AdcCommonRegisters> =
    unsafe { StaticRef::new(0x4001_2300 as *const AdcCommonRegisters) };

/// Channel sampling time.
///
/// It is possible for each sample to spend different amounts of time sampling.
/// This is configurable through the ADC_SMPR1 and ADC_SMPR2 registers.
/// The registers have fields for each channel.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
enum SamplingTime {
    Cycles3   = 0b000,
    Cycles15  = 0b001,
    Cycles28  = 0b010,
    Cycles56  = 0b011,
    Cycles84  = 0b100,
    Cycles112 = 0b101,
    Cycles144 = 0b110,
    Cycles480 = 0b111,
}

#[allow(dead_code)]
#[repr(u32)]
#[derive(Copy, Clone, PartialEq)]
pub enum Channel {
    Channel0 = 0b00000,
    Channel1 = 0b00001,
    Channel2 = 0b00010,
    Channel3 = 0b00011,
    Channel4 = 0b00100,
    Channel5 = 0b00101,
    Channel6 = 0b00110,
    Channel7 = 0b00111,
    Channel8 = 0b01000,
    Channel9 = 0b01001,
    Channel10 = 0b01010,
    Channel11 = 0b01011,
    Channel12 = 0b01100,
    Channel13 = 0b01101,
    Channel14 = 0b01110,
    Channel15 = 0b01111,
    Channel16 = 0b10000,
    Channel17 = 0b10001,
    Channel18 = 0b10010,
}

#[allow(dead_code)]
#[repr(u32)]
enum DataResolution {
    Bit12 = 0b00,
    Bit10 = 0b01,
    Bit8 = 0b10,
    Bit6 = 0b11,
}

#[derive(Copy, Clone, Debug, PartialEq)]
enum ADCStatus {
    Off,
    Idle,
    OneSample,
    Continuous(u8),
    HighSpeed(u8),
}

struct SubADC<'a> {
    clock: AdcClock<'a>,
    registers: StaticRef<AdcRegisters>,
    status: Cell<ADCStatus>,
    cc_config: MapCell<CCConfig>,
    sample_ticks: OptionalCell<usize>,
    dma_stream: OptionalCell<&'static dyn DMAChannel>,
    buffers: (TakeCell<'static, [u16]>, TakeCell<'static, [u16]>),
}

impl<'a> SubADC<'a> {
    const fn new(clock: AdcClock<'a>,
                 registers: StaticRef<AdcRegisters>) -> SubADC {
        SubADC {
            clock,
            registers,
            status: Cell::new(ADCStatus::Off),
            cc_config: MapCell::empty(),
            sample_ticks: OptionalCell::empty(),
            dma_stream: OptionalCell::empty(),
            buffers: (TakeCell::empty(), TakeCell::empty()),
        }
    }

    pub fn enable(&self) {
        // kernel::debug!("powering ADC...");
        if !self.clock.is_enabled() {
            self.clock.enable();
        }
        self.registers.cr2.modify(CR2::ADON::SET);
        while self.registers.cr2.read(CR2::ADON) != 1 {  }
        self.status.set(ADCStatus::Idle);
    }

    pub fn disable(&self) {
        kernel::debug!("disabling ADC...");
        if self.clock.is_enabled() {
            self.clock.disable();
        }
        self.registers.cr2.modify(CR2::ADON::CLEAR);
        while self.registers.cr2.read(CR2::ADON) == 1 {  }
        self.status.set(ADCStatus::Off);
    }

    #[inline]
    fn is_available(&self) -> bool {
        let status = self.status.get();
        status == ADCStatus::Off || status == ADCStatus::Idle
    }

    fn reset(&self) {
        if let Some(f) = self.sample_ticks.extract() {
            self.cc_config.map(|ccc| ccc.schedule_in(f as u32));
        }
    }
}

pub struct Adc<'a> {
    adcs: [MapCell<SubADC<'a>>; 3],
    common_registers: StaticRef<AdcCommonRegisters>,
    dma: OptionalCell<&'a DMA<'a>>,
    client: OptionalCell<&'static dyn hil::adc::Client>,
    timer: OptionalCell<&'a Tim2<'a>>,
}

impl<'a> Adc<'a> {
    pub const fn new(rcc: &'a rcc::Rcc) -> Adc<'a> {
        Adc {
            adcs: [MapCell::new(SubADC::new(AdcClock(PeripheralClock::new(PeripheralClockType::APB2(rcc::PCLK2::ADC1), rcc)), ADC1_BASE)),
                   MapCell::new(SubADC::new(AdcClock(PeripheralClock::new(PeripheralClockType::APB2(rcc::PCLK2::ADC2), rcc)), ADC2_BASE)),
                   MapCell::new(SubADC::new(AdcClock(PeripheralClock::new(PeripheralClockType::APB2(rcc::PCLK2::ADC3), rcc)), ADC3_BASE))],
            common_registers: ADC_COMMON_BASE,
            dma: OptionalCell::empty(),
            client: OptionalCell::empty(),
            timer: OptionalCell::empty(),
        }
    }

    pub fn configure(&self, timer: &'a Tim2<'a>, dma: &'a DMA<'a>) {
        self.common_registers.ccr.modify(CCR::ADCPRE::PCLKDIV8);
        self.timer.set(timer);
        self.dma.set(dma);
    }

    pub fn handle_interrupt(&self) {
        // kernel::debug!("bh: ADC interrupt");
        // Find out which ADC this was for.
        // Read the common status to get status of all ADCs in just one read.
        let common_status = self.common_registers.csr.get();
        // kernel::debug!("bh: common status: {:X}", common_status);
        // kernel::debug!("bh: adc2 cr1: {:X}, cr2: {:X}",
        //                self.adcs[1].map(|adc| adc.registers.cr1.get()).unwrap(),
        //                self.adcs[1].map(|adc| adc.registers.cr2.get()).unwrap());
        for adc_no in 0..2 {
            // Check each's EOC bit.
            if ((common_status >> (1 + (8 * adc_no))) & 1) == 1 {
                // kernel::debug!("bh: it is for ADC {}", adc_no);
                let (channel_no, sample) = self.adcs[adc_no].map(|adc| {
                    if adc.status.get() == ADCStatus::OneSample {
                        adc.registers.cr1.modify(CR1::EOCIE::CLEAR);
                        adc.status.set(ADCStatus::Idle);
                        adc.registers.cr2.modify(CR2::ADON::CLEAR);
                        adc.disable();
                        adc.status.set(ADCStatus::Off);
                    }

                    let source_channel = adc.registers.sqr3.read(SQR3::SQ1);
                    // Reading the DR register clears the status register EOC bit.
                    let sample = adc.registers.dr.read(DR::DATA);

                    // Reschedule the next sample for continuous sampling.
                    adc.reset();

                    (source_channel, sample)
                }).unwrap();

                // There is currently no parameter that would provide the ADC channel.
                // Instead, employ a hack to encode the source ADC channel with the callback to the driver.
                // We use the top four bits of the u16 to hold the channel no.
                let sample_with_channel: u16 = ((channel_no as u16) << 12) | ((sample as u16) & 0x0FFF);
                self.client.map(|c| c.sample_ready(sample_with_channel));
            }
        }
    }

    pub fn enable_temperature(&self) {
        self.common_registers.ccr.modify(CCR::TSVREFE::SET);
    }

    /// Find an inactive ADC component that can sample.
    ///
    /// Inspects all internal ADCs and returns the first inactive one.
    /// Returns None if no ADC is free.
    fn inactive_adc(&self) -> Option<(&MapCell<SubADC<'a>>, u8)> {
        self.adcs.iter()
            .zip(1..)
            .find(|(mc_adc, _adc_no)| mc_adc.map(|adc| adc.is_available()).unwrap())
    }
}

struct AdcClock<'a>(PeripheralClock<'a>);

impl ClockInterface for AdcClock<'_> {
    fn is_enabled(&self) -> bool {
        self.0.is_enabled()
    }

    fn enable(&self) {
        self.0.enable();
    }

    fn disable(&self) {
        self.0.disable();
    }
}

impl hil::adc::Adc for Adc<'_> {
    type Channel = Channel;

    fn sample(&self, channel: &Self::Channel) -> Result<(), ErrorCode> {
        // Find an off/idle ADC.
        if let Some((mc_adc, _adc_no)) = self.inactive_adc() {
            mc_adc.map(|adc| {
                if adc.status.get() == ADCStatus::Off {
                    adc.enable();
                }

                adc.status.set(ADCStatus::OneSample);
                // adc.registers.smpr2.modify(SMPR2::SMP0.val(0b110));
                adc.registers.sqr1.modify(SQR1::L.val(0));
                adc.registers.sqr3.modify(SQR3::SQ1.val(*channel as u32));
                adc.registers.cr1.modify(CR1::EOCIE::SET);
                adc.registers.cr2.modify(CR2::SWSTART::SET);
            }).unwrap();

            Ok(())
        } else {
            Err(ErrorCode::BUSY)
        }
    }

    fn sample_continuous(
        &self,
        channel: &Self::Channel,
        frequency: u32,
    ) -> Result<(), ErrorCode> {
        // Cannot sample faster than the timer's frequency.
        if frequency > <Tim2<'_> as Time>::Frequency::frequency() {
            return Err(ErrorCode::INVAL);
        }

        // Find an off/idle ADC.
        if let Some((mc_adc, _adc_no)) = self.inactive_adc() {
            mc_adc.map(|adc| {
                if adc.status.get() == ADCStatus::Off {
                    adc.enable();
                }

                adc.status.set(ADCStatus::Continuous(*channel as u32 as u8));
                // adc.registers.smpr2.modify(SMPR2::SMP0.val(0b001));
                adc.registers.sqr1.modify(SQR1::L.val(0));
                adc.registers.sqr3.modify(SQR3::SQ1.val(*channel as u32));
                adc.registers.cr1.modify(CR1::EOCIE::SET);

                // Start a new conversion as soon as the previous one finishes.
                // This produces samples at a _very_ fast rate---faster than Tock can keep up.
                // adc.registers.cr2.modify(CR2::CONT::SET);
                // adc.registers.cr2.modify(CR2::SWSTART::SET);

                // Use the timer to trigger conversions close to a specific frequency.
                let cc_config = self.timer
                    .expect("no timer set")
                    .allocate_channel()
                    .unwrap();
                kernel::debug!("allocated timer CC channel {}", cc_config.channel_no());
                adc.registers.cr2.modify(match cc_config.channel_no() {
                    2 => CR2::EXTSEL::TIM2_CC2,
                    3 => CR2::EXTSEL::TIM2_CC3,
                    4 => CR2::EXTSEL::TIM2_CC4,
                    // There are only specific channels that we can use to perform periodic sampling.
                    // There must be some way to state the channels that are capable of doing this.
                    // But, for the sake of science, we make shortcut here and just throw an error
                    // if we cannot get Timer2's channels 2, 3, or 4.
                    _ => unimplemented!(),
                });
                let ticks_per_sample = <Tim2<'_> as Time>::Frequency::frequency() / frequency;
                cc_config.output_compare(ticks_per_sample);
                adc.cc_config.put(cc_config);
                adc.sample_ticks.set(ticks_per_sample as usize);
                adc.registers.cr2.modify(CR2::EXTEN::BOTH);

                // kernel::debug!("CR1: {:X}", adc.registers.cr1.get());
                // kernel::debug!("CR2: {:X}", adc.registers.cr2.get());
            }).unwrap();

            Ok(())
        } else {
            Err(ErrorCode::BUSY)
        }
    }

    fn stop_sampling(&self) -> Result<(), ErrorCode> {
        Err(ErrorCode::NOSUPPORT)
    }

    fn stop_sampling_channel(&self, channel_no: usize) -> Result<(), ErrorCode> {
        let sampling_adc = self.adcs.iter()
            .inspect(|adc| kernel::debug!("adc: {:?}", adc.map(|adc| adc.status.get())))
            .find(|mc_adc| {
                mc_adc.map(|adc| match adc.status.get() {
                    ADCStatus::Continuous(currently_sampling) => currently_sampling as usize == channel_no,
                    ADCStatus::HighSpeed(currently_sampling) => currently_sampling as usize == channel_no,
                    _ => false
                }).unwrap()
            });

        if let Some(sampling_adc) = sampling_adc {
            sampling_adc.map(|adc| {
                adc.registers.cr1.modify(CR1::EOCIE::CLEAR);
                // We do not use the continuous conversion to periodically sample.
                adc.registers.cr2.modify(CR2::CONT::CLEAR);
                adc.registers.cr2.modify(CR2::ADON::CLEAR);
                adc.status.set(ADCStatus::Off);
                adc.registers.cr2.modify(CR2::EXTEN::DISABLED);
                adc.sample_ticks.clear();

                if let Some(cc_config) = adc.cc_config.take() {
                    self.timer.map(|t| (*t).deallocate_channel(&cc_config));
                }

                if let Some(dma_channel) = adc.dma_stream.extract() {
                    dma_channel.done();
                }

                Ok(())
            }).unwrap()
        } else {
            Err(ErrorCode::INVAL)
        }
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

/// Not yet supported
impl hil::adc::AdcHighSpeed for Adc<'static> {
    /// Capture buffered samples from the ADC continuously at a given
    /// frequency, calling the client whenever a buffer fills up. The client is
    /// then expected to either stop sampling or provide an additional buffer
    /// to sample into. Note that due to hardware constraints the maximum
    /// frequency range of the ADC is from 187 kHz to 23 Hz (although its
    /// precision is limited at higher frequencies due to aliasing).
    ///
    /// - `channel`: the ADC channel to sample
    /// - `frequency`: frequency to sample at
    /// - `buffer1`: first buffer to fill with samples
    /// - `length1`: number of samples to collect (up to buffer length)
    /// - `buffer2`: second buffer to fill once the first is full
    /// - `length2`: number of samples to collect (up to buffer length)
    fn sample_highspeed(
        &self,
        channel: &Self::Channel,
        frequency: u32,
        buffer1: &'static mut [u16],
        length1: usize,
        buffer2: &'static mut [u16],
        length2: usize,
    ) -> Result<(), (ErrorCode, &'static mut [u16], &'static mut [u16])> {
        if let Some((mc_adc, adc_no)) = self.inactive_adc() {
            use hil::dma::{
                DMA as _,
                Parameters,
                SourcePeripheral,
                TransferKind,
                TransferSize
            };
            kernel::debug!("using adc {}", adc_no);

            if let Some(dma) = self.dma.extract() {
                let stream = dma.configure(&Parameters {
                    kind: TransferKind::PeripheralToMemory(SourcePeripheral::ADC, adc_no),
                    transfer_count: length1,
                    transfer_size: TransferSize::HalfWord,
                    increment_on_read: false,
                    increment_on_write: true,
                    high_priority: true,
                }).unwrap(); // Need to fix to return buffers, but get lifetime compile error.

                mc_adc.map(move |adc| {
                    if adc.status.get() == ADCStatus::Off {
                        adc.enable();
                    }

                    // Gross.
                    let dma_buffer1 = unsafe {
                        core::slice::from_raw_parts_mut(buffer1.as_mut_ptr() as *mut usize, buffer1.len() / 2)
                    };
                    stream.start(None, Some(dma_buffer1));

                    adc.dma_stream.set(stream);
                    adc.buffers.1.put(Some(buffer2));

                    adc.status.set(ADCStatus::HighSpeed(*channel as u8));
                    adc.registers.sqr1.modify(SQR1::L.val(0));
                    adc.registers.sqr3.modify(SQR3::SQ1.val(*channel as u32));
                    adc.registers.smpr2.modify(SMPR2::SMP0.val(0b001));
                    adc.registers.cr2.modify(CR2::DMA::SET);
                    adc.registers.cr2.modify(CR2::DDS::SET);
                    adc.registers.cr2.modify(CR2::CONT::SET);

                    adc.registers.cr2.modify(CR2::SWSTART::SET);

                    Ok(())
                }).unwrap()
            } else {
                Err((ErrorCode::NOSUPPORT, buffer1, buffer2))
            }
        } else {
            Err((ErrorCode::NOSUPPORT, buffer1, buffer2))
        }
    }

    /// Provide a new buffer to send on-going buffered continuous samples to.
    /// This is expected to be called after the `samples_ready` callback.
    ///
    /// - `buf`: buffer to fill with samples
    /// - `length`: number of samples to collect (up to buffer length)
    fn provide_buffer(
        &self,
        buf: &'static mut [u16],
        _length: usize,
    ) -> Result<(), (ErrorCode, &'static mut [u16])> {
        Err((ErrorCode::NOSUPPORT, buf))
    }

    /// Reclaim buffers after the ADC is stopped.
    /// This is expected to be called after `stop_sampling`.
    fn retrieve_buffers(
        &self,
    ) -> Result<(Option<&'static mut [u16]>, Option<&'static mut [u16]>), ErrorCode> {
        Err(ErrorCode::NOSUPPORT)
    }
}
