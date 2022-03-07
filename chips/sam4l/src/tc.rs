//! 16-bit timer counter (TC)

use kernel::debug;
use kernel::errorcode::ErrorCode;
use kernel::hil;
use kernel::utilities::cells::OptionalCell;
use kernel::utilities::registers::interfaces::{
    Readable,
    Writeable
};
use kernel::utilities::registers::{
    register_bitfields,
    register_structs,
    ReadOnly,
    ReadWrite,
    WriteOnly
};
use kernel::utilities::StaticRef;

use crate::pm;

register_structs! {
    ChannelRegisters {
        (0x00 => ccr: WriteOnly<u32, CCR::Register>),
        (0x04 => cmr: ReadWrite<u32, CMR::Register>),
        (0x08 => smcr: ReadWrite<u32, SMCR::Register>),
        (0x0c => _reserved0: u32),
        (0x10 => cv: ReadOnly<u32, CV::Register>),
        (0x14 => ra: ReadWrite<u32, Rx::Register>),
        (0x18 => rb: ReadWrite<u32, Rx::Register>),
        (0x1c => rc: ReadWrite<u32, Rx::Register>),
        (0x20 => sr: ReadOnly<u32, SR::Register>),
        (0x24 => ier: WriteOnly<u32, IER::Register>),
        (0x28 => idr: WriteOnly<u32, IDR::Register>),
        (0x2c => imr: ReadOnly<u32, IMR::Register>),

        (0x30 => @END),
    },

    /// TC block registers
    BlockRegisters {
        (0x00 => channel0: ChannelRegisters),
        (0x30 => _reserved0: [u32; 4]),
        (0x40 => channel1: ChannelRegisters),
        (0x70 => _reserved1: [u32; 4]),
        (0x80 => channel2: ChannelRegisters),
        (0xb0 => _reserved2: [u32; 4]),

        (0xc0 => bcr: WriteOnly<u32, BCR::Register>),
        (0xc4 => bmr: ReadWrite<u32, BMR::Register>),

        (0xc8 => @END),
    }
}

register_bitfields![
    u32,
    CCR [
        SWTRG OFFSET(2) NUMBITS(1) [
            ResetAndStart = 1
        ],

        CLKDIS OFFSET(1) NUMBITS(1) [
            Disable = 1
        ],

        CLKEN OFFSET(0) NUMBITS(1) [
            Enable = 1
        ],
    ],

    CMR [
        LDRB OFFSET(18) NUMBITS(2) [
            None = 0,
            TIOARisingEdge = 1,
            TIOAFallingEdge = 2,
            TIOAEachEdge = 3
        ],

        LDRA OFFSET(16) NUMBITS(2) [
            None = 0,
            TIOARisingEdge = 1,
            TIOAFallingEdge = 2,
            TIOAEachEdge = 3
        ],

        WAVE OFFSET(15) NUMBITS(1) [
            Capture = 0,
            Waveform = 1
        ],

        CPCTRG OFFSET(14) NUMBITS(1) [
            None = 0,
            ResetAndStartOnMatch = 1
        ],

        ABETRG OFFSET(10) NUMBITS(1) [
            TIOB = 0,
            TIOA = 1
        ],

        ETRGEDG OFFSET(8) NUMBITS(2) [
            None = 0,
            Rising = 1,
            Falling = 2,
            Each = 3
        ],

        LDBDIS OFFSET(7) NUMBITS(1) [
            None = 0,
            DisableOnLoad = 1
        ],

        LDBSTOP OFFSET(6) NUMBITS(1) [
            None = 0,
            StopOnLoad = 1
        ],

        BURST OFFSET(4) NUMBITS(2) [
            NoGating = 0,
            ANDXC0 = 1,
            ANDXC1 = 2,
            ANDXC2 = 3
        ],

        CLKI OFFSET(3) NUMBITS(1) [
            IncrementOnRisingEdge = 0,
            IncrementOnFallingEdge = 1
        ],

        TCCLKS OFFSET(0) NUMBITS(3) [
            TimerClock1 = 0,
            TimerClock2 = 1,
            TimerClock3 = 2,
            TimerClock4 = 3,
            TimerClock5 = 4,
            XC0 = 5,
            XC1 = 6,
            XC2 = 7
        ]
    ],

    SMCR [
        DOWN OFFSET(1) NUMBITS(1),
        GCEN OFFSET(0) NUMBITS(1)
    ],

    CV [
        VALUE OFFSET(0) NUMBITS(16)
    ],

    Rx [
        VALUE OFFSET(0) NUMBITS(16)
    ],

    SR [
        MTIOB OFFSET(18) NUMBITS(1),
        MTIOA OFFSET(17) NUMBITS(1),
        CLKSTA OFFSET(16) NUMBITS(1),

        ETRGS OFFSET(7) NUMBITS(1),
        LDRBS OFFSET(6) NUMBITS(1),
        LDRAS OFFSET(5) NUMBITS(1),
        CPCS OFFSET(4) NUMBITS(1),
        CPBS OFFSET(3) NUMBITS(1),
        CPAS OFFSET(2) NUMBITS(1),
        LOVRS OFFSET(1) NUMBITS(1),
        COVFS OFFSET(0) NUMBITS(1)
    ],

    IER [
        ETRGS OFFSET(7) NUMBITS(1),
        LDRBS OFFSET(6) NUMBITS(1),
        LDRAS OFFSET(5) NUMBITS(1),
        CPCS OFFSET(4) NUMBITS(1),
        CPBS OFFSET(3) NUMBITS(1),
        CPAS OFFSET(2) NUMBITS(1),
        LOVRS OFFSET(1) NUMBITS(1),
        COVFS OFFSET(0) NUMBITS(1)
    ],

    IDR [
        ETRGS OFFSET(7) NUMBITS(1),
        LDRBS OFFSET(6) NUMBITS(1),
        LDRAS OFFSET(5) NUMBITS(1),
        CPCS OFFSET(4) NUMBITS(1),
        CPBS OFFSET(3) NUMBITS(1),
        CPAS OFFSET(2) NUMBITS(1),
        LOVRS OFFSET(1) NUMBITS(1),
        COVFS OFFSET(0) NUMBITS(1)
    ],

    IMR [
        ETRGS OFFSET(7) NUMBITS(1),
        LDRBS OFFSET(6) NUMBITS(1),
        LDRAS OFFSET(5) NUMBITS(1),
        CPCS OFFSET(4) NUMBITS(1),
        CPBS OFFSET(3) NUMBITS(1),
        CPAS OFFSET(2) NUMBITS(1),
        LOVRS OFFSET(1) NUMBITS(1),
        COVFS OFFSET(0) NUMBITS(1)
    ],

    BCR [
        SYNC OFFSET(0) NUMBITS(1)
    ],

    BMR [
        TC0XC0S OFFSET(0) NUMBITS(2),
        TC1XC1S OFFSET(0) NUMBITS(2),
        TC2XC2S OFFSET(0) NUMBITS(2)
    ]
];

const TC0_BASE_ADDRESS: usize = 0x4001_0000;
const TC1_BASE_ADDRESS: usize = 0x4001_4000;

const TC0_REGISTERS: StaticRef<BlockRegisters> =
    unsafe { StaticRef::new(TC0_BASE_ADDRESS as *const BlockRegisters) };
const TC1_REGISTERS: StaticRef<BlockRegisters> =
    unsafe { StaticRef::new(TC1_BASE_ADDRESS as *const BlockRegisters) };

#[derive(Copy, Clone)]
pub enum Mode {
    Capture,
    Waveform,
}

#[repr(u32)]
#[derive(Copy, Clone)]
pub enum ClockSource {
    /// Generic clock number 5 (TC0) or 8 (TC1).
    TimerClock1 = 0,
    /// PBA clock / 2
    TimerClock2 = 1,
    /// PBA clock / 8
    TimerClock3 = 2,
    /// PBA clock / 32
    TimerClock4 = 3,
    /// PBA clock / 128
    TimerClock5 = 4,
    /// TC0: PA14, PB13. TC1: PC06, PC21
    XC0 = 5,
    /// TC0: PA5, PB14. TC1: PC07, PC22
    XC1 = 6,
    /// TC0: PA16, PB15. TC1: PC08, PC23
    XC2 = 7
}

#[derive(Copy, Clone)]
#[repr(u32)]
pub enum Interrupt {
    /// When an external trigger has occured (ETRGS).
    ExternalTrigger = 1 << 7,
    /// When the RA register loads a value (LDRAS).
    RALoad = 1 << 5,
    /// When the RB register loads a value (LDRBS).
    RBLoad = 1 << 6,
    /// When an RC compare occurs (CPCS).
    RCCompare = 1 << 4,
    /// When an RB compare occurs and the counter is in Waveform mode (CPBS).
    RBCompare = 1 << 3,
    /// When an RA compare occurs and the counter is in Waveform mode (CPAS).
    RACompare = 1 << 2,
    /// When RA or RB have been loaded at least twice without any read of a corresponding register in Waveform mode (LOVRS).
    LoadOverrun = 1 << 1,
    /// When the counter overflows (COVFS).
    CounterOverflow = 1 << 0,
}

impl Interrupt {
    const fn mask(&self) -> u32 {
        use Interrupt::*;
        match self {
            ExternalTrigger => 1 << 7,
            RALoad => 1 << 5,
            RBLoad => 1 << 6,
            RCCompare => 1 << 4,
            RBCompare => 1 << 3,
            RACompare => 1 << 2,
            LoadOverrun => 1 << 1,
            CounterOverflow => 1 << 0,
        }
    }
}

pub struct Parameters<'a> {
    pub mode: Mode,
    pub clock: ClockSource,
    pub rc_compare_trigger: Option<u16>,
    pub interrupt_on: &'a [Interrupt],
}

#[derive(Copy, Clone)]
pub enum InterruptLine {
    TC00,
    TC01,
    TC02,
    TC10,
    TC11,
    TC12
}

pub struct Channel {
    registers: &'static ChannelRegisters,
    overflow_client: OptionalCell<&'static dyn hil::time::OverflowClient>,
}

impl Channel {
    const fn new(registers: &'static ChannelRegisters) -> Channel {
        Channel {
            registers,
            overflow_client: OptionalCell::empty(),
        }
    }

    fn configure(&self, params: &Parameters) {
        // Set the mode.
        self.registers.cmr.write(match params.mode {
            Mode::Capture => CMR::WAVE::Capture,
            Mode::Waveform => unimplemented!(),
        });

        // Configure resets on compare.
        if let Some(trigger_val) = params.rc_compare_trigger {
            self.registers.rc.set(trigger_val as u32);
            self.registers.cmr.write(CMR::CPCTRG::ResetAndStartOnMatch);
        }

        // Enable the interrupts.
        let mut interrupt_mask: u32 = 0;
        for source in params.interrupt_on {
            interrupt_mask |= source.mask();
        }
        self.registers.ier.set(interrupt_mask);

        // Set the clock source.
        self.registers.cmr.write(CMR::TCCLKS.val(params.clock as u32));

        // TODO: clean up this mess.
        // PM should be handling this clock configuration to enable the divided clocks to TC.
        debug!("state");
        debug!("CMR ({:#010X}): {:#010X}", &self.registers.cmr as *const _ as usize, self.registers.cmr.get());
        debug!("val: {}", self.registers.cv.get());
        unsafe {
            *((0x400e0000+0x58) as *mut u32) = 0xAA00_0040;
            *((0x400e0000+0x40) as *mut u32) = 0b01010101;
        }
        debug!("PBASEL: {:#010X}", unsafe { *((0x400e0000+0x0c) as usize as *const u32) });
        debug!("PBADIVMASK: {:#010X}", unsafe { *((0x400e0000+0x40) as usize as *const u32) });
    }

    fn handle_interrupt(&self) {
        // Read the status register, this will clear the interrupt.
        // Only look at interrupts that are enabled.
        let status = self.registers.sr.get() & self.registers.imr.get();

        // Service each pending interrupt reason.
        // Counter overflow.
        if SR::COVFS.is_set(status) {
            if let Some(client) = self.overflow_client.extract() {
                client.overflow();
            }
        }
    }

    pub fn counter_value(&self) -> u16 {
        self.registers.cv.get() as u16
    }

    pub fn status(&self) -> u32 {
        self.registers.sr.get()
    }
}

impl hil::time::Time for Channel {
    type Frequency = hil::time::Freq375KHz;
    type Ticks = hil::time::Ticks16;

    fn now(&self) -> Self::Ticks {
        Self::Ticks::from(self.registers.cv.get())
    }
}

impl hil::time::Counter<'static> for Channel {
    fn set_overflow_client(&self, client: &'static dyn hil::time::OverflowClient) {
        self.overflow_client.set(client);
    }

    fn start(&self) -> Result<(), ErrorCode> {
        // Enable the clock, and ensure it is not disabled.
        self.registers.ccr.write(CCR::CLKEN::Enable);
        self.registers.ccr.write(CCR::SWTRG::ResetAndStart);

        Ok(())
    }

    fn stop(&self) -> Result<(), ErrorCode> {
        self.registers.ccr.write(CCR::CLKDIS::Disable);
        Ok(())
    }

    fn reset(&self) -> Result<(), ErrorCode> {
        self.registers.ccr.write(CCR::SWTRG::ResetAndStart);
        Ok(())
    }

    fn is_running(&self) -> bool {
        self.registers.sr.read(SR::CLKSTA) == 1
    }
}

pub struct TimerCounter {
    block0: [Channel; 3],
    block1: [Channel; 3],
}

impl TimerCounter {
    pub fn new() -> TimerCounter {
        TimerCounter {
            block0: [
                Channel::new(&TC0_REGISTERS.channel0),
                Channel::new(&TC0_REGISTERS.channel1),
                Channel::new(&TC0_REGISTERS.channel2)
            ],
            block1: [
                Channel::new(&TC1_REGISTERS.channel0),
                Channel::new(&TC1_REGISTERS.channel1),
                Channel::new(&TC1_REGISTERS.channel2)
            ]
        }
    }

    fn channel(&self, block_no: u8, channel_no: u8) -> &Channel {
        let block = match block_no {
            0 => &self.block0,
            1 => &self.block1,
            _ => unimplemented!()
        };

        &block[channel_no as usize]
    }

    pub fn configure(
        &self,
        block_no: u8,
        channel_no: u8,
        params: &Parameters,
    ) -> &Channel {
        let req_clocks = [pm::Clock::PBA(pm::PBAClock::TC0),
                          pm::Clock::PBA(pm::PBAClock::TC1)];
        for clock in req_clocks {
            if !pm::is_clock_enabled(clock) {
                pm::enable_clock(clock);
            }
        }

        let channel = self.channel(block_no, channel_no);
        channel.configure(params);

        channel
    }

    pub fn handle_interrupt(&self, line: InterruptLine) {
        let channel = match line {
            InterruptLine::TC00 => &self.block0[0],
            InterruptLine::TC01 => &self.block0[1],
            InterruptLine::TC02 => &self.block0[2],
            InterruptLine::TC10 => &self.block1[0],
            InterruptLine::TC11 => &self.block1[1],
            InterruptLine::TC12 => &self.block1[2]
        };
        channel.handle_interrupt();
    }
}
