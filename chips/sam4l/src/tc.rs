//! 16-bit timer counter (TC)

use core::cell::Cell;

use kernel::errorcode::ErrorCode;
use kernel::utilities::cells::NumericCellExt;
use kernel::utilities::registers::interfaces::{
    ReadWriteable,
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

#[repr(C)]
pub struct Channel {
    ccr: WriteOnly<u32, CCR::Register>,
    cmr: ReadWrite<u32, CMR::Register>,
    smcr: ReadWrite<u32, SMCR::Register>,
    _reserved0: u32,
    cv: ReadOnly<u32, CV::Register>,
    ra: ReadWrite<u32, Rx::Register>,
    rb: ReadWrite<u32, Rx::Register>,
    rc: ReadWrite<u32, Rx::Register>,
    sr: ReadOnly<u32, SR::Register>,
    ier: WriteOnly<u32, IER::Register>,
    idr: WriteOnly<u32, IDR::Register>,
    imr: ReadOnly<u32, IMR::Register>,
}

register_structs! {
    /// TC block registers
    TC {
        (0x00 => channel0: Channel),
        (0x30 => _reserved0: [u32; 4]),
        (0x40 => channel1: Channel),
        (0x70 => _reserved1: [u32; 4]),
        (0x80 => channel2: Channel),
        (0xb0 => _reserved2: [u32; 4]),

        (0xc0 => bcr: WriteOnly<u32, BCR::Register>),
        (0xc4 => bmr: ReadWrite<u32, BMR::Register>),

        (0xc8 => @END),
    }
}

impl Channel {
    fn configure(&self, mode: Mode, trigger: Trigger) {
        self.cmr.write(CMR::WAVE::Capture);
    }
}

register_bitfields![
    u32,
    CCR [
        SWTRG OFFSET(2) NUMBITS(1) [],
        CLKDIS OFFSET(1) NUMBITS(1) [],
        CLKEN OFFSET(0) NUMBITS(1) [],
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
            ResetAndStartOnCompare = 1
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
#[allow(unused)]
const TC1_BASE_ADDRESS: usize = 0x4001_4000;

const REGISTERS: StaticRef<TC> =
    unsafe { StaticRef::new(TC0_BASE_ADDRESS as *const TC) };

pub enum Mode {
    Capture,
    Waveform,
}

pub enum Trigger {
    Software,
    Sync,
    Compare(u16),
}

pub struct TimerCounter;

impl TimerCounter {
    pub const fn new() -> TimerCounter {
        TimerCounter {  }
    }

    pub fn configure(
        &self,
        channel_no: u8,
        mode: Mode,
        trigger: Trigger
    ) -> &'static Channel {
        let channel = match channel_no {
            0 => &REGISTERS.channel0,
            1 => &REGISTERS.channel1,
            2 => &REGISTERS.channel2,
            _ => unimplemented!(),
        };

        channel.configure(mode, trigger);
        channel
    }

    pub fn handle_interrupt(&self) {
    }
}
