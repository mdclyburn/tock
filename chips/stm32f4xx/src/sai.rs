/*! Serial Audio Interface
 */

use kernel::errorcode::ErrorCode;
use kernel::hil;
use kernel::hil::dma::DMAChannel;
use kernel::platform::chip::ClockInterface;
use kernel::utilities::cells::OptionalCell;
use kernel::utilities::registers::{
    register_bitfields,
    ReadOnly,
    ReadWrite,
    WriteOnly,
    interfaces::{
        Readable as _,
        Writeable as _,
        ReadWriteable as _
    },
};
use kernel::utilities::StaticRef;

use crate::dma::DMA;
use crate::nvic;
use crate::rcc;
use crate::rcc::{
    PeripheralClock,
    Rcc,
};

#[repr(C)]
struct SAIRegisters {
    gcr: ReadWrite<u32, GCR::Register>,
    acr1: ReadWrite<u32, CR1::Register>,
    bcr1: ReadWrite<u32, CR1::Register>,
    acr2: ReadWrite<u32, CR2::Register>,
    bcr2: ReadWrite<u32, CR2::Register>,
    afrcr: ReadWrite<u32, FRCR::Register>,
    bfrcr: ReadWrite<u32, FRCR::Register>,
    aslotr: ReadWrite<u32, SLOTR::Register>,
    bslotr: ReadWrite<u32, SLOTR::Register>,
    aim: ReadWrite<u32, IM::Register>,
    bim: ReadWrite<u32, IM::Register>,
    asr: ReadOnly<u32, SR::Register>,
    bsr: ReadOnly<u32, SR::Register>,
    aclrfr: WriteOnly<u32, CLRFR::Register>,
    bclrfr: WriteOnly<u32, CLRFR::Register>,
    adr: ReadWrite<u32, DR::Register>,
    bdr: ReadWrite<u32, DR::Register>,
}

const SAI1_BASE: StaticRef<SAIRegisters> =
    unsafe { StaticRef::new(0x4002_5800 as *const SAIRegisters) };
const SAI2_BASE: StaticRef<SAIRegisters> =
    unsafe { StaticRef::new(0x4002_5C00 as *const SAIRegisters) };

register_bitfields![
    u32,

    GCR [
        // Synchronization outputs
        SYNCOUT OFFSET(4) NUMBITS(2) [
            NONE = 0b00,
            BLOCK_A = 0b01,
            BLOCK_B = 0b10,
        ],

        // Synchronization inputs
        SYNCIN OFFSET(0) NUMBITS(2) [  ],
    ],

    CR1 [
        // Master clock divider
        MCKDIV OFFSET(20) NUMBITS(4) [  ],
        // No divider
        NODIV OFFSET(19) NUMBITS(1) [  ],
        // DMA enable
        DMAEN OFFSET(17) NUMBITS(1) [  ],
        // Audio block enable
        SAIEN OFFSET(16) NUMBITS(1) [  ],
        // Output drive
        OUTDRIV OFFSET(13) NUMBITS(1) [  ],
        // Mono mode
        MONO OFFSET(12) NUMBITS(1) [  ],
        // Synchronization enable
        SYNCEN OFFSET(10) NUMBITS(2) [
            ASYNCHRONOUS = 0b00,
            SYNCHRONOUS_INTERNAL = 0b01,
            SYNCHRONOUS_EXTERNAL = 0b10,
        ],
        // Clock strobing edge
        CKSTR OFFSET(9) NUMBITS(1) [
            RISING_EDGE = 0b0,
            FALLING_EDGE = 0b1,
        ],
        // Least-significant bit first
        LSBFIRST OFFSET(8) NUMBITS(1) [
            MSB_FIRST = 0b0,
            LSB_FIRST = 0b1,
        ],
        // Data size
        DS OFFSET(5) NUMBITS(3) [
            BITS8 = 0b010,
            BITS10 = 0b011,
            BITS16 = 0b100,
            BITS20 = 0b101,
            BITS24 = 0b110,
            BITS32 = 0b111,
        ],
        // Protocol configuration
        PRTCFG OFFSET(2) NUMBITS(2) [
            FREE = 0b00,
            SPDIF = 0b01,
            AC97 = 0b10,
        ],
        // Mode
        MODE OFFSET(0) NUMBITS(2) [
            MASTER_TX = 0b00,
            MASTER_RX = 0b01,
            SLAVE_TX = 0b10,
            SLAVE_RX = 0b11,
        ]
    ],

    CR2 [
        // Companding mode
        COMP OFFSET(14) NUMBITS(2) [  ],
        // Complement bit
        CPL OFFSET(13) NUMBITS(1) [
            ONES_COMPLEMENT = 0b0,
            TWOS_COMPLEMENT = 0b1,
        ],
        // Mute counter
        MUTECNT OFFSET(7) NUMBITS(6) [  ],
        // Mute value
        MUTEVAL OFFSET(6) NUMBITS(1) [
            BIT0 = 0b0,
            LAST_VALUE = 0b1,
        ],
        // Mute
        MUTE OFFSET(5) NUMBITS(1) [  ],
        // Tristate management on data line
        TRIS OFFSET(4) NUMBITS(1) [
            DRIVEN = 0b0,
            RELEASED = 0b1,
        ],
        // FIFO flush
        FFLUSH OFFSET(3) NUMBITS(1) [  ],
        // FIFO threshold
        FTH OFFSET(0) NUMBITS(3) [
            EMPTY = 0b000,
            FIFO_1_4 = 0b001,
            FIFO_1_2 = 0b010,
            FIFO_3_4 = 0b011,
            FIFO_FULL = 0b100,
        ],
    ],

    FRCR [
        FSOFF OFFSET(18) NUMBITS(1) [
            FS_ON_FIRST_BIT = 0b0,
            FS_BEFORE_FIRST_BIT = 0b1,
        ],
        // Frame synchronization polarity
        FSPOL OFFSET(17) NUMBITS(1) [
            ACTIVE_LOW = 0b0,
            ACTIVE_HIGH = 0b1,
        ],
        // Frame synchronization definition
        FSDEF OFFSET(16) NUMBITS(1) [
            START_FRAME = 0b0,
            START_FRAME_CHANNEL_ID = 0b1,
        ],
        // Frame synchyronization active level length
        FSALL OFFSET(8) NUMBITS(7) [  ],
        // Frame length
        FRL OFFSET(0) NUMBITS(8) [  ],
    ],

    SLOTR [
        // Slot enable
        SLOTEN OFFSET(16) NUMBITS(16) [  ],
        // Number of slots
        NBSLOT OFFSET(8) NUMBITS(4) [  ],
        // Slot size
        SLOTSZ OFFSET(6) NUMBITS(2) [
            DATA_SIZE = 0b00,
            BIT16 = 0b01,
            BIT32 = 0b10,
        ],
        // First bit offset
        FBOFF OFFSET(0) NUMBITS(5) [  ],
    ],

    IM [
        // Late frame synchronization interrupt enable
        LFSDETIE OFFSET(6) NUMBITS(1) [  ],
        // Anticipated frame synchronization detection interrupt enable
        AFSDETIE OFFSET(5) NUMBITS(1) [  ],
        // Codec not ready interrupt enable
        CNRDYIE OFFSET(4) NUMBITS(1) [  ],
        // FIFO request interrupt enable
        FREQIE OFFSET(3) NUMBITS(1) [  ],
        // Wrong clock configuration interrupt enable
        WCKCFGIE OFFSET(2) NUMBITS(1) [  ],
        // Mute detection interrupt enable
        MUTEDETIE OFFSET(1) NUMBITS(1) [  ],
        // Overrun/underrun interrupt enable
        OVRUDRIE OFFSET(0) NUMBITS(1) [  ],
    ],

    SR [
        // FIFO level threshold
        FLVL OFFSET(16) NUMBITS(3) [
            FIFO_EMPTY = 0b000,
            FIFO_LT_1_4 = 0b001,
            FIFO_BW_1_4_1_2 = 0b010,
            FIFO_BW_1_2_3_4 = 0b011,
            FIFO_GT_3_4 = 0b100,
            FIFO_FULL = 0b101,
        ],
        // Late frame synchronization
        LFSDET OFFSET(6) NUMBITS(1) [  ],
        // Anticipated frame synchronization detection
        AFSDET OFFSET(5) NUMBITS(1) [  ],
        // Codec not ready
        CNRDY OFFSET(4) NUMBITS(1) [  ],
        // FIFO request
        FREQ OFFSET(3) NUMBITS(1) [  ],
        // Wrong clock configuration
        WCKCFG OFFSET(2) NUMBITS(1) [  ],
        // Mute detection
        MUTEDET OFFSET(1) NUMBITS(1) [  ],
        // Overrun/underrun
        OVRUDR OFFSET(0) NUMBITS(1) [  ],
    ],

    CLRFR [
        // Clear late frame synchronization
        CLFSDET OFFSET(6) NUMBITS(1) [  ],
        // Clear anticipated frame synchronization detection
        CAFSDET OFFSET(5) NUMBITS(1) [  ],
        // Clear codec not ready
        CCNRDY OFFSET(4) NUMBITS(1) [  ],
        // Clear wrong clock configuration
        CWCKCFG OFFSET(2) NUMBITS(1) [  ],
        // Clear mute detection
        CMUTEDET OFFSET(1) NUMBITS(1) [  ],
        // Clear overrun/underrun
        COVRUDR OFFSET(0) NUMBITS(1) [  ],
    ],

    DR [
        DATA OFFSET(0) NUMBITS(32) [  ],
    ],
];

#[derive(Clone, Copy, PartialEq)]
pub enum Instance {
    SAI1,
    SAI2,
}

#[derive(Clone, Copy, PartialEq)]
pub enum Channel {
    A,
    B,
}

pub struct SAI<'a> {
    instance: Instance,
    registers: StaticRef<SAIRegisters>,
    clock: PeripheralClock<'a>,
    dma: OptionalCell<&'a DMA<'a>>,
    a_dma_channel: OptionalCell<&'static dyn DMAChannel>,
    b_dma_channel: OptionalCell<&'static dyn DMAChannel>,
    client: OptionalCell<&'static dyn hil::digital_audio::DigitalAudioClient>,
}

impl<'a> SAI<'a> {
    pub fn new(instance: Instance,
               clock: PeripheralClock<'a>,
    ) -> SAI<'a>
    {
        let registers = match instance {
            Instance::SAI1 => SAI1_BASE,
            Instance::SAI2 => SAI2_BASE,
        };

        SAI {
            instance,
            registers,
            clock,
            dma: OptionalCell::empty(),
            a_dma_channel: OptionalCell::empty(),
            b_dma_channel: OptionalCell::empty(),
            client: OptionalCell::empty(),
        }
    }

    pub fn configure(&self, dma: &'a DMA<'a>) {
        self.dma.set(dma);
    }
}

impl<'a> hil::digital_audio::DigitalAudioInterface for SAI<'a> {
    fn play(&'static self, buffer: &'static mut [u16]) -> Result<(), (&'static mut [u16], ErrorCode)> {
        use kernel::hil::dma::DMA as _;
        if self.a_dma_channel.is_none() {
            let res = self.dma.extract().unwrap().configure(&hil::dma::Parameters {
                kind: hil::dma::TransferKind::MemoryToPeripheral(
                    hil::dma::TargetPeripheral::DigitalAudio(0),
                    match self.instance {
                        Instance::SAI1 => 1,
                        Instance::SAI2 => 2,
                    }),
                transfer_count: buffer.len(),
                transfer_size: hil::dma::TransferSize::HalfWord,
                increment_on_read: true,
                increment_on_write: false,
                high_priority: true,
            });

            if res.is_err() {
                return Err((buffer, ErrorCode::FAIL));
            }

            let channel = res.unwrap();
            channel.set_client(self);
            self.a_dma_channel.set(channel);
        }

        let resized_buffer = unsafe {
            core::slice::from_raw_parts_mut(buffer.as_mut_ptr() as *mut usize, buffer.len() / 2)
        };
        self.a_dma_channel.extract().unwrap().start(Some(resized_buffer), None)
            .map_err(|e| (buffer, e))?;

        while !self.clock.is_enabled() { self.clock.enable(); }

        // Set up the SAI.
        self.registers.acr1.modify(
            CR1::DS::BITS16
                + CR1::DMAEN::SET
                + CR1::MCKDIV.val(0b1100));
        self.registers.acr2.modify(CR2::FTH::FIFO_1_2);
        self.registers.afrcr.modify(FRCR::FRL.val(15));

        self.registers.acr1.modify(CR1::SAIEN::SET);

        Ok(())
    }

    fn state(&self) -> hil::digital_audio::State {
        kernel::debug!("SAI SR: {:b}", self.registers.asr.get());
        if self.registers.acr1.read(CR1::SAIEN) == 1 {
            hil::digital_audio::State::Playing
        } else {
            hil::digital_audio::State::Idle
        }
    }
}

impl<'a> hil::dma::DMAClient for SAI<'a> {
    fn transfer_done(&self,
                     channel: &dyn DMAChannel,
                     src_buffer: Option<&'static mut [usize]>,
                     dst_buffer: Option<&'static mut [usize]>)
    {
        self.registers.acr1.modify(CR1::DMAEN::CLEAR + CR1::SAIEN::CLEAR);
        kernel::debug!("Done transferring audio");

        let buffer = unsafe {
            let buffer = src_buffer.unwrap();
            core::slice::from_raw_parts_mut(
                buffer.as_mut_ptr() as *mut u16,
                buffer.len() * 2)
        };

        self.client.extract().unwrap().playback_finished(buffer);
    }
}
