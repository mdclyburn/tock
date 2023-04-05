//! Direct Memory Access driver.

use kernel::platform::chip::ClockInterface;
use kernel::utilities::cells::{OptionalCell, TakeCell};
use kernel::utilities::registers::interfaces::{ReadWriteable, Readable, Writeable};
use kernel::utilities::registers::{register_bitfields, ReadOnly, ReadWrite};
use kernel::utilities::StaticRef;

use crate::nvic;
use crate::rcc;
use crate::rcc::PeripheralClock;

#[repr(C)]
pub struct DMARegisters {
    lisr: ReadOnly<u32, LISR::Register>,
    hisr: ReadOnly<u32, HISR::Register>,
    lifcr: ReadWrite<u32, LIFCR::Register>,
    hifcr: ReadWrite<u32, HIFCR::Register>,
    stream_registers: [StreamRegisters; 8],
}

#[repr(C)]
pub struct StreamRegisters {
    sxcr: ReadWrite<u32, SXCR::Register>,
    sxndtr: ReadWrite<u32>,
    sxpar: ReadWrite<u32>,
    sxm0ar: ReadWrite<u32>,
    sxm1ar: ReadWrite<u32>,
    sxfcr: ReadWrite<u32, SXFCR::Register>,
}

register_bitfields![u32,
    LISR [
        /// Stream x transfer complete interrupt flag (x = 3..0)
        TCIF3 OFFSET(27) NUMBITS(1) [],
        /// Stream x half transfer interrupt flag (x=3..0)
        HTIF3 OFFSET(26) NUMBITS(1) [],
        /// Stream x transfer error interrupt flag (x=3..0)
        TEIF3 OFFSET(25) NUMBITS(1) [],
        /// Stream x direct mode error interrupt flag (x=3..0)
        DMEIF3 OFFSET(24) NUMBITS(1) [],
        /// Stream x FIFO error interrupt flag (x=3..0)
        FEIF3 OFFSET(22) NUMBITS(1) [],
        /// Stream x transfer complete interrupt flag (x = 3..0)
        TCIF2 OFFSET(21) NUMBITS(1) [],
        /// Stream x half transfer interrupt flag (x=3..0)
        HTIF2 OFFSET(20) NUMBITS(1) [],
        /// Stream x transfer error interrupt flag (x=3..0)
        TEIF2 OFFSET(19) NUMBITS(1) [],
        /// Stream x direct mode error interrupt flag (x=3..0)
        DMEIF2 OFFSET(18) NUMBITS(1) [],
        /// Stream x FIFO error interrupt flag (x=3..0)
        FEIF2 OFFSET(16) NUMBITS(1) [],
        /// Stream x transfer complete interrupt flag (x = 3..0)
        TCIF1 OFFSET(11) NUMBITS(1) [],
        /// Stream x half transfer interrupt flag (x=3..0)
        HTIF1 OFFSET(10) NUMBITS(1) [],
        /// Stream x transfer error interrupt flag (x=3..0)
        TEIF1 OFFSET(9) NUMBITS(1) [],
        /// Stream x direct mode error interrupt flag (x=3..0)
        DMEIF1 OFFSET(8) NUMBITS(1) [],
        /// Stream x FIFO error interrupt flag (x=3..0)
        FEIF1 OFFSET(6) NUMBITS(1) [],
        /// Stream x transfer complete interrupt flag (x = 3..0)
        TCIF0 OFFSET(5) NUMBITS(1) [],
        /// Stream x half transfer interrupt flag (x=3..0)
        HTIF0 OFFSET(4) NUMBITS(1) [],
        /// Stream x transfer error interrupt flag (x=3..0)
        TEIF0 OFFSET(3) NUMBITS(1) [],
        /// Stream x direct mode error interrupt flag (x=3..0)
        DMEIF0 OFFSET(2) NUMBITS(1) [],
        /// Stream x FIFO error interrupt flag (x=3..0)
        FEIF0 OFFSET(0) NUMBITS(1) []
    ],
    HISR [
        /// Stream x transfer complete interrupt flag (x=7..4)
        TCIF7 OFFSET(27) NUMBITS(1) [],
        /// Stream x half transfer interrupt flag (x=7..4)
        HTIF7 OFFSET(26) NUMBITS(1) [],
        /// Stream x transfer error interrupt flag (x=7..4)
        TEIF7 OFFSET(25) NUMBITS(1) [],
        /// Stream x direct mode error interrupt flag (x=7..4)
        DMEIF7 OFFSET(24) NUMBITS(1) [],
        /// Stream x FIFO error interrupt flag (x=7..4)
        FEIF7 OFFSET(22) NUMBITS(1) [],
        /// Stream x transfer complete interrupt flag (x=7..4)
        TCIF6 OFFSET(21) NUMBITS(1) [],
        /// Stream x half transfer interrupt flag (x=7..4)
        HTIF6 OFFSET(20) NUMBITS(1) [],
        /// Stream x transfer error interrupt flag (x=7..4)
        TEIF6 OFFSET(19) NUMBITS(1) [],
        /// Stream x direct mode error interrupt flag (x=7..4)
        DMEIF6 OFFSET(18) NUMBITS(1) [],
        /// Stream x FIFO error interrupt flag (x=7..4)
        FEIF6 OFFSET(16) NUMBITS(1) [],
        /// Stream x transfer complete interrupt flag (x=7..4)
        TCIF5 OFFSET(11) NUMBITS(1) [],
        /// Stream x half transfer interrupt flag (x=7..4)
        HTIF5 OFFSET(10) NUMBITS(1) [],
        /// Stream x transfer error interrupt flag (x=7..4)
        TEIF5 OFFSET(9) NUMBITS(1) [],
        /// Stream x direct mode error interrupt flag (x=7..4)
        DMEIF5 OFFSET(8) NUMBITS(1) [],
        /// Stream x FIFO error interrupt flag (x=7..4)
        FEIF5 OFFSET(6) NUMBITS(1) [],
        /// Stream x transfer complete interrupt flag (x=7..4)
        TCIF4 OFFSET(5) NUMBITS(1) [],
        /// Stream x half transfer interrupt flag (x=7..4)
        HTIF4 OFFSET(4) NUMBITS(1) [],
        /// Stream x transfer error interrupt flag (x=7..4)
        TEIF4 OFFSET(3) NUMBITS(1) [],
        /// Stream x direct mode error interrupt flag (x=7..4)
        DMEIF4 OFFSET(2) NUMBITS(1) [],
        /// Stream x FIFO error interrupt flag (x=7..4)
        FEIF4 OFFSET(0) NUMBITS(1) []
    ],
    LIFCR [
        /// Stream x clear transfer complete interrupt flag (x = 3..0)
        CTCIF3 OFFSET(27) NUMBITS(1) [],
        /// Stream x clear half transfer interrupt flag (x = 3..0)
        CHTIF3 OFFSET(26) NUMBITS(1) [],
        /// Stream x clear transfer error interrupt flag (x = 3..0)
        CTEIF3 OFFSET(25) NUMBITS(1) [],
        /// Stream x clear direct mode error interrupt flag (x = 3..0)
        CDMEIF3 OFFSET(24) NUMBITS(1) [],
        /// Stream x clear FIFO error interrupt flag (x = 3..0)
        CFEIF3 OFFSET(22) NUMBITS(1) [],
        /// Stream x clear transfer complete interrupt flag (x = 3..0)
        CTCIF2 OFFSET(21) NUMBITS(1) [],
        /// Stream x clear half transfer interrupt flag (x = 3..0)
        CHTIF2 OFFSET(20) NUMBITS(1) [],
        /// Stream x clear transfer error interrupt flag (x = 3..0)
        CTEIF2 OFFSET(19) NUMBITS(1) [],
        /// Stream x clear direct mode error interrupt flag (x = 3..0)
        CDMEIF2 OFFSET(18) NUMBITS(1) [],
        /// Stream x clear FIFO error interrupt flag (x = 3..0)
        CFEIF2 OFFSET(16) NUMBITS(1) [],
        /// Stream x clear transfer complete interrupt flag (x = 3..0)
        CTCIF1 OFFSET(11) NUMBITS(1) [],
        /// Stream x clear half transfer interrupt flag (x = 3..0)
        CHTIF1 OFFSET(10) NUMBITS(1) [],
        /// Stream x clear transfer error interrupt flag (x = 3..0)
        CTEIF1 OFFSET(9) NUMBITS(1) [],
        /// Stream x clear direct mode error interrupt flag (x = 3..0)
        CDMEIF1 OFFSET(8) NUMBITS(1) [],
        /// Stream x clear FIFO error interrupt flag (x = 3..0)
        CFEIF1 OFFSET(6) NUMBITS(1) [],
        /// Stream x clear transfer complete interrupt flag (x = 3..0)
        CTCIF0 OFFSET(5) NUMBITS(1) [],
        /// Stream x clear half transfer interrupt flag (x = 3..0)
        CHTIF0 OFFSET(4) NUMBITS(1) [],
        /// Stream x clear transfer error interrupt flag (x = 3..0)
        CTEIF0 OFFSET(3) NUMBITS(1) [],
        /// Stream x clear direct mode error interrupt flag (x = 3..0)
        CDMEIF0 OFFSET(2) NUMBITS(1) [],
        /// Stream x clear FIFO error interrupt flag (x = 3..0)
        CFEIF0 OFFSET(0) NUMBITS(1) []
    ],
    HIFCR [
        /// Stream x clear transfer complete interrupt flag (x = 7..4)
        CTCIF7 OFFSET(27) NUMBITS(1) [],
        /// Stream x clear half transfer interrupt flag (x = 7..4)
        CHTIF7 OFFSET(26) NUMBITS(1) [],
        /// Stream x clear transfer error interrupt flag (x = 7..4)
        CTEIF7 OFFSET(25) NUMBITS(1) [],
        /// Stream x clear direct mode error interrupt flag (x = 7..4)
        CDMEIF7 OFFSET(24) NUMBITS(1) [],
        /// Stream x clear FIFO error interrupt flag (x = 7..4)
        CFEIF7 OFFSET(22) NUMBITS(1) [],
        /// Stream x clear transfer complete interrupt flag (x = 7..4)
        CTCIF6 OFFSET(21) NUMBITS(1) [],
        /// Stream x clear half transfer interrupt flag (x = 7..4)
        CHTIF6 OFFSET(20) NUMBITS(1) [],
        /// Stream x clear transfer error interrupt flag (x = 7..4)
        CTEIF6 OFFSET(19) NUMBITS(1) [],
        /// Stream x clear direct mode error interrupt flag (x = 7..4)
        CDMEIF6 OFFSET(18) NUMBITS(1) [],
        /// Stream x clear FIFO error interrupt flag (x = 7..4)
        CFEIF6 OFFSET(16) NUMBITS(1) [],
        /// Stream x clear transfer complete interrupt flag (x = 7..4)
        CTCIF5 OFFSET(11) NUMBITS(1) [],
        /// Stream x clear half transfer interrupt flag (x = 7..4)
        CHTIF5 OFFSET(10) NUMBITS(1) [],
        /// Stream x clear transfer error interrupt flag (x = 7..4)
        CTEIF5 OFFSET(9) NUMBITS(1) [],
        /// Stream x clear direct mode error interrupt flag (x = 7..4)
        CDMEIF5 OFFSET(8) NUMBITS(1) [],
        /// Stream x clear FIFO error interrupt flag (x = 7..4)
        CFEIF5 OFFSET(6) NUMBITS(1) [],
        /// Stream x clear transfer complete interrupt flag (x = 7..4)
        CTCIF4 OFFSET(5) NUMBITS(1) [],
        /// Stream x clear half transfer interrupt flag (x = 7..4)
        CHTIF4 OFFSET(4) NUMBITS(1) [],
        /// Stream x clear transfer error interrupt flag (x = 7..4)
        CTEIF4 OFFSET(3) NUMBITS(1) [],
        /// Stream x clear direct mode error interrupt flag (x = 7..4)
        CDMEIF4 OFFSET(2) NUMBITS(1) [],
        /// Stream x clear FIFO error interrupt flag (x = 7..4)
        CFEIF4 OFFSET(0) NUMBITS(1) []
    ],

    SXCR [
        /// Channel selection
        CHSEL OFFSET(25) NUMBITS(3) [],
        /// Memory burst transfer configuration
        MBURST OFFSET(23) NUMBITS(2) [],
        /// Peripheral burst transfer configuration
        PBURST OFFSET(21) NUMBITS(2) [],
        /// Current target (only in double buffer mode)
        CT OFFSET(19) NUMBITS(1) [],
        /// Double buffer mode
        DBM OFFSET(18) NUMBITS(1) [],
        /// Priority level
        PL OFFSET(16) NUMBITS(2) [],
        /// Peripheral increment offset size
        PINCOS OFFSET(15) NUMBITS(1) [],
        /// Memory data size
        MSIZE OFFSET(13) NUMBITS(2) [],
        /// Peripheral data size
        PSIZE OFFSET(11) NUMBITS(2) [],
        /// Memory increment mode
        MINC OFFSET(10) NUMBITS(1) [],
        /// Peripheral increment mode
        PINC OFFSET(9) NUMBITS(1) [],
        /// Circular mode
        CIRC OFFSET(8) NUMBITS(1) [],
        /// Data transfer direction
        DIR OFFSET(6) NUMBITS(2) [],
        /// Peripheral flow controller
        PFCTRL OFFSET(5) NUMBITS(1) [],
        /// Transfer complete interrupt enable
        TCIE OFFSET(4) NUMBITS(1) [],
        /// Half transfer interrupt enable
        HTIE OFFSET(3) NUMBITS(1) [],
        /// Transfer error interrupt enable
        TEIE OFFSET(2) NUMBITS(1) [],
        /// Direct mode error interrupt enable
        DMEIE OFFSET(1) NUMBITS(1) [],
        /// Stream enable / flag stream ready when read low
        EN OFFSET(0) NUMBITS(1) []
    ],

    SXFCR [
        /// FIFO error interrupt enable
        FEIE OFFSET(7) NUMBITS(1) [],
        /// FIFO status
        FS OFFSET(3) NUMBITS(3) [],
        /// Direct mode disable
        DMDIS OFFSET(2) NUMBITS(1) [],
        /// FIFO threshold selection
        FTH OFFSET(0) NUMBITS(2) []
    ]
];

const DMA1_BASE: StaticRef<Dma1Registers> =
    unsafe { StaticRef::new(0x40026000 as *const Dma1Registers) };
const DMA2_BASE: StaticRef<DMARegisters> =
    unsafe { StaticRef::new(0x4002_6000 as *const DMARegisters) };

pub struct DMA {
    registers: StaticRef<DMARegisters>,
    clock: PeripheralClock<'static>,
}

impl DMA {
}
