//! Direct Memory Access driver.

use core::cell::Cell;

use cortexm4::nvic::Nvic;

use kernel::errorcode::ErrorCode;
use kernel::hil;
use kernel::hil::dma::{
    SourcePeripheral,
    TargetPeripheral,
    TransferKind,
    TransferSize};
use kernel::platform::chip::ClockInterface;
use kernel::utilities::cells::{OptionalCell, TakeCell};
use kernel::utilities::registers::interfaces::{ReadWriteable, Readable, Writeable};
use kernel::utilities::registers::{register_bitfields, ReadOnly, ReadWrite};
use kernel::utilities::StaticRef;

use crate::nvic;
use crate::rcc;
use crate::rcc::{PeripheralClock, Rcc};

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
        PL OFFSET(16) NUMBITS(2) [
            LOW = 0b00,
            MEDIUM = 0b01,
            HIGH = 0b10,
            VERY_HIGH = 0b11,
        ],
        /// Peripheral increment offset size
        PINCOS OFFSET(15) NUMBITS(1) [],
        /// Memory data size
        MSIZE OFFSET(13) NUMBITS(2) [
            BYTE = 0b00,
            HALFWORD = 0b01,
            WORD = 0b10,
        ],
        /// Peripheral data size
        PSIZE OFFSET(11) NUMBITS(2) [
            BYTE = 0b00,
            HALFWORD = 0b01,
            WORD = 0b10,
        ],
        /// Memory increment mode
        MINC OFFSET(10) NUMBITS(1) [],
        /// Peripheral increment mode
        PINC OFFSET(9) NUMBITS(1) [],
        /// Circular mode
        CIRC OFFSET(8) NUMBITS(1) [],
        /// Data transfer direction
        DIR OFFSET(6) NUMBITS(2) [
            PERIPHERAL_TO_MEMORY = 0b00,
            MEMORY_TO_PERIPHERAL = 0b01,
            MEMORY_TO_MEMORY = 0b10,
        ],
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

const DMA1_BASE: StaticRef<DMARegisters> =
    unsafe { StaticRef::new(0x4002_6000 as *const DMARegisters) };
const DMA2_BASE: StaticRef<DMARegisters> =
    unsafe { StaticRef::new(0x4002_6400 as *const DMARegisters) };

fn peripheral_source_address(p: SourcePeripheral) -> usize {
    match p {
        _ => unimplemented!(),
    }
}

fn peripheral_target_address(p: TargetPeripheral) -> usize {
    match p {
        _ => unimplemented!(),
    }
}

/// Specifiers for the DMA controllers.
#[derive(Clone, Copy, PartialEq)]
pub enum Controller {
    DMA1,
    DMA2,
}

pub struct Stream {
    stream_no: usize,
    controller_registers: StaticRef<DMARegisters>,
    client: OptionalCell<&'static dyn hil::dma::DMAClient>,
    src_buffer: TakeCell<'static, [usize]>,
    dst_buffer: TakeCell<'static, [usize]>,
    busy: Cell<bool>,
}

impl Stream {
    fn unconfigured(stream_no: usize, controller_registers: StaticRef<DMARegisters>) -> Stream {
        Stream {
            stream_no,
            controller_registers,
            client: OptionalCell::empty(),
            src_buffer: TakeCell::empty(),
            dst_buffer: TakeCell::empty(),
            busy: Cell::new(false),
        }
    }

    #[inline]
    fn is_available(&self) -> bool {
        self.busy.get() == false
    }

    #[inline]
    fn stream_registers(&self) -> &StreamRegisters {
        &self.controller_registers.stream_registers[self.stream_no]
    }

    fn enable_interrupts(&self) {
        self.stream_registers()
            .sxcr.modify(SXCR::TCIE::SET + SXCR::TEIE::SET);
    }

    fn disable_interrupts(&self) {
        self.stream_registers()
            .sxcr.modify(SXCR::TCIE::CLEAR + SXCR::TEIE::CLEAR);
    }

    fn clear_interrupts(&self) {
        match self.stream_no {
            0 => self.controller_registers.lifcr.modify(
                LIFCR::CFEIF0::SET + LIFCR::CTCIF0::SET + LIFCR::CHTIF0::SET + LIFCR::CDMEIF0::SET + LIFCR::CFEIF0::SET),
            1 => self.controller_registers.lifcr.modify(
                LIFCR::CFEIF1::SET + LIFCR::CTCIF1::SET + LIFCR::CHTIF1::SET + LIFCR::CDMEIF1::SET + LIFCR::CFEIF1::SET),
            2 => self.controller_registers.lifcr.modify(
                LIFCR::CFEIF2::SET + LIFCR::CTCIF2::SET + LIFCR::CHTIF2::SET + LIFCR::CDMEIF2::SET + LIFCR::CFEIF2::SET),
            3 => self.controller_registers.lifcr.modify(
                LIFCR::CFEIF3::SET + LIFCR::CTCIF3::SET + LIFCR::CHTIF3::SET + LIFCR::CDMEIF3::SET + LIFCR::CFEIF3::SET),
            4 => self.controller_registers.hifcr.modify(
                HIFCR::CFEIF4::SET + HIFCR::CTCIF4::SET + HIFCR::CHTIF4::SET + HIFCR::CDMEIF4::SET + HIFCR::CFEIF4::SET),
            5 => self.controller_registers.hifcr.modify(
                HIFCR::CFEIF5::SET + HIFCR::CTCIF5::SET + HIFCR::CHTIF5::SET + HIFCR::CDMEIF5::SET + HIFCR::CFEIF5::SET),
            6 => self.controller_registers.hifcr.modify(
                HIFCR::CFEIF6::SET + HIFCR::CTCIF6::SET + HIFCR::CHTIF6::SET + HIFCR::CDMEIF6::SET + HIFCR::CFEIF6::SET),
            7 => self.controller_registers.hifcr.modify(
                HIFCR::CFEIF7::SET + HIFCR::CTCIF7::SET + HIFCR::CHTIF7::SET + HIFCR::CDMEIF7::SET + HIFCR::CFEIF7::SET),
            _ => panic!(),
        }
    }

    fn configure(&self, params: &hil::dma::Parameters) -> Result<(), ErrorCode> {
        self.busy.set(true);

        let stream_registers = self.stream_registers();
        // Set the source/destination address for peripherals.
        // For memory-to-memory, simply set it to zero.
        // It will get set just before we start the transfer.
        stream_registers.sxpar.set(match params.kind {
            TransferKind::MemoryToPeripheral(target_peripheral) =>
                peripheral_target_address(target_peripheral) as u32,
            TransferKind::PeripheralToMemory(source_peripheral) =>
                peripheral_source_address(source_peripheral) as u32,
            _ => 0x0,
        });
        // Set transfer count.
        stream_registers.sxndtr.set(params.transfer_count as u32);
        // Configure direction and address incrementation.
        // We also set the peripheral address if there is a peripheral involved.
        stream_registers.sxcr.modify(match params.kind {
            TransferKind::MemoryToMemory => SXCR::DIR::MEMORY_TO_MEMORY + SXCR::PINC::SET + SXCR::MINC::SET,
            TransferKind::MemoryToPeripheral(_p) => SXCR::DIR::MEMORY_TO_PERIPHERAL + SXCR::PINC::CLEAR + SXCR::MINC::SET,
            TransferKind::PeripheralToMemory(_p) => SXCR::DIR::PERIPHERAL_TO_MEMORY + SXCR::PINC::CLEAR + SXCR::MINC::SET,
        });
        // Match the source and destination size.
        // These could be different and incur different behavior with the FIFO,
        // but this code does not support that unless the hardware enforces its usage
        // (i.e., memory-to-memory mode).
        stream_registers.sxcr.modify(match params.transfer_size {
            TransferSize::Byte => SXCR::MSIZE::BYTE + SXCR::PSIZE::BYTE,
            TransferSize::HalfWord => SXCR::MSIZE::HALFWORD + SXCR::PSIZE::HALFWORD,
            TransferSize::Word => SXCR::MSIZE::WORD + SXCR::PSIZE::WORD,
        });

        // Set priority.
        stream_registers.sxcr.modify(if params.high_priority { SXCR::PL::VERY_HIGH } else { SXCR::PL::MEDIUM });

        Ok(())
    }

    fn stop(&self) {
        self.stream_registers().sxcr.modify(SXCR::EN::CLEAR);
        while self.stream_registers().sxcr.read(SXCR::EN) != 0 {  }
        self.busy.set(false);
    }

    fn transfer_complete(&self) {
        // kernel::debug!("bh-transfer-complete: SxCR: {:X}", self.registers.sxcr.get());
        if let Some(client) = self.client.extract() {
            client.transfer_done(self, self.src_buffer.take(), self.dst_buffer.take());
        } else {
            // No client was set.
            // This is a coding error.
            panic!();
        }
    }

    fn transfer_error(&self) {
        unimplemented!()
    }
}

impl hil::dma::DMAChannel for Stream {
    fn channel_no(&self) -> usize {
        self.stream_no
    }

    fn start(&self,
             src_buffer: Option<&'static mut [usize]>,
             dst_buffer: Option<&'static mut [usize]>) -> Result<(), ErrorCode>
    {
        let stream_registers = self.stream_registers();

        stream_registers.sxcr.modify(SXCR::EN::CLEAR);
        while stream_registers.sxcr.read(SXCR::EN) != 0 {  }

        match stream_registers.sxcr.read(SXCR::DIR) {
            // Peripheral-to-memory
            0b00 => unimplemented!(),

            // Memory-to-peripheral
            0b01 => unimplemented!(),

            // Memory-to-memory
            0b10 => {
                let s_addr = src_buffer.as_ref().map(|b| b.as_ptr() as u32).ok_or(ErrorCode::INVAL)?;
                let d_addr = dst_buffer.as_ref().map(|b| b.as_ptr() as u32).ok_or(ErrorCode::INVAL)?;
                stream_registers.sxndtr.set(src_buffer.as_ref().map(|b| b.len() as u32).ok_or(ErrorCode::INVAL)?);
                stream_registers.sxpar.set(s_addr);
                stream_registers.sxm0ar.set(d_addr);
                self.src_buffer.put(src_buffer);
                self.dst_buffer.put(dst_buffer);
            },

            _ => panic!(), // Invalid value present in DIR register field.
        };

        self.enable_interrupts();
        // These must be cleared or the stream will not start.
        self.clear_interrupts();
        stream_registers.sxcr.modify(SXCR::EN::SET);

        Ok(())
    }

    fn transfers_remaining(&self) -> usize {
        self.stream_registers().sxndtr.get() as usize
    }

    fn poll(&self) -> Option<&'static mut [usize]> {
        None
    }

    fn set_client(&self, client: &'static dyn hil::dma::DMAClient) {
        self.client.set(client)
    }
}

pub struct DMA<'a> {
    controller: Controller,
    registers: StaticRef<DMARegisters>,
    clock: PeripheralClock<'a>,
    streams: [Stream; 8],
}

impl<'a> DMA<'a> {
    pub fn new(controller: Controller, rcc: &'a Rcc) -> DMA<'a> {
        match controller {
            Controller::DMA1 => DMA {
                controller,
                registers: DMA1_BASE,
                clock: PeripheralClock::new(rcc::PeripheralClockType::AHB1(rcc::HCLK1::DMA1), rcc),
                streams: [Stream::unconfigured(0, DMA1_BASE),
                          Stream::unconfigured(1, DMA1_BASE),
                          Stream::unconfigured(2, DMA1_BASE),
                          Stream::unconfigured(3, DMA1_BASE),
                          Stream::unconfigured(4, DMA1_BASE),
                          Stream::unconfigured(5, DMA1_BASE),
                          Stream::unconfigured(6, DMA1_BASE),
                          Stream::unconfigured(7, DMA1_BASE)],
            },

            Controller::DMA2 => DMA {
                controller,
                registers: DMA2_BASE,
                clock: PeripheralClock::new(rcc::PeripheralClockType::AHB1(rcc::HCLK1::DMA2), rcc),
                streams: [Stream::unconfigured(0, DMA2_BASE),
                          Stream::unconfigured(1, DMA2_BASE),
                          Stream::unconfigured(2, DMA2_BASE),
                          Stream::unconfigured(3, DMA2_BASE),
                          Stream::unconfigured(4, DMA2_BASE),
                          Stream::unconfigured(5, DMA2_BASE),
                          Stream::unconfigured(6, DMA2_BASE),
                          Stream::unconfigured(7, DMA2_BASE)],
            },
        }
    }

    /// Enable interrupts for DMA streams.
    fn enable_interrupts(&self) {
        let irqns = match self.controller {
            Controller::DMA1 => &[
                nvic::DMA1_Stream0,
                nvic::DMA1_Stream1,
                nvic::DMA1_Stream2,
                nvic::DMA1_Stream3,
                nvic::DMA1_Stream4,
                nvic::DMA1_Stream5,
                nvic::DMA1_Stream6,
                nvic::DMA1_Stream7,
            ],

            Controller::DMA2 => &[
                nvic::DMA2_Stream0,
                nvic::DMA2_Stream1,
                nvic::DMA2_Stream2,
                nvic::DMA2_Stream3,
                nvic::DMA2_Stream4,
                nvic::DMA2_Stream5,
                nvic::DMA2_Stream6,
                nvic::DMA2_Stream7,
            ],

            _ => panic!(),
        };

        // Enable interrupts at the NVIC.
        for irqn in irqns {
            unsafe { Nvic::new(*irqn).enable(); }
        }
    }

    /// Disable interrupts for DMA streams.
    fn disable_interrupts(&self) {
        let irqns = match self.controller {
            Controller::DMA1 => &[
                nvic::DMA1_Stream0,
                nvic::DMA1_Stream1,
                nvic::DMA1_Stream2,
                nvic::DMA1_Stream3,
                nvic::DMA1_Stream4,
                nvic::DMA1_Stream5,
                nvic::DMA1_Stream6,
                nvic::DMA1_Stream7,
            ],

            Controller::DMA2 => &[
                nvic::DMA2_Stream0,
                nvic::DMA2_Stream1,
                nvic::DMA2_Stream2,
                nvic::DMA2_Stream3,
                nvic::DMA2_Stream4,
                nvic::DMA2_Stream5,
                nvic::DMA2_Stream6,
                nvic::DMA2_Stream7,
            ],

            _ => panic!(),
        };

        // Disable interrupts at the NVIC.
        for irqn in irqns {
            unsafe { Nvic::new(*irqn).disable(); }
        }
    }

    pub fn handle_interrupt(&self) {
        if self.registers.lisr.is_set(LISR::TCIF0) {
            self.streams[0].transfer_complete();
            self.registers.lifcr.modify(
                LIFCR::CTCIF0::SET
                    + LIFCR::CHTIF0::SET);
        }

        if self.registers.lisr.is_set(LISR::TEIF0) {
            self.streams[0].transfer_error();
            self.registers.lifcr.modify(LIFCR::CTEIF0::SET);
        }

        if self.registers.lisr.is_set(LISR::TCIF1) {
            self.streams[1].transfer_complete();
            self.registers.lifcr.modify(
                LIFCR::CTCIF1::SET
                    + LIFCR::CHTIF1::SET);
        }

        if self.registers.lisr.is_set(LISR::TEIF1) {
            self.streams[1].transfer_error();
            self.registers.lifcr.modify(LIFCR::CTEIF1::SET);
        }
    }
}

impl<'a> hil::dma::DMA for DMA<'a> {
    /// Find and configure a free stream.
    ///
    /// This currenly only supports memory-to-memory transfers.
    fn configure(&'static self,
                 params: &hil::dma::Parameters)
                 -> Result<&'static dyn hil::dma::DMAChannel, ErrorCode>
    {
        if !self.clock.is_enabled() {
            self.clock.enable();
            while !self.clock.is_enabled() {  }
            self.enable_interrupts();
        }

        // We can extend this to support peripheral-to-memory and memory-to-peripheral transfers
        // by creating a lookup table to see which stream supports which sources/destinations.

        let found_stream = self.streams.iter()
            .find(|stream| stream.is_available());
        if let Some(stream) = found_stream {
            stream.configure(params)?;
            Ok(stream)
        } else {
            Err(ErrorCode::BUSY)
        }
    }

    fn stop(&'static self, channel_no: usize) -> Result<(), ErrorCode> {
        let stream = &self.streams[channel_no];
        stream.stop();

        Ok(())
    }

    fn status(&'static self) -> usize {
        self.registers.lisr.get() as usize
    }
}
