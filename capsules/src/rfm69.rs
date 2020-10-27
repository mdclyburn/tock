use kernel::common::cells::{MapCell, TakeCell};
use kernel::hil::spi;
use kernel::{AppId, Driver, ReturnCode};

use core::convert::From;

pub const DRIVER_NUM: usize = crate::driver::NUM::Ism as usize;

/// RFM69HCW register addresses
#[allow(non_upper_case_globals, unused)]
mod register {
    pub const FIFO: u8 = 0x00;
    pub const OpMode: u8 = 0x01;
    pub const PALevel: u8 = 0x11;
    pub const DIOMapping0: u8 = 0x25;
    pub const DIOMapping1: u8 = 0x26;
    pub const IRQFlags1: u8 = 0x27;
    pub const IRQFlags2: u8 = 0x28;
    pub const SyncConfig: u8 = 0x2e;

    /// RFM69HCW register masks
    mod mask {
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

        pub const SyncConfig_SyncOn: u8 = 0b10000000;
        pub const SyncConfig_SyncSize: u8 = 0b00111000;
    }
}

/// Radio operating mode.
enum OpMode {
    Sleep = 0,
    Standby = 1,
    FrequencySynthesizer = 2,
    Transmit = 3,
    Receive = 4,
}

impl From<usize> for OpMode {
    fn from(x: usize) -> OpMode {
        match x {
            0 => OpMode::Sleep,
            1 => OpMode::Standby,
            2 => OpMode::FrequencySynthesizer,
            3 => OpMode::Transmit,
            4 => OpMode::Receive,
            _ => OpMode::Sleep,
        }
    }
}

enum Status {
    Idle,
    Access,
    Modify(u8, u8, u8),
}

/// Driver for communicating with the RFM69HCW radio over SPI.
pub struct Rfm69<'a> {
    status: MapCell<Status>,
    spi: &'a dyn spi::SpiMasterDevice,
    tx_buffer: TakeCell<'static, [u8]>,
    rx_buffer: TakeCell<'static, [u8]>,
}

impl<'a> Rfm69<'a> {
    pub fn new(s: &'a dyn spi::SpiMasterDevice,
               tx_buffer: &'static mut [u8],
               rx_buffer: &'static mut [u8]) -> Rfm69<'a> {
        Rfm69 {
            status: MapCell::new(Status::Idle),
            spi: s,
            tx_buffer: TakeCell::new(tx_buffer),
            rx_buffer: TakeCell::new(rx_buffer),
        }
    }

    fn ready(&self) -> ReturnCode {
        if self.tx_buffer.is_some() && self.rx_buffer.is_some() {
            ReturnCode::SUCCESS
        } else {
            ReturnCode::EBUSY
        }
    }

    /// Reset and configure the radio.
    fn reset(&self) -> ReturnCode {
        self.spi.configure(spi::ClockPolarity::IdleLow, spi::ClockPhase::SampleLeading, 5000);
        ReturnCode::SUCCESS
    }

    /// Read from a single register.
    fn read(&self, address: u8) -> ReturnCode {
        if let Some(tx_buffer) = self.tx_buffer.take() {
            if let Some(rx_buffer) = self.rx_buffer.take() {
                tx_buffer[0] = 0b01111111 & address;
                self.status.put(Status::Access);
                self.spi.read_write_bytes(tx_buffer, Some(rx_buffer), 2)
            } else {
                ReturnCode::EBUSY
            }
        } else {
            ReturnCode::EBUSY
        }
    }

    /// Write to a single register.
    fn write(&self, address: u8, value: u8) -> ReturnCode {
        if let Some(tx_buffer) = self.tx_buffer.take() {
            tx_buffer[0] = 0b10000000 | address;
            tx_buffer[1] = value;

            self.status.put(Status::Access);
            self.spi.read_write_bytes(tx_buffer, None, 2)
        } else {
            ReturnCode::EBUSY
        }
    }

    /// Modify a part of a register.
    ///
    /// Note: assumes the mask contains one group of contiguous ones.
    fn modify(&self, address: u8, mut mask: u8, mut value: u8) -> ReturnCode {
        if mask == 0 {
            return ReturnCode::EINVAL;
        }

        while mask & 1 == 0 {
            mask = mask >> 1;
            value = value << 1;
        }

        if let Some(tx_buffer) = self.tx_buffer.take() {
            if let Some(rx_buffer) = self.rx_buffer.take() {
                tx_buffer[0] = 0b01111111 & address;
                self.status.put(Status::Modify(address, mask, value));
                self.spi.read_write_bytes(tx_buffer, Some(rx_buffer), 2)
            } else {
                ReturnCode::EBUSY
            }
        } else {
            ReturnCode::EBUSY
        }
    }

    // Complete a modify in-progress.
    fn complete_modify(&self, address: u8, mask: u8, to_insert: u8) -> ReturnCode {
        self.rx_buffer.map_or(
            ReturnCode::FAIL,
            |rxb| {
                let cval = rxb[1];
                let new_value = (cval ^ mask) | to_insert;
                self.write(address, new_value)
            })
    }

    /// Change the radio operating mode.
    fn set_mode(&self, mode: OpMode) -> ReturnCode {
        if let Some(tx_buffer) = self.tx_buffer.take() {
            self.write(
                register::OpMode,
                match mode {
                    OpMode::Sleep => 0b000,
                    OpMode::Standby => 0b001,
                    OpMode::FrequencySynthesizer => 0b010,
                    OpMode::Transmit => 0b011,
                    OpMode::Receive => 0b100,
                    _ => 0,
                })
        } else {
            ReturnCode::EBUSY
        }
    }

    fn fill(&self) -> ReturnCode {
        if let Some(buffer) = self.tx_buffer.take() {
            for i in 0..=55 {
                buffer[i] = 0x7a;
            }

            ReturnCode::SUCCESS
        } else {
            ReturnCode::EBUSY
        }
    }
}

impl<'a> spi::SpiMasterClient for Rfm69<'a> {
    fn read_write_done(
        &self,
        write_buffer: &'static mut [u8],
        read_buffer: Option<&'static mut [u8]>,
        _len: usize) {
        self.tx_buffer.put(Some(write_buffer));
        self.rx_buffer.put(read_buffer);

        if let Some(next) = self.status.take() {
            match next {
                Status::Modify(address, mask, ins_val) => {
                    self.complete_modify(address, mask, ins_val);
                },
                _ => {  },
            }
        }
    }
}

impl<'a> Driver for Rfm69<'a> {
    fn command(&self, minor_num: usize, r2: usize, r3: usize, _caller_id: AppId) -> ReturnCode {
        match minor_num {
            0 => ReturnCode::SUCCESS,

            // Configure SPI, reset the device.
            1 => self.reset(),

            // Current status.
            2 => {
                let x = self.status.map_or(0, |current_status| {
                    match current_status {
                        Status::Idle => 0,
                        Status::Access => 1,
                        Status::Modify(_, _, _) => 2,
                    }
                });

                ReturnCode::SuccessWithValue { value: x }
            },

            // Register read.
            3 => {
                let (address, _) = (r2 as u8, r3 as u8);
                self.read(r2 as u8)
            },

            // Register write.
            4 => {
                let (address, value) = (r2 as u8, r3 as u8);
                self.write(address, value)
            },

            // Set the operating mode.
            5 => {
                let (mode, _) = (r2, r3);
                self.set_mode(OpMode::from(mode))
            },

            50 => self.fill(),

            _ => ReturnCode::ENOSUPPORT,
        }
    }
}
