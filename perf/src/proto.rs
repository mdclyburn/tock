/*! Clockwise data flow performance protocol.

Encompasses code responsible for formatting data to go over the line.
This is a one-way protocol for communicating performance data to the peer.
Each data transmission is a fully-independent message that,
when used in combination with all other messages,
provides insights into system bandwidth.

The header of each message is a single byte with the format decided by the highest bit in the header.
- **Bit 7**: message type
  - 0: counter start signal
  - 1: performance data

In the performance data format:
- **Bits 6:3**: source
 */

use kernel::hil::uart::Transmit;

/* Sized to accomodate the following payloads:
- header: u8 + time upper mask: u8 + time lower mask: u8               =  9 bytes
- header: u8 + time upper mask: u32 + time lower mask: u32 + data: u32 = 13 bytes
 */
/// Size required to send the the largest counter payload.
pub const TX_BUFFER_LEN: usize = 13;

const PAYLOAD_PERF_LEN: usize = 13;
const PAYLOAD_SIGNAL_LEN: usize = 9;

#[derive(Copy, Clone)]
pub enum Message {
    Start,
    /// Payload is performance data for the specified trace point.
    PerformanceData(u8),
}

#[inline]
pub fn put_header(out_buffer: &mut [u8], message_type: Message) {
    out_buffer[0] = match message_type {
        Message::Start => 0,
        Message::PerformanceData(trace_id) =>
            0b1000_0000 | ((trace_id & 0b111) << 3),
    }
}

pub fn put_signal(out_buffer: &mut [u8], time_upper_bits: u8, time_lower_bits: u8) {
    let mut i = 0;
    for field in [time_upper_bits, time_lower_bits] {
        out_buffer[i] = field;
        i += 1;
    }
}

#[inline]
pub fn put_performance_data(
    out_buffer: &mut [u8],
    time_upper: u32,
    time_lower: u32,
    val: u32,
)
{
    let mut i = 0;
    for field in [time_upper, time_lower, val] {
        out_buffer[i+0] = ((field >> 24) & 0xFF) as u8;
        out_buffer[i+1] = ((field >> 16) & 0xFF) as u8;
        out_buffer[i+2] = ((field >> 8) & 0xFF) as u8;
        out_buffer[i+3] = ((field >> 0) & 0xFF) as u8;
        i += 4
    }
}

pub fn send(tx: &dyn Transmit, buffer: &'static mut [u8]) {
    let len = if buffer[0] & 0b1000_0000 != 0 {
        PAYLOAD_PERF_LEN
    } else {
        PAYLOAD_SIGNAL_LEN
    };

    tx.transmit_buffer(buffer, len).unwrap();
}
