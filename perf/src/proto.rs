/*! Clockwise data flow performance protocol implementation.

Encompasses code responsible for formatting data to go over the line.
This is a one-way protocol for communicating performance data to the peer.

* Format

Each data transmission is a fully-independent message that,
when used in combination with all other messages,
provides insights into system bandwidth.

** Initialization payload format

Header, 1 byte
B7 - payload type bit, set to 0

Counter frequency, 4 bytes
B31:B0 - frequency of the underlying counter

** Performance data payload format

Header, 1 byte
B7 - payload type bit, set to 1

Start time, 8 bytes
B63:B0 - implementation-specific, up-to-64-bit counter value

Performance data, 12 bytes
B95:B32 - end time for data collection
B31:B0  - stat value
 */

pub const TX_BUFFER_BYTE_LEN: usize =
    // Header
    1
    // Start time
    + 8
    // Stats
    + (8 * (8 + 4));

/// Container for performance data.
#[derive(Copy, Clone)]
pub struct Stat {
    acc: u32,
    t_latest: u64,
}

impl Stat {
    pub fn new() -> Stat {
        Stat {
            acc: 0,
            t_latest: 0,
        }
    }

    pub fn reset(&mut self) {
        self.acc = 0;
    }

    pub fn account(&mut self, time: u64, val: u32) {
        self.acc += val;
        self.t_latest = time;
    }

    pub fn accumulated(&self) -> u32 {
        self.acc
    }
}

pub fn serialize_init(out_buffer: &mut [u8], counter_freq: u32) -> usize {
    // Write the header.
    out_buffer[0] = 0;

    let mut b_no = 1;

    // Write the counter frequency.
    serialize_u32(&mut out_buffer[1..], counter_freq);
    b_no += 4;

    b_no
}

pub fn serialize_stats(out_buffer: &mut [u8], t0: u64, stats: &[Stat]) -> usize {
    // Write the header.
    out_buffer[0] = 1 << 7;

    let mut b_no = 1;

    // Write the start time.
    serialize_u64(&mut out_buffer[b_no..b_no+8], t0);
    b_no += 8;

    // Write each performance stat.
    for stat in stats {
        serialize_u64(&mut out_buffer[b_no..b_no+8], stat.t_latest);
        serialize_u32(&mut out_buffer[b_no+8..b_no+12], stat.acc);
        b_no += 8 + 4;
    }

    b_no
}

#[inline]
fn serialize_u64(out_buffer: &mut [u8], val: u64) {
    for i in 0..8 {
        out_buffer[i] = ((val >> (8 * i)) & 0xFF) as u8;
    }
}

#[inline]
fn serialize_u32(out_buffer: &mut [u8], val: u32) {
    for i in 0..4 {
        out_buffer[i] = ((val >> (8 * i)) & 0xFF) as u8;
    }
}
