//! Structures for tracking performance data.

/// Container for performance data.
#[derive(Copy, Clone)]
struct Stat {
    acc: u32,
    t_latest: u64,
}

impl Stat {
    fn new() -> Stat {
        Stat {
            acc: 0,
            t_latest: 0,
        }
    }

    fn reset(&mut self) {
        self.acc = 0;
    }

    fn account(&mut self, time: u64, val: u32) {
        self.acc += val;
        self.t_latest = time;
    }
}
