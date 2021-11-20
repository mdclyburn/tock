use crate::hil::time::{self, Alarm};

pub use clockwise_shared::trace::TraceData;

pub static mut INSTANCE: Option<&dyn Trace> = None;

pub static mut TIME_SOURCE: Option<&dyn Alarm<Frequency = time::Freq16KHz,
                                              Ticks = time::Ticks32>>
    = None;

pub trait Trace {
    fn signal(&self, trace: &TraceData);

    fn signal_sync(&self, trace: &TraceData);
}

pub fn signal(data: &TraceData) {
    unsafe {
        INSTANCE
            .expect("Cannot trace without selecting an implementation.")
            .signal(data);
    }
}

pub fn signal_sync(data: &TraceData) {
    unsafe {
        INSTANCE
            .expect("Cannot trace without selecting an implementation.")
            .signal_sync(data);
    }
}

pub fn now_us() -> u32 {
    unsafe {
        use crate::hil::time::ConvertTicks;
        let time_source = TIME_SOURCE
            .expect("Cannot create timestamp without a time source.");
        let now_ticks = time_source.now();
        time_source.ticks_to_us(now_ticks)
    }
}

#[macro_export]
macro_rules! trace {
    ($name:expr, $data:expr) => {{
        use clockwise_shared::trace::TraceData;
        let data: &TraceData = ($data);
        $crate::hil::trace::signal(data);
    }}
}

#[macro_export]
macro_rules! sync_trace {
    ($name:expr, $data:expr) => {{
        use clockwise_shared::trace::TraceData;
        let data: &TraceData = ($data);
        $crate::hil::trace::signal_sync(data);
    }}
}
