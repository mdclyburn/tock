pub use clockwise_shared::trace::TraceData;

pub static mut INSTANCE: Option<&dyn Trace> = None;

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
