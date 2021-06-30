pub static mut INSTANCE: Option<&dyn Trace> = None;

pub trait Trace {
    fn signal(&self, data: &[u8], len: usize);
}

#[macro_export]
macro_rules! trace {
    ($name:expr, $data:expr) => {
        if $crate::hil::trace::INSTANCE.is_some() {
            let data: &[u8] = $data;
            $crate::hil::trace::INSTANCE.as_ref().unwrap()
                .signal((data), (data).len());
        }
    }
}
