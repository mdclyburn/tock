pub static mut INSTANCE: Option<&dyn Trace> = None;

pub trait Trace {
    fn signal(&self, data: &[u8], len: usize);
}
