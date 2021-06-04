pub static mut INSTANCE: Option<&dyn Trace> = None;

pub trait Trace {
    fn signal(&self, id: u8, other_data: Option<u8>);
}
