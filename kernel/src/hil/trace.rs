use crate::common::cells::MapCell;

pub static mut INSTANCE: MapCell<&dyn Trace> = MapCell::empty();

pub trait Trace {
    fn signal(&self, id: u8, other_data: Option<u8>);
}
