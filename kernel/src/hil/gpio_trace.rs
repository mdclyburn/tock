use crate::common::cells::MapCell;

pub static mut INSTANCE: MapCell<&dyn GPIOTrace> = MapCell::empty();

pub trait GPIOTrace {
    fn signal(&self, id: u8, other_data: Option<u8>);
}
