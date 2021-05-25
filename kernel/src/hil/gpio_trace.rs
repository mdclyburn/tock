pub trait GPIOTrace {
    fn signal(&self, id: u8, other_data: Option<u8>);
}
