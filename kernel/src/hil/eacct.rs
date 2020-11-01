//! Interface for energy accounting.

pub enum Heuristic {
    Instant,
    After(usize),
}

pub trait EnergyAccounting {
    fn measure(&self, ticks: usize);
}
