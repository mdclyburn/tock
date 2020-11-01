//! Interface for energy accounting.

use crate::AppId;

pub enum Heuristic {
    Instant,
    After(usize),
}

pub trait EnergyAccounting {
    fn measure(&self, app: AppId, how: Heuristic);
}
