//! Interface for energy accounting.

use crate::AppId;
use crate::ReturnCode;

#[derive(Copy, Clone)]
pub enum Heuristic {
    /// Take a measurement now.
    Instant(AppId),

    /// Take a measurement after an amount of time.
    After(AppId, u32),

    /// Take a measurement repeatedly.
    Recurrent(AppId, u32),
}

pub trait EnergyAccounting {
    fn measure(&self, how: Heuristic) -> ReturnCode;
}
