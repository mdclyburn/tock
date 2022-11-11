/*! Energy accounting.
 */

/// Track energy usage by driver calls.
pub trait DriverEnergyAccounting {
    /// Perform accounting updates based on the provided syscall information.
    fn update(&self, driver_no: usize, command_no: usize, arg0: usize, arg1: usize);
}
