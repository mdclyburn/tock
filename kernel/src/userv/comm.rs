/*! Kernel-userspace service communication.
 */

use crate::userv::tl::Argument;

pub trait Client {
    fn userv_done(&self, args: &[Argument]);
}
