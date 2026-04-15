/*! Kernel-userspace service communication.
 */

use crate::userv::tl::ArgumentReader;

pub trait Client {
    fn usercall_done<'a>(&self, args: &ArgumentReader<'a>);
}
