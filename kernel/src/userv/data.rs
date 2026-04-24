/*! Serialization and deserialization for data moving to and from userspace services.
 */

use core::mem;

use crate::processbuffer::{
    ReadableProcessBuffer,
    ReadOnlyProcessBufferRef,
    ReadWriteProcessBufferRef,
    WriteableProcessBuffer,
};

/// Data that can be placed into a userspace service's process buffer.
pub trait Serialize: Sized {
    fn try_serialize(buffer: ReadWriteProcessBufferRef<'_>) -> Result<(), ()>;
}

/// Data that can be interpreted from a userspace service's process buffer bytes.
pub trait Deserialize: Sized {
    /// Attempt to convert the bytes of a process buffer into a target type.
    ///
    /// Try interpreting the bytes in the buffer as having type `Self`.
    /// Returns `Ok(Self)` if successful.
    /// Returns `Err(())` if the interpretation failed.
    fn try_deserialize(buffer: ReadOnlyProcessBufferRef<'_>) -> Result<Self, ()>;
}

/// Instantiate the Serialize and Deserialize implementations for a numeric type.
///
/// Expand the trait implementations of the serialization traits.
/// Requires that the type, T, define both `T::to_ne_bytes()` and `T::from_ne_bytes()`.
macro_rules! impl_serialization_for_numerical {
    ($($t:ty),+) => {
        $(
            impl Serialize for $t {
                fn try_serialize(buffer: ReadWriteProcessBufferRef<'_>) -> Result<(), ()> {
                    if buffer.len() < mem::size_of::<$t>() {
                        Err(())
                    } else {
                        buffer.mut_enter(
                            |rw_slice| {
                                let mut val_bytes = [0; mem::size_of::<$t>()];
                                rw_slice[0..mem::size_of::<$t>()]
                                    .copy_from_slice(&val_bytes[0..mem::size_of::<$t>()]);
                            })
                            .map_err(|_perr| ())
                    }
                }
            }

            impl Deserialize for $t {
                fn try_deserialize(buffer: ReadOnlyProcessBufferRef<'_>) -> Result<$t, ()> {
                    if buffer.len() != mem::size_of::<$t>() {
                        Err(())
                    } else {
                        buffer.enter(
                            |ro_slice| {
                                let mut val_bytes = [0; mem::size_of::<$t>()];
                                ro_slice.copy_to_slice(&mut val_bytes[0..mem::size_of::<$t>()]);
                                <$t>::from_ne_bytes(val_bytes)
                            })
                            .map_err(|_perr| ())
                    }
                }
            }
        )+
    };
}

impl_serialization_for_numerical!(
    u8, u16, u32, u64, usize,
    i8, i16, i32, i64, isize);
