/*! Serialization and deserialization for data moving to and from userspace services.
 */

use core::mem;

use kernel::errorcode::ErrorCode;
use kernel::processbuffer::{
    ReadableProcessBuffer,
    ReadOnlyProcessBufferRef,
    ReadWriteProcessBufferRef,
    WriteableProcessBuffer,
};

/// Data that can be serialized into a process buffer.
pub trait Serialize {
    /// Attempt to write `Self` into a process buffer.
    fn try_serialize(&self, buffer: ReadWriteProcessBufferRef<'_>) -> Result<(), ErrorCode>;
}

/// Data that can be interpreted from a userspace service's process buffer bytes.
pub trait Deserialize: Sized {
    /// Attempt to convert the bytes of a process buffer into `Self`.
    ///
    /// Try interpreting the bytes in the buffer as having type `Self`.
    /// Returns `Ok(Self)` if successful.
    /// Returns `Err(())` if the interpretation fails.
    fn try_deserialize(buffer: ReadOnlyProcessBufferRef<'_>) -> Result<Self, ErrorCode>;
}

/// Instantiate the Serialize and Deserialize implementations for a numeric type.
///
/// Expand the trait implementations of the serialization traits.
/// Requires that the type, T, define both `T::to_ne_bytes()` and `T::from_ne_bytes()`.
macro_rules! impl_serialization_for_numerical {
    ($($t:ty),+) => {
        $(
            impl Serialize for $t {
                fn try_serialize(&self, buffer: ReadWriteProcessBufferRef<'_>) -> Result<(), ErrorCode> {
                    if buffer.len() < mem::size_of::<$t>() {
                        Err(ErrorCode::NOMEM)
                    } else {
                        buffer.mut_enter(
                            |rw_slice| {
                                rw_slice[0..mem::size_of::<$t>()]
                                    .copy_from_slice(&self.to_ne_bytes());
                            })
                            .map_err(|perr| perr.into())
                    }
                }
            }

            impl Deserialize for $t {
                fn try_deserialize(buffer: ReadOnlyProcessBufferRef<'_>) -> Result<$t, ErrorCode> {
                    if buffer.len() != mem::size_of::<$t>() {
                        Err(ErrorCode::NOMEM)
                    } else {
                        buffer.enter(
                            |ro_slice| {
                                let mut val_bytes = [0; mem::size_of::<$t>()];
                                ro_slice.copy_to_slice(&mut val_bytes[0..mem::size_of::<$t>()]);
                                <$t>::from_ne_bytes(val_bytes)
                            })
                            .map_err(|perr| perr.into())
                    }
                }
            }
        )+
    };
}

impl_serialization_for_numerical!(
    u8, u16, u32, u64, usize,
    i8, i16, i32, i64, isize);

/// Newtype wrapper for `Serialize`ing slices into process buffers.
///
/// A wrapper type that allows slices to be passed ergonomically to [`UserspaceServiceAccess::usercall()`](super::comm::UserspaceServiceAccess).
/// The alternative would be to use double references
/// (i.e. define `impl Serialize for &&[u8]` and use with `&&&my_data[..]`
/// to guarantee to the compiler that the `Serialize` trait object is `Sized`).
pub struct Bytes<'a>(pub &'a [u8]);

impl<'a> Serialize for Bytes<'a> {
    fn try_serialize(&self, buffer: ReadWriteProcessBufferRef<'_>) -> Result<(), ErrorCode> {
        let src = self.0;
        if buffer.len() < src.len() {
            Err(ErrorCode::NOMEM)
        } else {
            buffer.mut_enter(
                |rw_slice| rw_slice[0..src.len()]
                    .copy_from_slice(src))
                .map_err(|perr| perr.into())
        }
    }
}
