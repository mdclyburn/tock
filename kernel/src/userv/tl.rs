/*! Kernel-userspace data translation support.
 */

use core::mem;
use core::ops::Index;

use crate::process::Error;
use crate::processbuffer::{
    ReadableProcessBuffer,
    ReadWriteProcessBuffer,
    WriteableProcessBuffer,
};

#[repr(C)]
pub enum Argument<'a> {
    /// A single 32-bit unsigned integer.
    U32(u32),
    /// A buffer, passed as address and length.
    Buffer(&'a [u8]),
    /// A sequence of bytes, copied.
    Bytes(&'a [u8]),
}

pub struct ArgumentBuilder<'a> {
    arg_count: usize,
    buffer: &'a ReadWriteProcessBuffer,
}

impl<'a> ArgumentBuilder<'a> {
    pub fn new(buffer: &'a ReadWriteProcessBuffer)
               -> Result<ArgumentBuilder<'a>, Error> {
        // Zero-initialize the buffer.
        let _empty_r = buffer.mut_enter(|b| {
            for n in b.iter() { n.set(0x00); }
        })?;

        Ok(ArgumentBuilder {
            arg_count: 0,
            buffer,
        })
    }

    pub fn place(&mut self, a: Argument) -> Result<(), Error> {
        self.buffer.mut_enter(
            |buf| {
                // Scan for the next available empty space.
                let mut idx = 0;
                loop {
                    if idx >= buf.len() {
                        return Err(Error::OutOfMemory);
                    } else if buf[idx].get() == 0x00 {
                        // Place the argument into the buffer.
                        // First the argument type no., then the actual argument.
                        let tag = match a {
                            Argument::U32(val) => {
                                buf[idx+1..idx+1+mem::size_of::<u32>()]
                                    .copy_from_slice(&val.to_ne_bytes());

                                0x01
                            },

                            Argument::Buffer(s) => {
                                buf[idx+1..idx+1+mem::size_of::<usize>()]
                                    .copy_from_slice(&s.len().to_ne_bytes());
                                buf[idx+1+mem::size_of::<usize>()..idx+1+mem::size_of::<usize>()+mem::size_of::<usize>()]
                                    .copy_from_slice(&usize::to_ne_bytes(s.as_ptr() as usize));

                                0x02
                            }

                            Argument::Buffer(s) => {
                                buf[idx+1..idx+1+mem::size_of::<usize>()]
                                    .copy_from_slice(&s.len().to_ne_bytes());
                                buf[idx+1+mem::size_of::<usize>()..idx+1+mem::size_of::<usize>()+s.len()]
                                    .copy_from_slice(&s);

                                0x03
                            }

                            _ => unimplemented!(),
                        };
                        buf[idx].set(tag);

                        break;
                    } else {
                        idx += match buf[idx].get() {
                            0x01 => mem::size_of::<u32>(),

                            0x02 | 0x03 => {
                                // The bytes of the slice are not directly accessible,
                                // so we must copy the bytes out to interpret them;
                                // a const-interpretation is not possible.
                                let mut len_bytes: [u8; 4] = [0; 4];
                                buf[idx..idx+4].copy_to_slice(&mut len_bytes);
                                4 + usize::from_ne_bytes(len_bytes)
                            },

                            _ => unimplemented!(),
                        }
                    }
                }

                Ok(())
            })??;

        // Update the number of arguments.
        self.arg_count += 1;

        Ok(())
    }

    /// Form the upcall arguments to the userspace service.
    pub fn as_upcall_arguments(&self) -> (usize, usize, usize) {
        (self.arg_count, self.buffer.ptr() as usize, 0)
    }
}
