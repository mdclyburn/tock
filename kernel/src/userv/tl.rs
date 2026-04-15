/*! Kernel-userspace data translation support.
 */

use core::mem;
use core::ops::Index;
use core::ptr;

use crate::process::Error;
use crate::processbuffer::{
    ReadableProcessBuffer,
    ReadWriteProcessBuffer,
    WriteableProcessBuffer,
};

pub enum Argument<'a> {
    /// A single 32-bit unsigned integer.
    U32(u32),
    /// A buffer, passed as address and length.
    Buffer(&'a [u8]),
    /// A sequence of bytes, copied.
    Bytes(&'a [u8]),
}

const ARG_MARK_U32: u8    = 0x01;
const ARG_MARK_BYTES: u8  = 0x02;
const ARG_MARK_BUFFER: u8 = 0x03;
const ARG_MARK_EMPTY: u8  = 0xFE;

pub struct ArgumentBuilder<'a> {
    arg_count: usize,
    buffer: &'a ReadWriteProcessBuffer,
}

impl<'a> ArgumentBuilder<'a> {
    pub fn new(buffer: &'a ReadWriteProcessBuffer)
               -> Result<ArgumentBuilder<'a>, Error> {
        // Zero-initialize the buffer.
        let _empty_r = buffer.mut_enter(|b| {
            for n in b.iter() { n.set(ARG_MARK_EMPTY); }
        })?;

        Ok(ArgumentBuilder {
            arg_count: 0,
            buffer,
        })
    }

    pub fn place(&mut self, a: &Argument) -> Result<(), Error> {
        self.buffer.mut_enter(
            |buf| {
                // Scan for the next available empty space.
                let mut idx = 0;
                loop {
                    if idx >= buf.len() {
                        return Err(Error::OutOfMemory);
                    } else if buf[idx].get() == ARG_MARK_EMPTY {
                        // Place the argument into the buffer.
                        // First the argument type no., then the actual argument.
                        let tag = match a {
                            Argument::U32(val) => {
                                buf[idx+1..idx+1+mem::size_of::<u32>()]
                                    .copy_from_slice(&val.to_ne_bytes());

                                ARG_MARK_U32
                            },

                            Argument::Buffer(s) => {
                                buf[idx+1..idx+1+mem::size_of::<usize>()]
                                    .copy_from_slice(&s.len().to_ne_bytes());
                                buf[idx+1+mem::size_of::<usize>()..idx+1+mem::size_of::<usize>()+mem::size_of::<usize>()]
                                    .copy_from_slice(&usize::to_ne_bytes(s.as_ptr() as usize));

                                ARG_MARK_BUFFER
                            },

                            Argument::Bytes(s) => {
                                buf[idx+1..idx+1+mem::size_of::<usize>()]
                                    .copy_from_slice(&s.len().to_ne_bytes());
                                buf[idx+1+mem::size_of::<usize>()..idx+1+mem::size_of::<usize>()+s.len()]
                                    .copy_from_slice(&s);

                                ARG_MARK_BYTES
                            },
                        };
                        buf[idx].set(tag);

                        break;
                    } else {
                        idx += match buf[idx].get() {
                            ARG_MARK_U32 => mem::size_of::<u32>(),

                            ARG_MARK_BUFFER | ARG_MARK_BYTES => {
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

pub struct ArgumentReader<'a> {
    buffer: &'a ReadWriteProcessBuffer,
}

impl<'a> ArgumentReader<'a> {
    pub fn new(buffer: &'a ReadWriteProcessBuffer) -> Result<ArgumentReader, Error> {
        if buffer.ptr() == ptr::null() {
            Err(Error::AddressOutOfBounds)
        } else {
            Ok(ArgumentReader {
                buffer,
            })
        }
    }

    pub fn read_argument_n(&self, arg_no: usize) -> Option<Argument> {
        self.buffer.enter(
            |buf| {
                let mut idx = 0;
                let mut curr = 0;

                loop {
                    if arg_no == curr {
                        match buf[idx].get() {
                            ARG_MARK_U32 => {
                                let mut u32_buf: [u8; 4] = [0; 4];
                                buf[idx+1..idx+1+4].copy_to_slice(&mut u32_buf);
                                return Some(Argument::U32(u32::from_ne_bytes(u32_buf)));
                            },

                            // NEXT: define extraction for other mark types.
                            // May need to go with (pointer, len) for buffer (and maybe bytes) mark.

                            _ => unimplemented!(),
                        }
                    } else {
                        let skip_len = match buf[idx].get() {
                            ARG_MARK_EMPTY => None,

                            ARG_MARK_U32 => Some(1 + 4),

                            ARG_MARK_BUFFER => Some(1 + 4),

                            ARG_MARK_BYTES => {
                                let mut usize_buf: [u8; 4] = [0; 4];
                                buf[idx+1..idx+1+4].copy_to_slice(&mut usize_buf);

                                Some(1 + usize::from_ne_bytes(usize_buf))
                            },

                            // Unrecognized argument marker.
                            _ => unimplemented!(),
                        };

                        if let Some(len) = skip_len {
                            idx += len;
                            curr += 1;
                        } else {
                            return None;
                        }
                    }
                }
            })
            .unwrap() // Must be able to enter process' buffer.
    }
}
