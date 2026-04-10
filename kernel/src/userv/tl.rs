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
    U32(u32),
    Buffer(&'a [u8], usize),
}

pub struct ArgumentBuilder<'a> {
    arg_count: usize,
    buffer: &'a ReadWriteProcessBuffer,
}

impl<'a> ArgumentBuilder<'a> {
    pub fn new(buffer: &'a ReadWriteProcessBuffer)
               -> Result<ArgumentBuilder<'a>, Error> {
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

                            _ => unimplemented!(),
                        };
                        buf[idx].set(tag);

                        break;
                    } else {
                        idx += match a {
                            Argument::U32(_) => 2,

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
}
