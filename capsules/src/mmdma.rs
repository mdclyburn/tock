//! Memory-to-memory DMA interface for CPU-hands-off memory transfers.

use kernel::errorcode::ErrorCode;
use kernel::hil::dma::{
    self,
    DMA,
    DMAChannel,
    DMAClient,
};
use kernel::process::ProcessId;
use kernel::syscall::{
    CommandReturn,
    SyscallDriver
};
use kernel::utilities::cells::OptionalCell;

pub const DRIVER_NUM: usize = crate::driver::NUM::DMA as usize;

struct Request {
    // DMA channel the request was assigned to.
    dma_channel: &'static dyn DMAChannel,
    // Process ID of the application that made the request.
    client_app: ProcessId,
}

pub struct MMDMA {
    dma: &'static dyn DMA,
    itself: OptionalCell<&'static dyn DMAClient>,
    requests: [OptionalCell<Request>; 8],
}

impl MMDMA {
    pub fn new(dma: &'static dyn DMA) -> MMDMA {
        MMDMA {
            dma,
            itself: OptionalCell::empty(),
            requests: [
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
            ],
        }
    }

    pub fn configure(&self, itself: &'static dyn DMAClient) {
        self.itself.set(itself);
    }
}

impl DMAClient for MMDMA {
    fn transfer_done(&self,
                     channel: &dyn DMAChannel,
                     src_buffer: Option<&'static mut [usize]>,
                     dst_buffer: Option<&'static mut [usize]>)
    {
        // kernel::debug!("DMA request on channel {} completed.", channel.channel_no());
        channel.start(src_buffer, dst_buffer).unwrap();
        // kernel::debug!("cap: ndtr = {}", channel.transfers_remaining());
    }
}

impl SyscallDriver for MMDMA {
    fn command(&self, command_no: usize, r2: usize, r3: usize, pid: ProcessId) -> CommandReturn {
        match (command_no, r2, r3) {
            (0, _r2, _r3) => CommandReturn::success(),

            // Simple one-shot memory-to-memory operation.
            (10, src_addr, dst_addr) => {
                let new_request_cell = self.requests.iter()
                    .find(|oc| oc.is_none());
                if new_request_cell.is_none() {
                    CommandReturn::failure(ErrorCode::BUSY)
                } else {
                    let new_request_cell = new_request_cell.unwrap();

                    let dma_params = dma::Parameters {
                        kind: dma::TransferKind::MemoryToMemory,
                        transfer_count: 256, // Heh...
                        transfer_size: dma::TransferSize::Word,
                        increment_on_read: true,
                        increment_on_write: true,
                        high_priority: false,
                    };
                    let result = self.dma.configure(&dma_params);
                    match result {
                        Ok(allocated_channel) => {
                            allocated_channel.set_client(self.itself.extract().unwrap());

                            new_request_cell.set(Request {
                                dma_channel: allocated_channel,
                                client_app: pid
                            });

                            let (src_buffer, dst_buffer): (&mut [usize], &mut [usize]) = unsafe {
                                (core::slice::from_raw_parts_mut(src_addr as *mut usize, 256),
                                 core::slice::from_raw_parts_mut(dst_addr as *mut usize, 256))
                            };

                            allocated_channel.start(Some(src_buffer), Some(dst_buffer));

                            CommandReturn::success()
                        },

                        Err(code) => CommandReturn::failure(code),
                    }
                }
            },

            // DMA status
            (200, _r2, _r3) => CommandReturn::success_u32(self.dma.status() as u32),

            _ => CommandReturn::failure(ErrorCode::INVAL),
        }
    }

    fn allocate_grant(&self, process_id: ProcessId) -> Result<(), kernel::process::Error> {
        Ok(())
    }
}
