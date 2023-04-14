//! Memory-to-memory DMA interface for CPU-hands-off memory transfers.

use core::cell::Cell;

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
use kernel::utilities::cells::{
    MapCell,
    NumericCellExt,
    OptionalCell
};

pub const DRIVER_NUM: usize = crate::driver::NUM::DMA as usize;

struct Request {
    // DMA channel the request was assigned to.
    dma_channel: &'static dyn DMAChannel,
    // Process ID of the application that made the request.
    client_app: ProcessId,
    // Whether to start the transfer again.
    again: Cell<bool>,
    completed: Cell<usize>,
}

pub struct MMDMA {
    dma: &'static dyn DMA,
    itself: OptionalCell<&'static dyn DMAClient>,
    requests: [MapCell<Request>; 8],
}

impl MMDMA {
    pub fn new(dma: &'static dyn DMA) -> MMDMA {
        MMDMA {
            dma,
            itself: OptionalCell::empty(),
            requests: [
                MapCell::empty(),
                MapCell::empty(),
                MapCell::empty(),
                MapCell::empty(),
                MapCell::empty(),
                MapCell::empty(),
                MapCell::empty(),
                MapCell::empty(),
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
        let request = self.requests.iter()
            .find(|mc| mc.map_or(false, |request| request.dma_channel.channel_no() == channel.channel_no()))
            .expect("DMA channel was not recorded in requests");
        request.map(|request| {
            if request.completed.get() < 500 {
                request.completed.increment();
                channel.start(src_buffer, dst_buffer).unwrap();
            } else {
                kernel::debug!("no more transferring for channel no. {}", channel.channel_no());
            }
        }).unwrap();
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
                        transfer_count: 2048, // Heh...
                        transfer_size: dma::TransferSize::Word,
                        increment_on_read: true,
                        increment_on_write: true,
                        high_priority: false,
                    };
                    let result = self.dma.configure(&dma_params);
                    match result {
                        Ok(allocated_channel) => {
                            allocated_channel.set_client(self.itself.extract().unwrap());

                            new_request_cell.put(Request {
                                dma_channel: allocated_channel,
                                client_app: pid,
                                again: Cell::new(true),
                                completed: Cell::new(0),
                            });

                            let (src_buffer, dst_buffer): (&mut [usize], &mut [usize]) = unsafe {
                                (core::slice::from_raw_parts_mut(src_addr as *mut usize, 2048),
                                 core::slice::from_raw_parts_mut(dst_addr as *mut usize, 2048))
                            };

                            match allocated_channel.start(Some(src_buffer), Some(dst_buffer)) {
                                Ok(_) => CommandReturn::success(),
                                Err(code) => CommandReturn::failure(code),
                            }
                        },

                        Err(code) => CommandReturn::failure(code),
                    }
                }
            },

            // Stop transfer.
            (20, _r2, _r3) => {
                for request in self.requests.iter() {
                    let _ = request.map(|request| {
                        kernel::debug!("preventing channel no. {}", request.dma_channel.channel_no());
                        request.again.set(false);
                        let channel_no = request.dma_channel.channel_no();
                        kernel::debug!("Calling DMA::stop()");
                        match self.dma.stop(channel_no) {
                            Ok(_) => kernel::debug!("stopped channel no. {}", channel_no),
                            Err(_) => kernel::debug!("failed to stop channel no. {}", channel_no),
                        }
                    });
                }

                CommandReturn::success()
            },

            // Power off
            (150, _r2, _r3) => {
                let _r = self.dma.power_off();
                CommandReturn::success()
            },

            // DMA status
            (200, _r2, _r3) => {
                let total = self.requests.iter()
                    .filter(|r| r.is_some())
                    .map(|r| r.map(|r| (r.dma_channel.channel_no(), r.completed.get())).unwrap())
                    .inspect(|(c, comp)| kernel::debug!("channel no. {} completed {} requests", c, comp))
                    .map(|(c, comp)| comp as u32)
                    .sum();
                CommandReturn::success_u32(total)
                // CommandReturn::success_u32(self.completed.get() as u32),
            },

            _ => CommandReturn::failure(ErrorCode::INVAL),
        }
    }

    fn allocate_grant(&self, process_id: ProcessId) -> Result<(), kernel::process::Error> {
        Ok(())
    }
}
