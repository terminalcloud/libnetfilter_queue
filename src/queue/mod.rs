//! Queue handling
//!
//! The queue handle and callback,
//! analagous to <http://netfilter.org/projects/libnetfilter_queue/doxygen/group__Queue.html>
mod verdict;

use libc::*;
use std::mem;
use std::ptr::null;

use error::*;
use util::*;
use message::{Message, Payload};
pub use self::verdict::{Verdict, QueueHandle};
use lock::NFQ_LOCK as LOCK;

use ffi::*;

const NFQNL_COPY_NONE: u8 = 0;
const NFQNL_COPY_META: u8 = 1;
const NFQNL_COPY_PACKET: u8 = 2;

/// The amount of data to be copied to userspace for each packet queued.
pub enum CopyMode {
    /// None
    None,
    /// Packet metadata only
    Metadata,
    /// If you copy the packet, you must also specify the size of the packet to copy
    Packet(u16)
}



extern fn queue_callback<F: PacketHandler>(qh: *mut nfq_q_handle,
                                           nfmsg: *mut nfgenmsg,
                                           nfad: *mut nfq_data,
                                           cdata: *mut c_void) -> c_int {
    let queue_ptr: *mut Queue<F> = unsafe { mem::transmute(cdata) };
    let queue: &mut Queue<F> = unsafe { as_mut(&queue_ptr).unwrap() };
    let message = Message::new(nfmsg, nfad);

    queue.callback.handle(QueueHandle::new(qh), message.as_ref()) as c_int
}

/// A handle to an NFQueue queue and its data.
///
/// This is used to set queue-specific settings, such as copy-mode and max-length.
/// It is bundled with callback metadata specific to this instance,
/// making it fatter than `QueueHandle`.
///
/// `QueueHandle` should be used within packet-handling for `Sync` operations.
pub struct Queue<F: PacketHandler> {
    ptr: *mut nfq_q_handle,
    callback: F
}

impl<F: PacketHandler> Drop for Queue<F> {
    fn drop(&mut self) {
        let ret = unsafe { nfq_destroy_queue(self.ptr) };
        if ret != 0 {
            panic!("Failed to destroy nfq queue");
        }
    }
}

impl<F: PacketHandler> Queue<F> {
    #[doc(hidden)]
    pub fn new(handle: *mut nfq_handle,
               queue_number: u16,
               packet_handler: F) -> Result<Box<Queue<F>>, Error> {
        let _lock = LOCK.lock().unwrap();

        let nfq_ptr: *const nfq_q_handle = null();
        let mut queue: Box<Queue<F>> = Box::new(Queue {
            ptr: nfq_ptr as *mut nfq_q_handle, // set after nfq_create_queue
            callback: packet_handler,
        });
        let queue_ptr: *mut Queue<F> = &mut *queue;

        let ptr = unsafe {
            nfq_create_queue(handle,
                             queue_number,
                             queue_callback::<F>,
                             mem::transmute(queue_ptr))
        };

        if ptr.is_null() {
            return Err(error(Reason::CreateQueue, "Failed to create queue", None));
        } else {
            queue.ptr = ptr;
        }

        Ok(queue)
    }

    /// Set the copy-mode for this queue
    pub fn set_mode(&mut self, mode: CopyMode) -> Result<(), Error> {
        let copy_mode = match mode {
            CopyMode::None => NFQNL_COPY_NONE,
            CopyMode::Metadata => NFQNL_COPY_META,
            CopyMode::Packet(_) => NFQNL_COPY_PACKET
        };
        let range = match mode {
            CopyMode::Packet(r) => r,
            _ => 0
        } as u32;

        let res = unsafe { nfq_set_mode(self.ptr, copy_mode, range) };
        if res != 0 {
            Err(error(Reason::SetQueueMode, "Failed to set queue mode", Some(res)))
        } else {
            Ok(())
        }
    }

    /// Set the copy-mode to Packet for the size of the given struct
    ///
    /// This fn behaves like `set_mode` except that packet size is determined by the size of the type, `P`.
    /// For example, to copy enough to parse `IPHeader`, use `set_mode_sized::<IPHeader>()`.
    pub fn set_mode_sized<P: Payload>(&mut self) -> Result<(), Error> {
        let bytes = mem::size_of::<P>() as u16;
        self.set_mode(CopyMode::Packet(bytes * 8))
    }

    /// Set the max-length for this queue
    ///
    /// Once `length` packets are enqueued, packets will be dropped until enqueued packets are processed.
    pub fn set_max_length(&mut self, length: u32) -> Result<(), Error> {
        let res = unsafe { nfq_set_queue_maxlen(self.ptr, length) };
        if res != 0 {
            Err(error(Reason::SetQueueMaxlen, "Failed to set queue maxlen", Some(res)))
        } else {
            Ok(())
        }
    }
}

/// Invoked to handle packets from the queue
pub trait PacketHandler {
    /// Handle a packet from the queue
    ///
    /// `Verdict`s must be set using the `set_verdict` fn.
    fn handle(&mut self, hq: QueueHandle, message: Result<&Message, &Error>) -> i32;
}

/// An abstraction over `PacketHandler` for simple handling that needs only a `Verdict`
pub trait VerdictHandler {
    /// Handle a packet from the queue
    ///
    /// Only properly formed `Message`s will be passed to this fn.
    fn decide(&mut self, message: &Message) -> Verdict;
}

#[allow(non_snake_case)]
impl<V> PacketHandler for V where V: VerdictHandler {
    fn handle(&mut self, hq: QueueHandle, message: Result<&Message, &Error>) -> i32 {
        let NULL: *const c_uchar = null();
        match message {
            Ok(m) => { let _ = Verdict::set_verdict(hq, m.header.id(), self.decide(m), 0, NULL); },
            Err(_) => ()
        }
        0
    }
}

impl<F> VerdictHandler for F where F: FnMut(&Message) -> Verdict {
    fn decide(&mut self, message: &Message) -> Verdict {
        self(message)
    }
}
