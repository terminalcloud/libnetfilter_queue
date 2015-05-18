//! The handle into NFQueue for library setup.
//!
//! Analagous to <http://netfilter.org/projects/libnetfilter_queue/doxygen/group__LibrarySetup.html>

use libc::*;
use std::mem;
use error;
use error::*;
use queue::{Queue, PacketHandler};
use message::Payload;
use lock::NFQ_LOCK as LOCK;
use errno::errno;

use ffi::*;

/// Protocol Family
///
/// NFQueue will only deal with IP, so only those families are made available.
pub enum ProtocolFamily {
    /// IPv4 Address Family
    INET = AF_INET as isize,
    /// IPv6 Address Family
    INET6 = AF_INET6 as isize
}

/// A handle into NFQueue
///
/// This is needed for library setup.
pub struct Handle {
    ptr: *mut nfq_handle
}

impl Drop for Handle {
    fn drop(&mut self) {
        let ret = unsafe { nfq_close(self.ptr) };
        if ret != 0 {
            panic!("Failed to close NFQHandle");
        }
    }
}

impl Handle {
    /// Open a new handle to NFQueue
    ///
    /// This tells the kernel that userspace queuing will be handled for the selected protocol.
    pub fn new() -> Result<Handle, Error> {
        let _lock = LOCK.lock().unwrap();

        let ptr = unsafe { nfq_open() };
        if ptr.is_null() {
            Err(error(Reason::OpenHandle, "Failed to allocate handle", None))
        } else {
            Ok(Handle{ ptr: ptr })
        }
    }

    /// Bind the handle to a `ProtocolFamily`
    pub fn bind(&mut self, proto: ProtocolFamily) -> Result<(), Error> {
        let _lock = LOCK.lock().unwrap();

        let res = unsafe { nfq_bind_pf(self.ptr, proto as uint16_t) };
        if res < 0 {
            Err(error(Reason::Bind, "Failed to bind handle", Some(res)))
        } else {
            Ok(())
        }
    }

    /// Unbind the handle from a `ProtocolFamily`
    ///
    /// This should usually be avoided, as it may attach other programs from the `ProtocolFamily`.
    pub fn unbind(&mut self, proto: ProtocolFamily) -> Result<(), Error> {
        let _lock = LOCK.lock().unwrap();

        let res = unsafe { nfq_unbind_pf(self.ptr, proto as uint16_t) };
        if res < 0 {
            Err(error(Reason::Unbind, "Failed to unbind handle", Some(res)))
        } else {
            Ok(())
        }
    }

    /// Create a new Queue
    pub fn queue<F: PacketHandler>(&mut self,
                                   queue_number: u16,
                                   handler: F) -> Result<Box<Queue<F>>, Error> {
        Queue::new(self.ptr, queue_number as uint16_t, handler)
    }

    /// Start listening using any attached queues
    ///
    /// This will only listen on queues attached with `queue_builder`.
    /// `length` determines the amount of a packet to grab from the queue at a time, in bytes.
    /// If you are using `queue::Queue::CopyMode(SIZE)` it must match `SIZE`.
    pub fn start(&mut self, length: u16) -> Result<(), Error> {
        unsafe {
            // TODO: Get rid of malloc
            let buffer: *mut c_void = malloc(length as u64);
            if buffer.is_null() {
                panic!("Failed to allocate packet buffer");
            }
            let fd = nfq_fd(self.ptr);

            loop {
                println!("{}", length);
                match recv(fd, buffer, 4096 as u64, 0) {
                    rv if rv >=0 => {
                        println!("Received: {}", rv);
                        nfq_handle_packet(self.ptr, buffer as *mut c_char, rv as i32);
                    },
                    _ => {
                        free(buffer as *mut c_void);
                        let e = errno();
                        // trim() because as_str() is unstable
                        let err = error::error(error::Reason::GetPayload, format!("{}", e).trim(), Some(e.0 as i32));
                        return Err(err)
                    }
                }
            }
        }
    }

    /// Start listening using any attached queues
    ///
    /// This will only listen on queues attached with `queue_builder`.
    /// This fn behaves like `start` except that `length` is determined by the size_of the type, `P`.
    /// For example, to parse `IPHeader`, use `start_sized<IPHeader>()`.
    pub fn start_sized<P: Payload>(&mut self) -> Result<(), Error> {
        let bytes = mem::size_of::<P>() as u16;
        // netlink header (128 bits) + payload
        self.start(16 + bytes)
    }
}
