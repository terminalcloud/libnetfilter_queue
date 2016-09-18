//! Message parsing
//!
//! Analagous to <http://netfilter.org/projects/libnetfilter_queue/doxygen/group__Parsing.html>

use libc::*;
use std::mem;
use std::ptr::null_mut;
use std::net::Ipv4Addr;
use error::*;
use util::*;
use ffi::*;
pub use ffi::nfqnl_msg_packet_hdr as Header;

/// Structs impl'ing `Payload` must be sized correctly for the payload data that mill be transmuted to it
pub trait Payload {}

#[allow(dead_code)]
#[allow(missing_docs)]
/// A `Payload` to fetch and parse an IP packet header
pub struct IPHeader {
    pub version_and_header_raw: u8,
    pub dscp_raw: u8,
    pub total_length_raw: u16,
    pub id_raw: u16,
    pub flags_and_offset_raw: u16,
    pub ttl_raw: u8,
    pub protocol_raw: u8,
    pub checksum_raw: u16,
    pub saddr_raw: u32,
    pub daddr_raw: u32
}

impl IPHeader {
    /// Parse the source address
    pub fn saddr(&self) -> Ipv4Addr {
        addr_to_ipv4(&self.saddr_raw)
    }

    /// Parse the destination address
    pub fn daddr(&self) -> Ipv4Addr {
        addr_to_ipv4(&self.daddr_raw)
    }
}

#[inline]
fn addr_to_ipv4(src: &u32) -> Ipv4Addr {
    let octets: [u8; 4] = unsafe { mem::transmute(*src) };
    Ipv4Addr::new(u8::from_be(octets[0]),
                  u8::from_be(octets[1]),
                  u8::from_be(octets[2]),
                  u8::from_be(octets[3]))
}

impl Payload for IPHeader {}

/// The packet message
pub struct Message<'a> {
    /// A raw pointer to the queue data
    pub raw: *mut nfgenmsg,
    /// A raw pointer to the packet data
    pub ptr: *mut nfq_data,
    /// The `Message` header
    ///
    /// A verdict cannot be set without the packet's id
    /// parsed from the header.
    /// For convenience, the header is always parsed into the message.
    pub header: &'a Header
}

impl<'a> Drop for Message<'a> {
    fn drop(&mut self) {}
}

impl<'a> Message<'a> {
    #[doc(hidden)]
    pub fn new(raw: *mut nfgenmsg, ptr: *mut nfq_data) -> Result<Message<'a>, Error> {
        let header = unsafe {
            let ptr = nfq_get_msg_packet_hdr(ptr);
            match as_ref(&ptr) {
                Some(h) => h,
                None => return Err(error(Reason::GetHeader, "Failed to get header", None))
            }
        };
        Ok(Message {
            raw: raw,
            ptr: ptr,
            header: header
        })
    }

    /// Parse the `IPHeader` from the message
    ///
    /// When parsing `IPHeader` from a message, the `Queue`'s `CopyMode` and the `Handle` should be sized to the `IPHeader`.
    /// The best way to do this is with the `queue_builder.set_copy_mode_sized_to_payload`
    /// and `handle.start_sized_to_payload` methods.
    /// See `examples/get_addrs.rs`.
    pub unsafe fn ip_header(&self) -> Result<&IPHeader, Error> {
        self.payload::<IPHeader>().map(|x| x.0)
    }

    /// Parse a sized `Payload` from the message
    ///
    /// The size of the `Payload` must be equal to the value that `handle.start` was called with.
    /// The best way to do this is with the `queue_builder.set_copy_mode_sized_to_payload`
    /// and `handle.start_sized_to_payload` methods.
    /// See `examples/get_addrs.rs`.
    pub unsafe fn payload<A: Payload>(&self) -> Result<(&A, usize), Error> {
        let mut data: *mut A = null_mut();
        let ptr: *mut *mut A = &mut data;
        let n = match nfq_get_payload(self.ptr, ptr as *mut *mut c_uchar) {
            -1 => return Err(error(Reason::GetPayload, "Failed to get payload", Some(-1))),
            n => n
        };
        println!("{:?}, n={}", data, n);
        match as_mut(&data) {
            Some(payload) => Ok((payload, n as usize)),
            None => Err(error(Reason::GetPayload, "Failed to get payload", None))
        }
    }
}
