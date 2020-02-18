#![allow(non_camel_case_types)]

use libc::*;

#[repr(C)]
pub struct nfq_handle(c_void);

#[repr(C)]
/// The handle into NFQueue
pub struct nfq_q_handle(c_void);

#[repr(C)]
pub struct nfgenmsg(c_void);

#[repr(C)]
pub struct nfq_data(c_void);

#[repr(C,packed)]
/// The NFQueue specific packet data
pub struct nfqnl_msg_packet_hdr {
    /// The packet id
    ///
    /// This id is necessary to identify the packet to `set_verdict`.
    /// However, it may have the wrong endianness, so `id()` should be used instead.
    pub packet_id: u32,
    /// HW protocol (network order)
    pub hw_protocol: u16,
    /// Netfilter hook
    pub hook: u8,
}

impl nfqnl_msg_packet_hdr {
    /// Extract the packet id from the packet in local endianness
    ///
    /// This id should be passed to `set_verdict` to set the destiny of the packet.
    pub fn id(&self) -> u32 { u32::from_be(self.packet_id) }
}

#[link(name="netfilter_queue")]
extern {
    pub static nfq_errno: c_int;

    // Library setup
    pub fn nfq_open() -> *mut nfq_handle;
    pub fn nfq_close(handle: *mut nfq_handle) -> c_int;
    pub fn nfq_bind_pf(handle: *mut nfq_handle, pf: u16) -> c_int;
    pub fn nfq_unbind_pf(handle: *mut nfq_handle, pf: u16) -> c_int;

    // Queue handling
    pub fn nfq_create_queue(handle: *mut nfq_handle,
                            num: u16,
                            cb: extern "C" fn(h: *mut nfq_q_handle,
                                              nfmsg: *mut nfgenmsg,
                                              nfad: *mut nfq_data,
                                              data: *mut c_void) -> c_int,
                            data: *mut c_void) -> *mut nfq_q_handle;
    pub fn nfq_destroy_queue(handle: *mut nfq_q_handle) -> c_int;
    pub fn nfq_set_mode(handle: *mut nfq_q_handle,
                        mode: u8,
                        range: u32) -> c_int;
    pub fn nfq_set_queue_maxlen(handle: *mut nfq_q_handle,
                                queuelen: u32) -> c_int;

    // Iterating through a queue
    pub fn nfq_fd(handle: *mut nfq_handle) -> c_int;
    pub fn nfq_handle_packet(handle: *mut nfq_handle,
                             buf: *mut c_char,
                             len: c_int) -> c_int;

    // Deciding on a verdict
    pub fn nfq_set_verdict(handle: *mut nfq_q_handle,
                           id: u32,
                           verdict: u32,
                           data_len: u32,
                           buf: *const c_uchar) -> c_int;

    // Parsing the message
    pub fn nfq_get_msg_packet_hdr(nfad: *mut nfq_data) -> *const nfqnl_msg_packet_hdr;
    pub fn nfq_get_payload  (nfad: *mut nfq_data, data: *mut *mut c_uchar) -> c_int;
}
