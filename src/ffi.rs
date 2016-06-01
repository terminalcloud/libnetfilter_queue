#![allow(non_camel_case_types)]

use libc::*;

pub const NF_DROP: u32 = 0;
pub const NF_ACCEPT: u32 = 1;
pub const NF_STOLEN: u32 = 2;
pub const NF_QUEUE: u32 = 3;
pub const NF_REPEAT: u32 = 4;
pub const NF_STOP: u32 = 5;

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
    pub packet_id: uint32_t,
    /// HW protocol (network order)
    pub hw_protocol: uint16_t,
    /// Netfilter hook
    pub hook: uint8_t
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
    pub fn nfq_bind_pf(handle: *mut nfq_handle, pf: uint16_t) -> c_int;
    pub fn nfq_unbind_pf(handle: *mut nfq_handle, pf: uint16_t) -> c_int;

    // Queue handling
    pub fn nfq_create_queue(handle: *mut nfq_handle,
                            num: uint16_t,
                            cb: extern "C" fn(h: *mut nfq_q_handle,
                                              nfmsg: *mut nfgenmsg,
                                              nfad: *mut nfq_data,
                                              data: *mut c_void) -> c_int,
                            data: *mut c_void) -> *mut nfq_q_handle;
    pub fn nfq_destroy_queue(handle: *mut nfq_q_handle) -> c_int;
    pub fn nfq_set_mode(handle: *mut nfq_q_handle,
                        mode: uint8_t,
                        range: uint32_t) -> c_int;
    pub fn nfq_set_queue_maxlen(handle: *mut nfq_q_handle,
                                queuelen: uint32_t) -> c_int;

    // Iterating through a queue
    pub fn nfq_fd(handle: *mut nfq_handle) -> c_int;
    pub fn nfq_handle_packet(handle: *mut nfq_handle,
                             buf: *mut c_char,
                             len: c_int) -> c_int;

    // Deciding on a verdict
    pub fn nfq_set_verdict(handle: *mut nfq_q_handle,
                           id: uint32_t,
                           verdict: uint32_t,
                           data_len: uint32_t,
                           buf: *const c_uchar) -> c_int;

    // Parsing the message
    pub fn nfq_get_msg_packet_hdr(nfad: *mut nfq_data) -> *const nfqnl_msg_packet_hdr;
    pub fn nfq_get_payload  (nfad: *mut nfq_data, data: *mut *mut c_uchar) -> c_int;
}
