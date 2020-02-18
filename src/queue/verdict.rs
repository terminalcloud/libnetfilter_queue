//! Verdict and packet handling for NFQueue packets.
use libc::*;
use error::*;
use ffi::*;

/// An explicit handle to the NFQueue queue, used only for setting the verdict
///
/// This can be used in a thread-safe manner
pub struct QueueHandle(*mut nfq_q_handle);
unsafe impl Send for QueueHandle {}
unsafe impl Sync for QueueHandle {}

#[allow(missing_docs)]
impl QueueHandle {
    pub fn new(ptr: *mut nfq_q_handle) -> Self {
        QueueHandle(ptr)
    }
}

/// Packet verdict used to notify netfilter of a packet's destiny
pub enum Verdict {
    /// Drop the packet and release it's memory
    Drop,
    /// Accept the packet from this chain
    Accept,
    /// Drop the packet but do not release it's memory
    ///
    /// This is used when userspace (this program) will finish handling the packet.
    Stolen,
    /// Queue the packet into the given queue_number
    Queue(u16),
    /// Call this hook again for this packet
    ///
    /// The hook is stored in the packet header.
    Repeat,
    /// Similar to Accept
    Stop
}

impl Verdict {
    // Encodes the enum into a u32 suitible for use by nfq_set_verdict
    fn as_i32(&self) -> i32 {
        match *self {
            Verdict::Drop => NF_DROP,
            Verdict::Accept => NF_ACCEPT,
            Verdict::Stolen => NF_STOLEN,
            Verdict::Queue(t) => NF_QUEUE | (t as i32) << 16,
            Verdict::Repeat => NF_REPEAT,
            Verdict::Stop => NF_STOP,
        }
    }

    /// Set the verdict for a packet
    ///
    /// The `packet_id` must be used to identify a packet, fetched from `packet.header.id()`.
    /// For simpler cases, pass `data_len = 0` and `buffer = std::ptr::null()`.
    pub fn set_verdict(qh: QueueHandle, packet_id: u32, verdict: Verdict, data_len: u32, buffer: *const c_uchar) -> Result<c_int, Error> {
	let c_verdict = verdict.as_i32() as u32;

        match unsafe { nfq_set_verdict(qh.0, packet_id, c_verdict, data_len, buffer) } {
            -1 => Err(error(Reason::SetVerdict, "Failed to set verdict", None)),
            r @ _ => Ok(r)
        }
    }
}
