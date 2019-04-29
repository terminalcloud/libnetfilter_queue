#![allow(missing_docs)]

use libc::c_int;
use std::error::Error as Base;
use std::fmt;
use ffi::nfq_errno;

#[derive(Debug)]
pub enum Reason {
    OpenHandle,
    Bind,
    Unbind,
    CreateQueue,
    SetQueueMode,
    SetQueueMaxlen,
    SetVerdict,
    GetHeader,
    GetPayload,
}

pub struct Error {
    reason: Reason,
    description: String,
}

impl fmt::Debug for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        let msg = format!("{:?}: {:?}", self.reason, self.description);
        formatter.write_str(msg.as_ref())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        let msg = format!("{:?} ({:?})", self.reason, self.description);
        formatter.write_str(msg.as_ref())
    }
}

impl Base for Error {
    fn description(&self) -> &str {
        self.description.as_ref()
    }
    fn cause(&self) -> Option<&Base> {
        None
    }
}

pub fn error(reason: Reason, msg: &str, res: Option<c_int>) -> Error {
    let errno = unsafe { nfq_errno };
    let desc = match res {
        Some(r) => format!("{} (errno: {}, res: {})", msg, errno, r),
        None => format!("{}, (errno: {})", msg, errno)
    };
    Error {
        reason: reason,
        description: desc,
    }
}
