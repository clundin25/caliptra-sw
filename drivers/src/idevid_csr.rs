// Licensed under the Apache-2.0 license

use core::mem::size_of;
use zerocopy::{AsBytes, FromBytes};
use zeroize::Zeroize;

use crate::memory_layout;

pub const MAX_CSR_SIZE: usize = 512;

#[derive(FromBytes, AsBytes, Zeroize)]
#[repr(C)]
pub struct IDevIDCsr {
    pub csr: [u8; MAX_CSR_SIZE],
    pub csr_len: u32,
}

impl Default for IDevIDCsr {
    fn default() -> Self {
        Self {
            csr: [0; MAX_CSR_SIZE],
            csr_len: 0,
        }
    }
}

impl IDevIDCsr {
    /// The `csr_len` field is set to this constant when a ROM image supports CSR generation but
    /// the CSR generation flag was not enabled.
    ///
    /// This is used by the runtime to distinguish ROM images that support CSR generation from
    /// ones that do not.
    ///
    /// u32::MAX is too large to be a valid CSR, so we use it to encode this state.
    pub const UNPROVISIONED_CSR: u32 = u32::MAX;
    /// Get the CSR buffer
    pub fn get(&self) -> Option<&[u8]> {
        if !self.is_valid() {
            return None;
        }
        self.csr.get(..self.csr_len as usize)
    }

    pub fn is_valid(&self) -> bool {
        self.csr_len != Self::UNPROVISIONED_CSR
    }
}

const _: () = assert!(size_of::<IDevIDCsr>() < memory_layout::IDEVID_CSR_SIZE as usize);
