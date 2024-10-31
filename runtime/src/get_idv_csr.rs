// Licensed under the Apache-2.0 license

use crate::Drivers;

use caliptra_cfi_derive_git::cfi_impl_fn;
use caliptra_cfi_lib_git::cfi_launder;

use caliptra_common::{
    cprintln,
    mailbox_api::{GetIDevIDCSRReq, GetIDevIDCSRResp, MailboxResp, MailboxRespHeader},
};
use caliptra_error::{CaliptraError, CaliptraResult};

use caliptra_drivers::IDevIDCsr;

use zerocopy::{AsBytes, FromBytes};

pub struct GetIDVCSRCmd;
impl GetIDVCSRCmd {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers, cmd_args: &[u8]) -> CaliptraResult<MailboxResp> {
        if let Some(cmd) = GetIDevIDCSRReq::read_from(cmd_args) {
            let csr_persistent_mem = &drivers.persistent_data.get().idevid_csr;
            let mut resp = GetIDevIDCSRResp::default();

            let csr = csr_persistent_mem
                .get()
                .ok_or(CaliptraError::RUNTIME_GET_IDEV_ID_UNPROVISIONED)?;

            match csr_persistent_mem.csr_len {
                IDevIDCsr::UNPROVISIONED_CSR => {
                    Err(CaliptraError::RUNTIME_GET_IDEV_ID_UNPROVISIONED)
                }
                0 => Err(CaliptraError::RUNTIME_GET_IDEV_ID_UNSUPPORTED_ROM),
                _ => {
                    resp.data_size = csr_persistent_mem.csr_len;
                    resp.data[..resp.data_size as usize].copy_from_slice(csr);

                    Ok(MailboxResp::GetIDevIDCSR(resp))
                }
            }
        } else {
            Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)
        }
    }
}
