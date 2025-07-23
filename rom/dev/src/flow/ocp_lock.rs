/*++

Licensed under the Apache-2.0 license.

File Name:

    ocp_lock.rs

Abstract:

    File contains the implementation of the ROM OCP LOCK flow.
--*/

use crate::rom_env::RomEnv;
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_common::cprintln;
use caliptra_drivers::{
    Array4x8, AxiAddr, CaliptraError, CaliptraResult, DmaOtpCtrl, Lifecycle, SocIfc,
};

const ROM_SUPPORTS_OCP_LOCK: bool = true;

pub struct OcpLockFlow {}

impl OcpLockFlow {
    #[inline(never)]
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn run(soc: &mut SocIfc) -> CaliptraResult<()> {
        let fuse_bank = soc.fuse_bank();
        if supports_ocp_lock(soc) {
            cprintln!("[ROM] Starting OCP LOCK Flow");
        } else {
            cprintln!("[ROM] OCP LOCK Disabled");
            return Err(CaliptraError::ROM_OCP_LOCK_HARDWARE_UNSUPPORTED)?;
        }

        let hek_seed = fuse_bank.ocp_heck_seed();

        if hek_seed == Array4x8::default() {
            cprintln!("[ROM] HEK seed is zerozed");
        } else {
            cprintln!("[ROM] HEK seed is not zerozed");
        }

        Ok(())
    }
}

/// Checks if ROM supports OCP LOCK.
///
/// ROM needs to be compiled with `ocp-lock` feature and the hardware needs to support OCP
/// LOCK.
///
/// # Arguments
/// * `soc_ifc` - SOC Interface
///
/// # Returns true if OCP lock is supported.
fn supports_ocp_lock(soc_ifc: &SocIfc) -> bool {
    #[cfg(feature = "ocp-lock")]
    if soc_ifc.ocp_lock_mode() {
        return true;
    }

    false
}
