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
use caliptra_common::{
    cprintln,
    keyids::{KEY_ID_OCP_LOCK_HEK, KEY_ID_OCP_LOCK_MDK, KEY_ID_ROM_FMC_CDI, KEY_ID_TMP},
};
use caliptra_drivers::{
    Array4x16, Array4x8, AxiAddr, CaliptraError, CaliptraResult, DmaOtpCtrl, Hmac, HmacData,
    HmacKey, HmacMode, HmacTag, KeyReadArgs, KeyUsage, KeyWriteArgs, Lifecycle, SocIfc, Trng,
};

const ROM_SUPPORTS_OCP_LOCK: bool = true;

pub struct OcpLockFlow {}

impl OcpLockFlow {
    #[inline(never)]
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn run(soc: &mut SocIfc, hmac: &mut Hmac, trng: &mut Trng) -> CaliptraResult<()> {
        cprintln!("[ROM] Starting OCP LOCK Flow");
        let fuse_bank = soc.fuse_bank();
        if supports_ocp_lock(soc) {
        } else {
            return Err(CaliptraError::ROM_OCP_LOCK_HARDWARE_UNSUPPORTED)?;
        }

        cprintln!("[ROM] OCP LOCK: Checking HEK seed");
        let hek_seed = fuse_bank.ocp_heck_seed();

        if hek_seed == Array4x8::default() {
            cprintln!("[ROM] HEK seed is zerozed");
        } else {
            cprintln!("[ROM] HEK seed is not zerozed");
        }

        cprintln!("[ROM] OCP LOCK: LOCKING ROM");
        soc.ocp_lock_set_lock_in_progress();

        populate_hek(hmac, trng)?;
        check_hmac_ocp_kv_to_ocp_kv_lock_mode(hmac, trng)?;
        check_hmac_regular_kv_to_ocp_kv_lock_mode(hmac, trng)?;

        Ok(())
    }
}

/// Populate HEK slot with garbage for testing.
fn populate_hek(hmac: &mut Hmac, trng: &mut Trng) -> CaliptraResult<()> {
    cprintln!("[ROM] OCP LOCK filling HEK with garbage");
    hmac.hmac(
        HmacKey::Array4x16(&Array4x16::default()),
        HmacData::from(&[0]),
        trng,
        KeyWriteArgs::new(
            KEY_ID_OCP_LOCK_HEK,
            KeyUsage::default().set_hmac_key_en().set_aes_key_en(),
        )
        .into(),
        HmacMode::Hmac512,
    )
}

fn check_hmac_ocp_kv_to_ocp_kv_lock_mode(hmac: &mut Hmac, trng: &mut Trng) -> CaliptraResult<()> {
    cprintln!("[ROM] Checking OCP to OCP KV HMAC after LOCK mode enabled");
    // Assertion:
    // After ROM enables LOCK mode, it should still be possible to do HMAC(key=HEK, dest=LOCK_KV)
    let res = hmac.hmac(
        HmacKey::Key(KeyReadArgs::new(KEY_ID_OCP_LOCK_HEK)),
        HmacData::Slice(&[0; 32]),
        trng,
        HmacTag::Key(KeyWriteArgs::new(KEY_ID_OCP_LOCK_MDK, KeyUsage::default())),
        HmacMode::Hmac512,
    );

    match res {
        Ok(res) => {
            cprintln!("[ROM] check_hmac_ocp_kv_to_ocp_kv_lock_mode PASSED");
            Ok(res)
        }
        Err(e) => {
            cprintln!("[ROM] check_hmac_ocp_kv_to_ocp_kv_lock_mode FAILED");
            Err(e)
        }
    }
}

fn check_hmac_regular_kv_to_ocp_kv_lock_mode(
    hmac: &mut Hmac,
    trng: &mut Trng,
) -> CaliptraResult<()> {
    cprintln!("[ROM] Checking Regular to OCP KV HMAC after LOCK mode enabled");
    // Assertion:
    // After ROM enables LOCK mode, it should still be possible to do HMAC(key=HEK, dest=LOCK_KV)
    let res = hmac.hmac(
        HmacKey::Key(KeyReadArgs::new(KEY_ID_ROM_FMC_CDI)),
        HmacData::Slice(&[0; 32]),
        trng,
        HmacTag::Key(KeyWriteArgs::new(KEY_ID_OCP_LOCK_MDK, KeyUsage::default())),
        HmacMode::Hmac512,
    );

    match res {
        Ok(res) => {
            cprintln!("[ROM] check_hmac_regular_kv_to_ocp_kv_lock_mode FAILED");
            Err(CaliptraError::RUNTIME_INTERNAL)
        }
        Err(e) => {
            cprintln!("[ROM] check_hmac_regular_kv_to_ocp_kv_lock_mode PASSED");
            Ok(())
        }
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
    if soc_ifc.ocp_lock_enabled() {
        cprintln!("[ROM] OCP LOCK supported in hardware and enabled in ROM");
        return true;
    }

    cprintln!("[ROM] OCP LOCK Disabled");
    false
}
