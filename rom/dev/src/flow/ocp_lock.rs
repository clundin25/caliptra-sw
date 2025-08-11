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
    keyids::{
        ocp_lock::{KEY_ID_EPK, KEY_ID_HEK, KEY_ID_MDK, KEY_ID_MEK},
        KEY_ID_ROM_FMC_CDI, KEY_ID_TMP, KEY_ID_UDS,
    },
};
use caliptra_drivers::{
    Aes, AesKey, AesOperation, Array4x16, Array4x8, AxiAddr, CaliptraError, CaliptraResult,
    DmaOtpCtrl, FuseBank, Hmac, HmacData, HmacKey, HmacMode, HmacTag, KeyId, KeyReadArgs, KeyUsage,
    KeyWriteArgs, Lifecycle, SocIfc, Trng,
};

const ROM_SUPPORTS_OCP_LOCK: bool = true;

pub struct OcpLockFlow {}

impl OcpLockFlow {
    #[inline(never)]
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn run(
        soc: &mut SocIfc,
        hmac: &mut Hmac,
        trng: &mut Trng,
        aes: &mut Aes,
    ) -> CaliptraResult<()> {
        cprintln!("[ROM] Starting OCP LOCK Flow");
        if !supports_ocp_lock(soc) {
            return Err(CaliptraError::ROM_OCP_LOCK_HARDWARE_UNSUPPORTED)?;
        }
        validation_flow(soc, hmac, trng, aes)?;
        Ok(())
    }
}

//populate_slot(hmac, trng, KEY_ID_OCP_LOCK_HEK)?;
//
//check_aes_decrypt_mdk_to_fw(aes, trng)?;
//check_hmac_ocp_kv_to_ocp_kv_lock_mode(hmac, trng)?;

// TODO: This flow is not yet supported in HW.
//check_hmac_regular_kv_to_ocp_kv_lock_mode(hmac, trng)?;

fn validation_flow(
    soc: &mut SocIfc,
    hmac: &mut Hmac,
    trng: &mut Trng,
    aes: &mut Aes,
) -> CaliptraResult<()> {
    cprintln!("[ROM] Starting OCP LOCK Validation");
    let fuse_bank = soc.fuse_bank();

    check_hek_seed(&fuse_bank)?;
    check_populate_mek_with_aes(aes, hmac, trng);
    check_populate_mek_with_hmac(hmac, trng);

    cprintln!("[ROM] OCP LOCK: LOCKING OCP");
    soc.ocp_lock_set_lock_in_progress();

    check_locked_hmac(hmac, trng);
    check_locked_hek(hmac, trng);
    Ok(())
}

fn check_hek_seed(fuse_bank: &FuseBank) -> CaliptraResult<()> {
    cprintln!("[ROM] OCP LOCK: Checking HEK seed");
    let hek_seed = fuse_bank.ocp_heck_seed();

    if hek_seed == Array4x8::default() {
        cprintln!("[ROM] HEK seed is zerozed");
    } else {
        cprintln!("[ROM] HEK seed is not zerozed");
    }
    Ok(())
}

// Currently get's stuck waiting for KV complete
fn check_populate_mek_with_aes(
    aes: &mut Aes,
    hmac: &mut Hmac,
    trng: &mut Trng,
) -> CaliptraResult<()> {
    cprintln!("[ROM] check_populate_mek_with_aes");
    populate_slot(hmac, trng, KEY_ID_MDK)?;

    //let res = aes.aes_256_ecb(
    //    AesKey::KV(KeyReadArgs::new(KEY_ID_OCP_LOCK_MDK)),
    //    AesOperation::Decrypt,
    //    &[0; 16],
    //    &mut output,
    //);

    Ok(())
}

fn check_populate_mek_with_hmac(hmac: &mut Hmac, trng: &mut Trng) -> CaliptraResult<()> {
    cprintln!("[ROM] check_populate_mek_with_hmac");
    // Using the EPK slot. Any OCP LOCK slot will work.
    populate_slot(hmac, trng, KEY_ID_EPK)?;

    hmac.hmac(
        HmacKey::Key(KeyReadArgs::new(KEY_ID_EPK)),
        HmacData::from(&[0]),
        trng,
        KeyWriteArgs::new(
            KEY_ID_MEK,
            KeyUsage::default().set_hmac_key_en().set_aes_key_en(),
        )
        .into(),
        HmacMode::Hmac512,
    )?;

    cprintln!("[ROM] check_populate_mek_with_hmac PASSED");
    Ok(())
}

/// We should no longer be able to write from a non-KV to a LOCK KV.
fn check_locked_hmac(hmac: &mut Hmac, trng: &mut Trng) -> CaliptraResult<()> {
    cprintln!("[ROM] check_locked_hmac");

    // It should no longer be possible to perform an HMAC for non-OCP KV => OCP KV.
    // Assumes `KEY_ID_ROM_FMC_CDI` has been populated.
    let res = hmac.hmac(
        HmacKey::Key(KeyReadArgs::new(KEY_ID_ROM_FMC_CDI)),
        HmacData::from(&[0]),
        trng,
        KeyWriteArgs::new(
            KEY_ID_EPK,
            KeyUsage::default().set_hmac_key_en().set_aes_key_en(),
        )
        .into(),
        HmacMode::Hmac512,
    );

    match res {
        Ok(_) => {
            cprintln!("[ROM] check_locked_hmac FAILED")
        }
        Err(e) => {
            cprintln!("[ROM] Result is: 0x{:x}", u32::from(e));
            cprintln!("[ROM] check_locked_hmac PASSED");
        }
    }
    // TODO: We want these checks to fail.
    Ok(())
}

/// We should still be able to write from a HEK to a LOCK KV.
fn check_locked_hek(hmac: &mut Hmac, trng: &mut Trng) -> CaliptraResult<()> {
    cprintln!("[ROM] check_locked_hek");

    // Assumes `KEY_ID_HEK` has been populated.
    let res = hmac.hmac(
        HmacKey::Key(KeyReadArgs::new(KEY_ID_HEK)),
        HmacData::from(&[0]),
        trng,
        KeyWriteArgs::new(
            KEY_ID_EPK,
            KeyUsage::default().set_hmac_key_en().set_aes_key_en(),
        )
        .into(),
        HmacMode::Hmac512,
    )?;

    cprintln!("[ROM] check_locked_hek PASSED");
    Ok(())
}

/// Populate slot for testing.
fn populate_slot(hmac: &mut Hmac, trng: &mut Trng, slot: KeyId) -> CaliptraResult<()> {
    hmac.hmac(
        HmacKey::Array4x16(&Array4x16::default()),
        HmacData::from(&[0]),
        trng,
        KeyWriteArgs::new(slot, KeyUsage::default().set_hmac_key_en().set_aes_key_en()).into(),
        HmacMode::Hmac512,
    )
}

fn check_aes_decrypt_mdk_to_fw(aes: &mut Aes, trng: &mut Trng) -> CaliptraResult<()> {
    cprintln!("[ROM] Checking AES-256-ECB decrypt from MDK to FW");
    // Assertion:
    let mut output = [0; 16];
    let res = aes.aes_256_ecb(
        AesKey::KV(KeyReadArgs::new(KEY_ID_MDK)),
        AesOperation::Decrypt,
        &[0; 16],
        &mut output,
    );

    match res {
        Ok(res) => {
            cprintln!("[ROM] check_aes_decrypt_mdk_to_fw PASSED");
            Ok(res)
        }
        Err(e) => {
            cprintln!("[ROM] check_aes_decrypt_mdk_to_fw FAILED");
            Err(e)
        }
    }
}

fn check_hmac_ocp_kv_to_ocp_kv_lock_mode(hmac: &mut Hmac, trng: &mut Trng) -> CaliptraResult<()> {
    cprintln!("[ROM] Checking OCP to OCP KV HMAC after LOCK mode enabled");
    // Assertion:
    // After ROM enables LOCK mode, it should still be possible to do HMAC(key=HEK, dest=LOCK_KV)
    let res = hmac.hmac(
        HmacKey::Key(KeyReadArgs::new(KEY_ID_HEK)),
        HmacData::Slice(&[0; 32]),
        trng,
        HmacTag::Key(KeyWriteArgs::new(KEY_ID_MDK, KeyUsage::default())),
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
        HmacTag::Key(KeyWriteArgs::new(KEY_ID_MDK, KeyUsage::default())),
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
