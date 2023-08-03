// Licensed under the Apache-2.0 license

use core::ops::Range;

use caliptra_common::cprintln;
use caliptra_common::memory_layout::ICCM_ORG;
use caliptra_common::memory_layout::ICCM_SIZE;
use caliptra_common::memory_layout::MBOX_ORG;
use caliptra_common::FMC_ORG;
use caliptra_common::MAN1_ORG;
use caliptra_common::RUNTIME_ORG;
use caliptra_drivers::Array4x12;
use caliptra_drivers::CaliptraError;
use caliptra_drivers::CaliptraResult;
use caliptra_drivers::DataVault;
use caliptra_drivers::Ecc384;
use caliptra_drivers::Ecc384PubKey;
use caliptra_drivers::Ecc384Result;
use caliptra_drivers::Ecc384Signature;
use caliptra_drivers::Lifecycle;
use caliptra_drivers::Lms;
use caliptra_drivers::LmsResult;
use caliptra_drivers::LmsVerifyConfig;
use caliptra_drivers::ResetReason;
use caliptra_drivers::Sha256;
use caliptra_drivers::Sha384Acc;
use caliptra_drivers::SocIfc;
use caliptra_drivers::VendorPubKeyRevocation;
use caliptra_image_types::ImageDigest;
use caliptra_image_types::ImageEccPubKey;
use caliptra_image_types::ImageEccSignature;
use caliptra_image_types::ImageLmsPublicKey;
use caliptra_image_types::ImageLmsSignature;
use caliptra_image_types::SHA384_DIGEST_BYTE_SIZE;
use caliptra_image_verify::ImageVerificationEnv;
use caliptra_image_verify::ImageVerifier;
use caliptra_kat::{Ecc384Kat, Hmac384Kat, LmsKat, Sha1Kat, Sha256Kat, Sha384AccKat, Sha384Kat};
use caliptra_registers::mbox::enums::MboxStatusE;
use zerocopy::{AsBytes, FromBytes};

use crate::Drivers;
use crate::MemoryRegions;

pub struct FipsModule;

#[repr(C)]
#[derive(Clone, Debug, Default, AsBytes, FromBytes)]
pub struct VersionResponse {
    pub mode: u32,
    pub fips_rev: [u32; 3],
    pub name: [u8; 12],
}

impl VersionResponse {
    pub const NAME: [u8; 12] = *b"Caliptra RTM";
    pub const MODE: u32 = 0x46495053;

    pub fn new(_env: &Drivers) -> Self {
        Self {
            mode: Self::MODE,
            // Just return all zeroes for now.
            fips_rev: [1, 0, 0],
            name: Self::NAME,
        }
    }
    pub fn copy_to_mbox(&self, env: &mut Drivers) -> CaliptraResult<()> {
        let mbox = &mut env.mbox;
        mbox.write_response(self.as_bytes())
    }
}

/// Fips command handler.
impl FipsModule {
    pub fn version(env: &mut Drivers) -> CaliptraResult<MboxStatusE> {
        cprintln!("[rt] FIPS Version");

        VersionResponse::new(env).copy_to_mbox(env)?;
        Ok(MboxStatusE::DataReady)
    }

    fn copy_image_to_mbox(env: &mut Drivers) {
        let mbox_ptr = MBOX_ORG as *mut u8;
        let man1_ptr = MAN1_ORG as *const u8;

        let fmc_org = FMC_ORG as *mut u8;
        let rt_org = RUNTIME_ORG as *const u8;

        unsafe {
            let mut offset = 0;
            MemoryRegions::copy_bytes(
                man1_ptr,
                mbox_ptr.add(offset),
                env.manifest.as_bytes().len(),
            );
            offset += env.manifest.as_bytes().len();
            MemoryRegions::copy_bytes(
                fmc_org,
                mbox_ptr.add(offset),
                env.manifest.fmc.size as usize,
            );
            offset += env.manifest.fmc.size as usize;
            MemoryRegions::copy_bytes(
                rt_org,
                mbox_ptr.add(offset),
                env.manifest.runtime.size as usize,
            );
        }
    }
    pub fn self_test(env: &mut Drivers) -> CaliptraResult<MboxStatusE> {
        cprintln!("[rt] FIPS self test");
        Self::execute_kats(env)?;

        //env.regions.mbox.fill(0);

        // Reconstruct the image in the mailbox.
        Self::copy_image_to_mbox(env);

        let venv = FipsTestEnv {
            sha384_acc: &mut env.sha384_acc,
            ecc384: &mut env.ecc384,
            sha256: &mut env.sha256,
            soc_ifc: &mut env.soc_ifc,
            data_vault: &env.data_vault,
        };

        let mut verifier = ImageVerifier::new(venv);
        //Verify Caliptra image loaded to ICCM by ROM using the manifest stored in DCCM.
        verifier.verify(
            &env.manifest,
            caliptra_common::memory_layout::MBOX_SIZE,
            ResetReason::ColdReset,
        )?;

        Ok(MboxStatusE::CmdComplete)
    }

    pub fn shutdown(env: &mut Drivers) -> CaliptraResult<MboxStatusE> {
        Self::zeroize(env);
        env.mbox.set_status(MboxStatusE::CmdComplete);

        Err(CaliptraError::RUNTIME_SHUTDOWN)
    }

    /// Clear data structures in DCCM.  
    fn zeroize(env: &mut Drivers) {
        env.regions.zeroize();
    }

    /// Execute KAT for cryptographic algorithms implemented in H/W.
    fn execute_kats(env: &mut Drivers) -> CaliptraResult<()> {
        cprintln!("[kat] Executing SHA2-256 Engine KAT");
        Sha256Kat::default().execute(&mut env.sha256)?;

        cprintln!("[kat] Executing SHA2-384 Engine KAT");
        Sha384Kat::default().execute(&mut env.sha384)?;

        cprintln!("[kat] Executing SHA2-384 Accelerator KAT");
        Sha384AccKat::default().execute(&mut env.sha384_acc)?;

        cprintln!("[kat] Executing ECC-384 Engine KAT");
        Ecc384Kat::default().execute(&mut env.ecc384, &mut env.trng)?;

        cprintln!("[kat] Executing HMAC-384 Engine KAT");
        Hmac384Kat::default().execute(&mut env.hmac384, &mut env.trng)?;

        cprintln!("[kat] sha1");
        Sha1Kat::default().execute(&mut env.sha1)?;

        cprintln!("[kat] LMS");
        LmsKat::default().execute(&mut env.sha256, &env.lms)?;

        Ok(())
    }
}

struct FipsTestEnv<'a> {
    pub(crate) sha384_acc: &'a mut Sha384Acc,
    pub(crate) ecc384: &'a mut Ecc384,
    pub(crate) sha256: &'a mut Sha256,
    pub(crate) soc_ifc: &'a mut SocIfc,
    pub(crate) data_vault: &'a DataVault,
}

impl ImageVerificationEnv for FipsTestEnv<'_> {
    fn sha384_digest(&mut self, offset: u32, len: u32) -> CaliptraResult<ImageDigest> {
        loop {
            if let Some(mut txn) = self.sha384_acc.try_start_operation() {
                let mut digest = Array4x12::default();
                txn.digest(len, offset, false, &mut digest)?;
                return Ok(digest.0);
            }
        }
    }

    /// ECC-384 Verification routine
    fn ecc384_verify(
        &mut self,
        digest: &ImageDigest,
        pub_key: &ImageEccPubKey,
        sig: &ImageEccSignature,
    ) -> CaliptraResult<Ecc384Result> {
        // TODO: Remove following conversions after refactoring the driver ECC384PubKey
        // for use across targets
        let pub_key = Ecc384PubKey {
            x: pub_key.x.into(),
            y: pub_key.y.into(),
        };

        // TODO: Remove following conversions after refactoring the driver SHA384Digest
        // for use across targets
        let digest: Array4x12 = digest.into();

        // TODO: Remove following conversions after refactoring the driver ECC384Signature
        // for use across targets
        let sig = Ecc384Signature {
            r: sig.r.into(),
            s: sig.s.into(),
        };

        self.ecc384.verify(&pub_key, &digest, &sig)
    }

    fn lms_verify(
        &mut self,
        digest: &ImageDigest,
        pub_key: &ImageLmsPublicKey,
        sig: &ImageLmsSignature,
    ) -> CaliptraResult<LmsResult> {
        let mut message = [0u8; SHA384_DIGEST_BYTE_SIZE];
        for i in 0..digest.len() {
            message[i * 4..][..4].copy_from_slice(&digest[i].to_be_bytes());
        }
        Lms::default().verify_lms_signature(self.sha256, &message, pub_key, sig)
    }

    /// Retrieve Vendor Public Key Digest
    fn vendor_pub_key_digest(&self) -> ImageDigest {
        self.soc_ifc.fuse_bank().vendor_pub_key_hash().into()
    }

    /// Retrieve Vendor ECC Public Key Revocation Bitmask
    fn vendor_ecc_pub_key_revocation(&self) -> VendorPubKeyRevocation {
        self.soc_ifc.fuse_bank().vendor_ecc_pub_key_revocation()
    }

    /// Retrieve Vendor LMS Public Key Revocation Bitmask
    fn vendor_lms_pub_key_revocation(&self) -> u32 {
        self.soc_ifc.fuse_bank().vendor_lms_pub_key_revocation()
    }

    /// Retrieve Owner Public Key Digest from fuses
    fn owner_pub_key_digest_fuses(&self) -> ImageDigest {
        self.soc_ifc.fuse_bank().owner_pub_key_hash().into()
    }

    /// Retrieve Anti-Rollback disable fuse value
    fn anti_rollback_disable(&self) -> bool {
        self.soc_ifc.fuse_bank().anti_rollback_disable()
    }

    /// Retrieve Device Lifecycle state
    fn dev_lifecycle(&self) -> Lifecycle {
        self.soc_ifc.lifecycle()
    }

    /// Get the vendor key index saved in data vault on cold boot
    fn vendor_pub_key_idx_dv(&self) -> u32 {
        self.data_vault.ecc_vendor_pk_index()
    }

    /// Get the owner public key digest saved in the dv on cold boot
    fn owner_pub_key_digest_dv(&self) -> ImageDigest {
        self.data_vault.owner_pk_hash().into()
    }

    // Get the fmc digest from the data vault on cold boot
    fn get_fmc_digest_dv(&self) -> ImageDigest {
        self.data_vault.fmc_tci().into()
    }

    // Get Fuse FMC Key Manifest SVN
    fn fmc_fuse_svn(&self) -> u32 {
        self.soc_ifc.fuse_bank().fmc_fuse_svn()
    }

    // Get Runtime fuse SVN
    fn runtime_fuse_svn(&self) -> u32 {
        self.soc_ifc.fuse_bank().runtime_fuse_svn()
    }

    fn iccm_range(&self) -> Range<u32> {
        Range {
            start: ICCM_ORG,
            end: ICCM_ORG + ICCM_SIZE,
        }
    }

    fn lms_verify_enabled(&self) -> bool {
        self.soc_ifc.fuse_bank().lms_verify() == LmsVerifyConfig::EcdsaAndLms
    }
}
