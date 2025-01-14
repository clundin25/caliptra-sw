// Licensed under the Apache-2.0 license

use crate::{dpe_crypto::DpeCrypto, Drivers};

use caliptra_cfi_derive_git::cfi_impl_fn;
use caliptra_cfi_lib_git::{cfi_assert, cfi_assert_eq, cfi_launder};

use caliptra_common::mailbox_api::{MailboxResp, MailboxRespHeader, SignWithExportedReq, SignWithExportedResp};
use caliptra_error::{CaliptraError, CaliptraResult};

use crypto::{Crypto, Digest, EcdsaSig};
use dpe::{DPE_PROFILE, MAX_EXPORTED_CDI_SIZE};
use zerocopy::{FromBytes, IntoBytes};

pub struct SignWithExportedCmd;
impl SignWithExportedCmd {
    /// SignWithExported signs a `digest` using an ECDSA keypair derived from a exported_cdi
    /// handle and the CDI stored in DPE.
    ///
    /// # Arguments
    ///
    /// * `env` - DPE environment containing Crypto and Platform implementations
    /// * `digest` - The data to be signed
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn ecdsa_sign(
        env: &mut DpeCrypto,
        digest: &Digest,
        exported_cdi_handle: &[u8; MAX_EXPORTED_CDI_SIZE],
    ) -> CaliptraResult<EcdsaSig> {
        let algs = DPE_PROFILE.alg_len();
        // TODO(clundin): Add unique error codes.
        let cdi = env.get_cdi_from_exported_handle(exported_cdi_handle);
        // TODO(clundin): Actually handle this.
        let cdi = cdi.unwrap();

        let key_label = b"Exported ECC";
        let key_pair =
            env.derive_key_pair_exported(algs, &cdi, key_label, b"Exported Handle");

        if cfi_launder(key_pair.is_ok()) {
            #[cfg(not(feature = "no-cfi"))]
            cfi_assert!(key_pair.is_ok());
        } else {
            #[cfg(not(feature = "no-cfi"))]
            cfi_assert!(key_pair.is_err());
        }
        let (priv_key, pub_key) =
            key_pair.map_err(|_| CaliptraError::RUNTIME_INITIALIZE_DPE_FAILED)?;

        let sig = env
            .ecdsa_sign_with_derived(algs, digest, &priv_key, &pub_key)
            .map_err(|_| CaliptraError::RUNTIME_INITIALIZE_DPE_FAILED)?;

        Ok(sig)
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers, cmd_args: &[u8]) -> CaliptraResult<MailboxResp> {
        let cmd = SignWithExportedReq::ref_from_bytes(cmd_args)
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        let key_id_rt_cdi = Drivers::get_key_id_rt_cdi(drivers)?;
        let key_id_rt_priv_key = Drivers::get_key_id_rt_priv_key(drivers)?;
        let mut crypto = DpeCrypto::new(
            &mut drivers.sha384,
            &mut drivers.trng,
            &mut drivers.ecc384,
            &mut drivers.hmac384,
            &mut drivers.key_vault,
            &mut drivers.persistent_data.get_mut().fht.rt_dice_pub_key,
            key_id_rt_cdi,
            key_id_rt_priv_key,
        );
        crypto.with_exported_cdi_slots(&mut drivers.exported_cdi_slots);

        // TODO(clundin): Update error code.
        let digest =
            Digest::new(&cmd.digest).map_err(|_| CaliptraError::RUNTIME_INVALID_CHECKSUM)?;
        // TODO(clundin): Can we / should we make these assumptions for the signature type?
        // I think we need to expose more metadata.
        let EcdsaSig { r, s } = Self::ecdsa_sign(&mut crypto, &digest, &cmd.exported_cdi)?;

        let mut resp = SignWithExportedResp::default();
        resp.signature[..r.bytes().len()].copy_from_slice(r.bytes());
        resp.signature[r.bytes().len()..s.bytes().len() + r.bytes().len()]
            .copy_from_slice(s.bytes());
        resp.signature_size = (s.bytes().len() + r.bytes().len()) as u32;
        Ok(MailboxResp::SignWithExported(resp))
    }
}
