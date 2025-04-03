// Licensed under the Apache-2.0 license

use crate::{dpe_crypto::DpeCrypto, Drivers, PauserPrivileges};

use caliptra_cfi_derive_git::cfi_impl_fn;
use caliptra_cfi_lib_git::{cfi_assert, cfi_assert_eq, cfi_launder};

use caliptra_common::cfi_check;
use caliptra_common::mailbox_api::{
    MailboxResp, SignWithExportedEcdsaReq, SignWithExportedEcdsaResp,
};
use caliptra_error::{CaliptraError, CaliptraResult};

use crypto::ecdsa::curve_384::{EcdsaPub384, EcdsaSignature384};
use crypto::ecdsa::{EcdsaPubKey, EcdsaSignature};
use crypto::{Crypto, Digest, ExportedPubKey, Sha384, Signature};
use dpe::MAX_EXPORTED_CDI_SIZE;
use zerocopy::{FromBytes, TryFromBytes};

pub struct SignWithExportedEcdsaCmd;
impl SignWithExportedEcdsaCmd {
    /// SignWithExported signs a `digest` using an ECDSA keypair derived from a exported_cdi
    /// handle and the CDI stored in DPE.
    ///
    /// # Arguments
    ///
    /// * `env` - DPE environment containing Crypto and Platform implementations
    /// * `digest` - The data to be signed
    /// * `exported_cdi_handle` - A handle from DPE that is exchanged for a CDI.
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn ecdsa_sign(
        env: &mut DpeCrypto,
        digest: Sha384,
        exported_cdi_handle: &[u8; MAX_EXPORTED_CDI_SIZE],
    ) -> CaliptraResult<(EcdsaSignature384, EcdsaPub384)> {
        let key_pair =
            env.derive_key_pair_exported(exported_cdi_handle, b"Exported ECC", b"Exported ECC");

        cfi_check!(key_pair);
        let (priv_key, pub_key) = key_pair
            .map_err(|_| CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_ECDSA_KEY_DERIVIATION_FAILED)?;

        let Ok(Signature::Ecdsa(EcdsaSignature::Ecdsa384(sig))) =
            env.sign_with_derived(&Digest::Sha384(digest), &priv_key, &pub_key)
        else {
            Err(CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_ECDSA_SIGNATURE_FAILED)?
        };

        let Ok(ExportedPubKey::Ecdsa(EcdsaPubKey::Ecdsa384(pub_key))) =
            env.export_public_key(&pub_key)
        else {
            Err(CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_ECDSA_SIGNATURE_FAILED)?
        };

        Ok((sig, pub_key))
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers, cmd_args: &[u8]) -> CaliptraResult<MailboxResp> {
        let cmd = SignWithExportedEcdsaReq::ref_from_bytes(cmd_args)
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

        match drivers.caller_privilege_level() {
            // SIGN_WITH_EXPORTED_ECDSA MUST only be called from PL0
            PauserPrivileges::PL0 => (),
            PauserPrivileges::PL1 => {
                return Err(CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL);
            }
        }

        let key_id_rt_cdi = Drivers::get_key_id_rt_cdi(drivers)?;
        let key_id_rt_priv_key = Drivers::get_key_id_rt_priv_key(drivers)?;

        let mut crypto = DpeCrypto::new(
            &mut drivers.sha2_512_384,
            &mut drivers.trng,
            &mut drivers.ecc384,
            &mut drivers.hmac,
            &mut drivers.key_vault,
            &mut drivers.persistent_data.get_mut().fht.rt_dice_pub_key,
            key_id_rt_cdi,
            key_id_rt_priv_key,
            &mut drivers.exported_cdi_slots,
        );

        let digest = Sha384::try_read_from_bytes(&cmd.tbs)
            .map_err(|_| CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_ECDSA_INVALID_DIGEST)?;
        let (sig, pub_key) = Self::ecdsa_sign(&mut crypto, digest, &cmd.exported_cdi_handle)?;

        let mut resp = SignWithExportedEcdsaResp::default();
        let (r, s) = sig
            .as_slice()
            .map_err(|_| CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_ECDSA_INVALID_SIGNATURE)?;
        resp.signature_r[..r.len()].copy_from_slice(r);
        resp.signature_s[..s.len()].copy_from_slice(s);

        let (x, y) = pub_key
            .as_slice()
            .map_err(|_| CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_ECDSA_INVALID_SIGNATURE)?;
        resp.derived_pubkey_x[..x.len()].copy_from_slice(x);
        resp.derived_pubkey_y[..y.len()].copy_from_slice(y);

        Ok(MailboxResp::SignWithExportedEcdsa(resp))
    }
}
