/*++

Licensed under the Apache-2.0 license.

File Name:

    dpe_crypto.rs

Abstract:

    File contains DpeCrypto implementation.

--*/

#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive_git::cfi_impl_fn;
use caliptra_common::keyids::{
    KEY_ID_DPE_CDI, KEY_ID_DPE_PRIV_KEY, KEY_ID_EXPORTED_DPE_CDI, KEY_ID_TMP,
};
use caliptra_drivers::{
    hmac_kdf,
    sha2_512_384::{Sha2DigestOpTrait, Sha384},
    Array4x12, Ecc384, Ecc384PrivKeyIn, Ecc384PubKey, Ecc384Scalar, Ecc384Seed, Hmac, HmacMode,
    KeyId, KeyReadArgs, KeyUsage, KeyVault, KeyWriteArgs, Sha2DigestOp, Sha2_512_384, Trng,
};
use crypto::{
    ecdsa::{
        curve_384::{self, EcdsaPub384, EcdsaSignature384},
        EcdsaPubKey, EcdsaSignature,
    },
    Crypto, CryptoEngine, CryptoError, Digest, DigestAlgorithm, DigestType, ExportedPubKey, Hasher,
    Signature, SignatureAlgorithm, SignatureType,
};
use dpe::{EcdsaAlgorithm, ExportedCdiHandle, MAX_EXPORTED_CDI_SIZE};
use zerocopy::TryFromBytes;

// Currently only can export CDI once, but in the future we may want to support multiple exported
// CDI handles at the cost of using more KeyVault slots.
pub const EXPORTED_HANDLES_NUM: usize = 1;
pub type ExportedCdiHandles = [Option<(KeyId, ExportedCdiHandle)>; EXPORTED_HANDLES_NUM];

pub struct DpeCrypto<'a> {
    sha2_512_384: &'a mut Sha2_512_384,
    trng: &'a mut Trng,
    ecc384: &'a mut Ecc384,
    hmac: &'a mut Hmac,
    key_vault: &'a mut KeyVault,
    rt_pub_key: &'a mut Ecc384PubKey,
    key_id_rt_cdi: KeyId,
    key_id_rt_priv_key: KeyId,
    exported_cdi_slots: &'a mut ExportedCdiHandles,
}

impl<'a> CryptoEngine for DpeCrypto<'a> {}

impl<'a> SignatureType for DpeCrypto<'a> {
    const SIGNATURE_ALGORITHM: SignatureAlgorithm =
        SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit384);
}

impl<'a> DigestType for DpeCrypto<'a> {
    const DIGEST_ALGORITHM: DigestAlgorithm = DigestAlgorithm::Sha384;
}

impl<'a> DpeCrypto<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sha2_512_384: &'a mut Sha2_512_384,
        trng: &'a mut Trng,
        ecc384: &'a mut Ecc384,
        hmac: &'a mut Hmac,
        key_vault: &'a mut KeyVault,
        rt_pub_key: &'a mut Ecc384PubKey,
        key_id_rt_cdi: KeyId,
        key_id_rt_priv_key: KeyId,
        exported_cdi_slots: &'a mut ExportedCdiHandles,
    ) -> Self {
        Self {
            sha2_512_384,
            trng,
            ecc384,
            hmac,
            key_vault,
            rt_pub_key,
            key_id_rt_cdi,
            key_id_rt_priv_key,
            exported_cdi_slots,
        }
    }

    fn derive_cdi_inner(
        &mut self,
        measurement: &Digest,
        info: &[u8],
        key_id: KeyId,
    ) -> Result<<DpeCrypto<'a> as crypto::Crypto>::Cdi, CryptoError> {
        let mut hasher = self.hash_initialize()?;
        hasher.update(measurement.bytes())?;
        hasher.update(info)?;
        let context = hasher.finish()?;

        hmac_kdf(
            self.hmac,
            KeyReadArgs::new(self.key_id_rt_cdi).into(),
            b"derive_cdi",
            Some(context.bytes()),
            self.trng,
            KeyWriteArgs::new(
                key_id,
                KeyUsage::default()
                    .set_hmac_key_en()
                    .set_ecc_key_gen_seed_en(),
            )
            .into(),
            HmacMode::Hmac384,
        )
        .map_err(|e| CryptoError::CryptoLibError(u32::from(e)))?;
        Ok(key_id)
    }

    fn derive_key_pair_inner(
        &mut self,
        cdi: &<DpeCrypto<'a> as crypto::Crypto>::Cdi,
        label: &[u8],
        info: &[u8],
        key_id: KeyId,
    ) -> Result<
        (
            <DpeCrypto<'a> as crypto::Crypto>::PrivKey,
            <DpeCrypto<'a> as crypto::Crypto>::PubKey,
        ),
        CryptoError,
    > {
        hmac_kdf(
            self.hmac,
            KeyReadArgs::new(*cdi).into(),
            label,
            Some(info),
            self.trng,
            KeyWriteArgs::new(KEY_ID_TMP, KeyUsage::default().set_ecc_key_gen_seed_en()).into(),
            HmacMode::Hmac384,
        )
        .map_err(|e| CryptoError::CryptoLibError(u32::from(e)))?;

        let pub_key = self
            .ecc384
            .key_pair(
                &Ecc384Seed::Key(KeyReadArgs::new(KEY_ID_TMP)),
                &Array4x12::default(),
                self.trng,
                KeyWriteArgs::new(key_id, KeyUsage::default().set_ecc_private_key_en()).into(),
            )
            .map_err(|e| CryptoError::CryptoLibError(u32::from(e)))?;
        let pub_key = EcdsaPub384::from_slice(
            &<[u8; curve_384::CURVE_SIZE]>::from(pub_key.x),
            &<[u8; curve_384::CURVE_SIZE]>::from(pub_key.y),
        )?;
        Ok((key_id, pub_key))
    }

    pub fn get_cdi_from_exported_handle(
        &mut self,
        exported_cdi_handle: &[u8; MAX_EXPORTED_CDI_SIZE],
    ) -> Option<<DpeCrypto<'a> as crypto::Crypto>::Cdi> {
        for cdi_slot in self.exported_cdi_slots.iter() {
            match cdi_slot {
                Some((cdi, handle)) if handle == exported_cdi_handle => return Some(*cdi),
                _ => (),
            }
        }
        None
    }
}

impl Drop for DpeCrypto<'_> {
    fn drop(&mut self) {
        let _ = self.key_vault.erase_key(KEY_ID_DPE_CDI);
        let _ = self.key_vault.erase_key(KEY_ID_DPE_PRIV_KEY);
        let _ = self.key_vault.erase_key(KEY_ID_TMP);
    }
}

pub struct DpeHasher<'a> {
    op: Sha2DigestOp<'a, Sha384>,
}

impl<'a> DpeHasher<'a> {
    pub fn new(op: Sha2DigestOp<'a, Sha384>) -> Self {
        Self { op }
    }
}

impl Hasher for DpeHasher<'_> {
    fn update(&mut self, bytes: &[u8]) -> Result<(), CryptoError> {
        self.op
            .update(bytes)
            .map_err(|e| CryptoError::HashError(u32::from(e)))
    }

    fn finish(self) -> Result<Digest, CryptoError> {
        let mut digest = Array4x12::default();
        self.op
            .finalize(&mut digest)
            .map_err(|e| CryptoError::HashError(u32::from(e)))?;
        let digest = <[u8; DigestAlgorithm::Sha384.size()]>::from(digest);
        let digest = crypto::Sha384::try_read_from_bytes(&digest).map_err(|_| CryptoError::Size)?;
        Ok(Digest::Sha384(digest))
    }
}

impl Crypto for DpeCrypto<'_> {
    type Cdi = KeyId;
    type Hasher<'b>
        = DpeHasher<'b>
    where
        Self: 'b;
    type PrivKey = KeyId;
    type PubKey = EcdsaPub384;

    fn rand_bytes(&mut self, dst: &mut [u8]) -> Result<(), CryptoError> {
        for chunk in dst.chunks_mut(48) {
            let trng_bytes = <[u8; 48]>::from(
                self.trng
                    .generate()
                    .map_err(|e| CryptoError::CryptoLibError(u32::from(e)))?,
            );
            chunk.copy_from_slice(&trng_bytes[..chunk.len()])
        }
        Ok(())
    }

    fn hash_initialize(&mut self) -> Result<Self::Hasher<'_>, CryptoError> {
        let op = self
            .sha2_512_384
            .sha384_digest_init()
            .map_err(|e| CryptoError::HashError(u32::from(e)))?;
        Ok(DpeHasher::new(op))
    }

    fn get_pubkey_serial(
        &mut self,
        pub_key: &ExportedPubKey,
        serial: &mut [u8],
    ) -> Result<(), CryptoError> {
        if serial.len() < DigestAlgorithm::Sha384.size() {
            return Err(CryptoError::Size);
        }

        let mut hasher = self.hash_initialize()?;
        let ExportedPubKey::Ecdsa(pub_key) = pub_key;
        let (x, y) = pub_key.as_slice()?;

        hasher.update(&[0x4u8])?;
        hasher.update(x)?;
        hasher.update(y)?;
        let digest = hasher.finish()?;

        let src = digest.bytes();
        if serial.len() != src.len() * 2 {
            return Err(CryptoError::Size);
        }

        let mut curr_idx = 0;
        const HEX_CHARS: &[u8; 16] = b"0123456789ABCDEF";
        for &b in src {
            let h1 = (b >> 4) as usize;
            let h2 = (b & 0xF) as usize;
            if h1 >= HEX_CHARS.len()
                || h2 >= HEX_CHARS.len()
                || curr_idx >= serial.len()
                || curr_idx + 1 >= serial.len()
            {
                return Err(CryptoError::CryptoLibError(0));
            }
            serial[curr_idx] = HEX_CHARS[h1];
            serial[curr_idx + 1] = HEX_CHARS[h2];
            curr_idx += 2;
        }
        Ok(())
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn derive_exported_cdi(
        &mut self,
        measurement: &Digest,
        info: &[u8],
    ) -> Result<ExportedCdiHandle, CryptoError> {
        let mut exported_cdi_handle = [0; MAX_EXPORTED_CDI_SIZE];
        self.rand_bytes(&mut exported_cdi_handle)?;

        // Currently we only use one slot for export CDIs.
        let cdi_slot = KEY_ID_EXPORTED_DPE_CDI;
        // Copy the CDI slots to work around the borrow checker.
        let mut slots_clone = *self.exported_cdi_slots;

        for slot in slots_clone.iter_mut() {
            match slot {
                // Matching existing slot
                Some((cached_cdi, _handle)) if *cached_cdi == cdi_slot => {
                    Err(CryptoError::ExportedCdiHandleDuplicateCdi)?
                }
                // Empty slot
                None => {
                    let cdi = self.derive_cdi_inner(measurement, info, cdi_slot)?;
                    *slot = Some((cdi, exported_cdi_handle));
                    // We need to update `self.exported_cdi_slots` with our mutation.
                    *self.exported_cdi_slots = slots_clone;
                    return Ok(exported_cdi_handle);
                }
                // Used slot for a different CDI.
                _ => (),
            }
        }
        // Never found an available slot.
        Err(CryptoError::ExportedCdiHandleLimitExceeded)
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn derive_cdi(&mut self, measurement: &Digest, info: &[u8]) -> Result<Self::Cdi, CryptoError> {
        let res = self.derive_cdi_inner(measurement, info, KEY_ID_DPE_CDI);
        res
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn derive_key_pair(
        &mut self,
        cdi: &Self::Cdi,
        label: &[u8],
        info: &[u8],
    ) -> Result<(Self::PrivKey, Self::PubKey), CryptoError> {
        let res = self.derive_key_pair_inner(cdi, label, info, KEY_ID_DPE_PRIV_KEY);
        res
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn derive_key_pair_exported(
        &mut self,
        exported_handle: &ExportedCdiHandle,
        label: &[u8],
        info: &[u8],
    ) -> Result<(Self::PrivKey, Self::PubKey), CryptoError> {
        let cdi = {
            let mut cdi = None;
            for cdi_slot in self.exported_cdi_slots.iter() {
                match cdi_slot {
                    Some((stored_cdi, stored_handle)) if stored_handle == exported_handle => {
                        cdi = Some(*stored_cdi);
                        break;
                    }
                    _ => (),
                }
            }
            cdi.ok_or(CryptoError::InvalidExportedCdiHandle)
        }?;
        self.derive_key_pair_inner(&cdi, label, info, KEY_ID_TMP)
    }

    fn sign_with_alias(&mut self, digest: &Digest) -> Result<Signature, CryptoError> {
        let pub_key = EcdsaPub384::from_slice(
            &<[u8; curve_384::CURVE_SIZE]>::from(self.rt_pub_key.x),
            &<[u8; curve_384::CURVE_SIZE]>::from(self.rt_pub_key.y),
        )?;
        self.sign_with_derived(digest, &self.key_id_rt_priv_key.clone(), &pub_key)
    }

    fn sign_with_derived(
        &mut self,
        digest: &Digest,
        priv_key: &Self::PrivKey,
        pub_key: &Self::PubKey,
    ) -> Result<Signature, CryptoError> {
        let priv_key_args = KeyReadArgs::new(*priv_key);
        let ecc_priv_key = Ecc384PrivKeyIn::Key(priv_key_args);

        let (x, y) = pub_key.as_slice()?;
        let ecc_pub_key = Ecc384PubKey {
            x: Ecc384Scalar::from(x),
            y: Ecc384Scalar::from(y),
        };

        let mut digest_arr = [0u8; Self::DIGEST_ALGORITHM.size()];
        digest_arr
            .get_mut(..Self::DIGEST_ALGORITHM.size())
            .ok_or(CryptoError::CryptoLibError(0))?
            .copy_from_slice(
                digest
                    .bytes()
                    .get(..Self::DIGEST_ALGORITHM.size())
                    .ok_or(CryptoError::CryptoLibError(0))?,
            );

        let sig = self
            .ecc384
            .sign(
                &ecc_priv_key,
                &ecc_pub_key,
                &Ecc384Scalar::from(digest_arr),
                self.trng,
            )
            .map_err(|e| CryptoError::CryptoLibError(u32::from(e)))?;
        let r = &<[u8; EcdsaAlgorithm::Bit384.curve_size()]>::from(&sig.r);
        let s = &<[u8; EcdsaAlgorithm::Bit384.curve_size()]>::from(&sig.s);

        Ok(Signature::Ecdsa(EcdsaSignature::Ecdsa384(
            EcdsaSignature384::from_slice(r, s).map_err(|e| CryptoError::Size)?,
        )))
    }

    fn export_public_key(&self, pub_key: &Self::PubKey) -> Result<ExportedPubKey, CryptoError> {
        Ok(ExportedPubKey::Ecdsa(EcdsaPubKey::Ecdsa384(
            pub_key.clone(),
        )))
    }
}
