// Licensed under the Apache-2.0 license

use crate::Drivers;
use caliptra_common::x509;
use caliptra_drivers::sha2_512_384::Sha2DigestOpTrait;
use caliptra_drivers::{Array4x12, KeyReadArgs, Mldsa87Seed, Mldsa87SignRnd};
use caliptra_error::{CaliptraError, CaliptraResult};
use caliptra_ocp_eat::csr_eat::{oids, CsrEatClaims};
use caliptra_ocp_eat::{cbor::TaggedOid, cbor_tags, CborEncoder, CoseSign1, ProtectedHeader};

mod fmc_alias;
mod ldevid;
mod rt_alias;

use fmc_alias::{generate_fmc_alias_ecc_csr, generate_fmc_alias_mldsa_csr};
use ldevid::{generate_ldevid_ecc_csr, generate_ldevid_mldsa_csr};
use rt_alias::{generate_rt_alias_ecc_csr, generate_rt_alias_mldsa_csr};

// Maximum size for CSR EAT claims payload (CBOR encoded)
// Calculation for ML-DSA CSR (worst case, assuming 7680-byte CSR):
// - Map header (3 items): 1 byte
// - Nonce claim (32 bytes): 1 (key 10) + 2 (bstr header) + 32 (data) = 35 bytes
// - CSR claim (7680 bytes): 5 (key -70001) + 3 (bstr header) + 7680 (data) = 7688 bytes
// - Attributes claim (1 OID, 11 bytes): 5 (key -70002) + 1 (array header) + 2 (tag 111) + 1 (bstr header) + 11 (OID) = 20 bytes
// Total: 7744 bytes, rounded up to 8KB for safety
pub(crate) const MAX_CSR_EAT_CLAIMS_SIZE: usize = 8192;
pub(crate) const MAX_CSR_SIZE: usize = 8192;

enum CryptoType {
    ECC384,
    MLDSA87,
}

pub(crate) enum DevIdKeyType {
    LdevId = 1,
    FmcAlias = 2,
    RtAlias = 3,
}

impl TryFrom<u32> for DevIdKeyType {
    type Error = CaliptraError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(DevIdKeyType::LdevId),
            2 => Ok(DevIdKeyType::FmcAlias),
            3 => Ok(DevIdKeyType::RtAlias),
            _ => Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS),
        }
    }
}

impl DevIdKeyType {
    pub fn to_kda_oid(&self) -> TaggedOid {
        match self {
            DevIdKeyType::LdevId => TaggedOid::new(oids::OCP_SECURITY_OID_KDA_OWNER_ENTROPY_FUSE),
            DevIdKeyType::FmcAlias => TaggedOid::new(oids::OCP_SECURITY_OID_KDA_FIRST_MUTABLE_CODE),
            DevIdKeyType::RtAlias => {
                TaggedOid::new(oids::OCP_SECURITY_OID_KDA_NON_FIRST_MUTABLE_CODE)
            }
        }
    }

    pub fn generate_ecc_csr(&self, drivers: &mut Drivers, csr_data: &mut [u8]) -> CaliptraResult<usize> {
        let csr_data = <&mut [u8; MAX_CSR_SIZE]>::try_from(csr_data)
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        match self {
            DevIdKeyType::LdevId => generate_ldevid_ecc_csr(drivers, csr_data),
            DevIdKeyType::FmcAlias => generate_fmc_alias_ecc_csr(drivers, csr_data),
            DevIdKeyType::RtAlias => generate_rt_alias_ecc_csr(drivers, csr_data),
        }
    }

    pub fn generate_mldsa_csr(&self, drivers: &mut Drivers, csr_data: &mut [u8]) -> CaliptraResult<usize> {
        let csr_data = <&mut [u8; MAX_CSR_SIZE]>::try_from(csr_data)
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        match self {
            DevIdKeyType::LdevId => generate_ldevid_mldsa_csr(drivers, csr_data),
            DevIdKeyType::FmcAlias => generate_fmc_alias_mldsa_csr(drivers, csr_data),
            DevIdKeyType::RtAlias => generate_rt_alias_mldsa_csr(drivers, csr_data),
        }
    }

    fn generate_csr_eat_claims(
        &self,
        drivers: &mut Drivers,
        nonce: &[u8; 32],
        eat_buffer: &mut [u8],
        crypto: CryptoType,
    ) -> CaliptraResult<usize> {
        let attributes = [self.to_kda_oid()];
        // generate CSR for key identified by key_id
        let mut csr_data = [0u8; MAX_CSR_SIZE];
        let csr_len = match crypto {
            CryptoType::ECC384 => self.generate_ecc_csr(drivers, &mut csr_data),
            CryptoType::MLDSA87 => self.generate_mldsa_csr(drivers, &mut csr_data),
        }?;

        let attested_csr = CsrEatClaims::with_nonce(
            csr_data
                .get(..csr_len)
                .ok_or(CaliptraError::RUNTIME_ATTESTED_CSR_EAT_ENCODING_ERROR)?,
            &attributes,
            nonce,
        );
        let mut cbor_eat_encoder = CborEncoder::new(eat_buffer);

        attested_csr
            .encode(&mut cbor_eat_encoder)
            .map_err(|_| CaliptraError::RUNTIME_ATTESTED_CSR_EAT_ENCODING_ERROR)?;

        Ok(cbor_eat_encoder.len())
    }

    fn hash_signature_context(
        drivers: &mut Drivers,
        cose_sign1: &CoseSign1,
        payload: &[u8],
    ) -> CaliptraResult<Array4x12> {
        let mut sha_op = drivers.sha2_512_384.sha384_digest_init()?;

        // Sig_structure = [ "Signature1", body_protected, external_aad, payload ]
        // All are CBOR encoded.
        
        // Use a small buffer for headers
        let mut header_buf = [0u8; 64];
        
        // 1. Array header (4 items)
        let len = {
            let mut encoder = CborEncoder::new(&mut header_buf);
            encoder.encode_array_header(4).map_err(|_| CaliptraError::RUNTIME_ATTESTED_CSR_COSE_SIGN1_ENCODING_ERROR)?;
            encoder.len()
        };
        sha_op.update(&header_buf[..len])?;

        // 2. "Signature1"
        let len = {
            let mut encoder = CborEncoder::new(&mut header_buf);
            encoder.encode_text("Signature1").map_err(|_| CaliptraError::RUNTIME_ATTESTED_CSR_COSE_SIGN1_ENCODING_ERROR)?;
            encoder.len()
        };
        sha_op.update(&header_buf[..len])?;

        // 3. body_protected (byte string)
        let protected_header_encoded = cose_sign1.get_protected_header_encoded()
            .map_err(|_| CaliptraError::RUNTIME_ATTESTED_CSR_COSE_SIGN1_ENCODING_ERROR)?;
        let len = {
            let mut encoder = CborEncoder::new(&mut header_buf);
            encoder.encode_type_value(caliptra_ocp_eat::cbor::MajorType::ByteString, protected_header_encoded.len() as u64)
                .map_err(|_| CaliptraError::RUNTIME_ATTESTED_CSR_COSE_SIGN1_ENCODING_ERROR)?;
            encoder.len()
        };
        sha_op.update(&header_buf[..len])?;
        sha_op.update(&protected_header_encoded)?;

        // 4. external_aad (empty byte string)
        sha_op.update(&[0x40])?; // CBOR empty bstr

        // 5. payload (byte string)
        let len = {
            let mut encoder = CborEncoder::new(&mut header_buf);
            encoder.encode_type_value(caliptra_ocp_eat::cbor::MajorType::ByteString, payload.len() as u64)
                .map_err(|_| CaliptraError::RUNTIME_ATTESTED_CSR_COSE_SIGN1_ENCODING_ERROR)?;
            encoder.len()
        };
        sha_op.update(&header_buf[..len])?;
        sha_op.update(payload)?;

        let mut digest = Array4x12::default();
        sha_op.finalize(&mut digest)?;
        Ok(digest)
    }

    pub fn generate_attested_ecc_csr(
        &self,
        drivers: &mut Drivers,
        payload: &[u8],
        rt_key_id: &[u8; 20],
        signed_eat_buffer: &mut [u8],
    ) -> CaliptraResult<usize> {
        // Get RT public key
        let rt_pub_key = drivers.persistent_data.get().fht.rt_dice_ecc_pub_key;

        // Create protected header
        let mut protected_header = ProtectedHeader::new_es384();
        protected_header.kid = Some(rt_key_id);

        let cose_sign1 = CoseSign1::new(signed_eat_buffer)
            .protected_header(&protected_header)
            .payload(payload);

        let digest = Self::hash_signature_context(drivers, &cose_sign1, payload)?;

        // Get RT Alias private key from key vault
        let key_id_rt_priv_key = Drivers::get_key_id_rt_ecc_priv_key(drivers)?;

        // Sign the digest with RT Alias private key
        let priv_key_args = KeyReadArgs::new(key_id_rt_priv_key);
        let priv_key = caliptra_drivers::Ecc384PrivKeyIn::Key(priv_key_args);
        let signature = drivers
            .ecc384
            .sign(priv_key, &rt_pub_key, &digest, &mut drivers.trng)?;

        // Convert signature to [u8; 96] format (r || s)
        let mut ecc384_signature = [0u8; 96];
        let r_bytes: [u8; 48] = signature.r.into();
        let s_bytes: [u8; 48] = signature.s.into();
        ecc384_signature[..48].copy_from_slice(&r_bytes);
        ecc384_signature[48..].copy_from_slice(&s_bytes);

        // Complete encoding COSE Sign1 structure with signature and CWT tag
        let signed_eat_len = cose_sign1
            .signature(&ecc384_signature)
            .encode(Some(&[cbor_tags::CWT]))
            .map_err(|_| CaliptraError::RUNTIME_ATTESTED_CSR_COSE_SIGN1_ENCODING_ERROR)?;

        Ok(signed_eat_len)
    }

    pub fn generate_attested_mldsa_csr(
        &self,
        drivers: &mut Drivers,
        payload: &[u8],
        rt_key_id: &[u8; 20],
        signed_eat_buffer: &mut [u8],
    ) -> CaliptraResult<usize> {
        // Get RT public key
        let rt_pub_key = Drivers::get_key_id_rt_mldsa_pub_key(drivers)?;

        // Create protected header
        let mut protected_header = ProtectedHeader::new_mldsa87();
        protected_header.kid = Some(rt_key_id);

        let cose_sign1 = CoseSign1::new(signed_eat_buffer)
            .protected_header(&protected_header)
            .payload(payload);

        let digest = Self::hash_signature_context(drivers, &cose_sign1, payload)?;

        let rt_seed = Drivers::get_key_id_rt_mldsa_keypair_seed(drivers)?;
        let key_args = KeyReadArgs::new(rt_seed);

        let signature = drivers.mldsa87.sign_var(
            Mldsa87Seed::Key(key_args),
            &rt_pub_key,
            digest.as_bytes(),
            &Mldsa87SignRnd::default(),
            &mut drivers.trng,
        )?;

        // Complete encoding COSE Sign1 structure with signature and CWT tag
        let signed_eat_len = cose_sign1
            .signature(signature.as_bytes())
            .encode(Some(&[cbor_tags::CWT]))
            .map_err(|_| CaliptraError::RUNTIME_ATTESTED_CSR_COSE_SIGN1_ENCODING_ERROR)?;

        Ok(signed_eat_len)
    }
}

// --- Mailbox command handlers ---

use crate::mutrefbytes;
use caliptra_api::mailbox::{GetAttestedEccCsrReq, GetAttestedMldsaCsrReq};
use caliptra_cfi_derive_git::cfi_impl_fn;
use caliptra_common::mailbox_api::{AttestedCsrResp, ResponseVarSize};
use zerocopy::{FromBytes, IntoBytes};

pub struct AttestedEccCsrCmd;

impl AttestedEccCsrCmd {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(
        drivers: &mut Drivers,
        cmd_args: &[u8],
        mbox_resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        // Convert cmd_args to GetAttestedEccCsrReq
        let cmd = GetAttestedEccCsrReq::ref_from_bytes(cmd_args)
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

        // Extract key_id and nonce
        let key_type = DevIdKeyType::try_from(cmd.key_id)?;
        let nonce = cmd.nonce;
        let mut env_csr_eat = [0u8; MAX_CSR_EAT_CLAIMS_SIZE];
        let csr_eat_len = key_type.generate_csr_eat_claims(
            drivers,
            &nonce,
            &mut env_csr_eat,
            CryptoType::ECC384,
        )?;

        // Compute RT Alias subject key identifier for COSE header kid
        let rt_pub_key = drivers.persistent_data.get().fht.rt_dice_ecc_pub_key;
        let rt_subj_sn = x509::subj_key_id(
            &mut drivers.sha256,
            &caliptra_common::crypto::PubKey::Ecc(&rt_pub_key),
        )?;

        // Sign EAT using COSE Sign1 with RT Alias private key
        let resp = mutrefbytes::<AttestedCsrResp>(mbox_resp)?;
        let csr_slice = &env_csr_eat
            .get(..csr_eat_len)
            .ok_or(CaliptraError::RUNTIME_ATTESTED_CSR_EAT_ENCODING_ERROR)?;
        let signed_eat_len = key_type.generate_attested_ecc_csr(
            drivers,
            csr_slice,
            &rt_subj_sn,
            resp.data.as_mut(),
        )?;

        resp.data_size = signed_eat_len as u32;
        resp.partial_len()
    }
}

pub struct AttestedMldsaCsrCmd;

impl AttestedMldsaCsrCmd {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(
        drivers: &mut Drivers,
        cmd_args: &[u8],
        mbox_resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        // Convert cmd_args to GetAttestedMldsaCsrReq
        let cmd = GetAttestedMldsaCsrReq::ref_from_bytes(cmd_args)
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

        // Extract key_id and nonce
        let key_type = DevIdKeyType::try_from(cmd.key_id)?;
        let nonce = cmd.nonce;
        let mut env_csr_eat = [0u8; MAX_CSR_EAT_CLAIMS_SIZE];
        let csr_eat_len = key_type.generate_csr_eat_claims(
            drivers,
            &nonce,
            &mut env_csr_eat,
            CryptoType::MLDSA87,
        )?;

        // Compute RT Alias subject key identifier for COSE header kid
        let rt_pub_key = Drivers::get_key_id_rt_mldsa_pub_key(drivers)?;
        let rt_subj_sn = x509::subj_key_id(
            &mut drivers.sha256,
            &caliptra_common::crypto::PubKey::Mldsa(&rt_pub_key),
        )?;

        // Sign EAT using COSE Sign1 with RT Alias private key
        let resp = mutrefbytes::<AttestedCsrResp>(mbox_resp)?;
        let csr_slice = &env_csr_eat
            .get(..csr_eat_len)
            .ok_or(CaliptraError::RUNTIME_ATTESTED_CSR_EAT_ENCODING_ERROR)?;
        let signed_eat_len = key_type.generate_attested_mldsa_csr(
            drivers,
            csr_slice,
            &rt_subj_sn,
            resp.data.as_mut(),
        )?;

        resp.data_size = signed_eat_len as u32;
        resp.partial_len()
    }
}
