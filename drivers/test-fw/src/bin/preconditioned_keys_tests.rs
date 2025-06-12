// Licensed under the Apache-2.0 license

#![no_std]
#![no_main]

use caliptra_cfi_lib::CfiCounter;
use caliptra_drivers::{
    cprintln, hmac_kdf, Aes, AesKey, Array4x12, Array4x16, Array4x8, Ecc384, Ecc384PrivKeyOut,
    Ecc384Scalar, Ecc384Seed, Hmac, HmacData, HmacKey, HmacMode, HmacTag, KeyId, KeyReadArgs,
    KeyUsage, KeyWriteArgs, Sha256, Sha256Alg, Sha256DigestOp, Trng,
};
use caliptra_registers::aes::AesReg;
use caliptra_registers::aes_clp::AesClpReg;
use caliptra_registers::csrng::CsrngReg;
use caliptra_registers::ecc::EccReg;
use caliptra_registers::entropy_src::EntropySrcReg;
use caliptra_registers::hmac::HmacReg;
use caliptra_registers::sha256::Sha256Reg;
use caliptra_registers::soc_ifc::SocIfcReg;
use caliptra_registers::soc_ifc_trng::SocIfcTrngReg;
use caliptra_test_harness::test_suite;

use zerocopy::FromBytes;

fn test_preconditioned_keys() {
    let mut ecc = unsafe { Ecc384::new(EccReg::new()) };
    let mut aes = unsafe { Aes::new(AesReg::new(), AesClpReg::new()) };
    let mut hmac = unsafe { Hmac::new(HmacReg::new()) };
    let mut sha = unsafe { Sha256::new(Sha256Reg::new()) };
    let mut trng = unsafe {
        Trng::new(
            CsrngReg::new(),
            EntropySrcReg::new(),
            SocIfcTrngReg::new(),
            &SocIfcReg::new(),
        )
        .unwrap()
    };

    let mut entropy_gen = || trng.generate4();
    CfiCounter::reset(&mut entropy_gen);

    let aes_keys = [
        Array4x16::default(),
        Array4x16::default(),
        Array4x16::default(),
    ];

    let mut digest_op = sha.digest_init().unwrap();
    let completed_digest_op = aes_keys
        .iter()
        .map(|&key| {
            let mut out = [0; 32];
            let key: [u8; 64] = key.into();
            let (left, rem) = <[u8; 32]>::ref_from_prefix(&key).unwrap();
            let right = <[u8; 32]>::ref_from_bytes(rem).unwrap();
            let key = AesKey::Split(left, right);

            let _ = aes
                .aes_256_gcm_encrypt(
                    &mut trng,
                    caliptra_drivers::AesGcmIv::Random,
                    key,
                    b"key",
                    &[0; 32],
                    &mut out,
                    16,
                )
                .unwrap();
            out
        })
        .fold(digest_op, |mut digest_op, digest| {
            assert!(digest_op.update(&digest).is_ok());
            digest_op
        });

    let mut composite_key_checksum = Array4x8::default();
    assert!(completed_digest_op
        .finalize(&mut composite_key_checksum)
        .is_ok());

    assert_ne!(composite_key_checksum, Array4x8::default());
    let composite_key_slice: [u8; 32] = composite_key_checksum.into();

    let mut hkdf_extract = [0; 196];
    for (&key, chunk) in aes_keys.iter().zip(hkdf_extract.chunks_exact_mut(64)) {
        let output = Array4x16::mut_from_bytes(chunk).unwrap();
        let hkdf = hmac_kdf(
            &mut hmac,
            HmacKey::Array4x16(&key),
            &composite_key_slice,
            None,
            &mut trng,
            HmacTag::Array4x16(output),
            HmacMode::Hmac384,
        );
        assert!(hkdf.is_ok());
        assert_ne!(*output, Array4x16::default());
    }

    assert_ne!(hkdf_extract, [0; 196]);
    let mut preconditioned_key = Array4x16::default();
    let res = hmac_kdf(
        &mut hmac,
        HmacKey::Array4x16(&Array4x16::default()),
        &hkdf_extract,
        None,
        &mut trng,
        HmacTag::Array4x16(&mut preconditioned_key),
        HmacMode::Hmac384,
    );
    assert!(res.is_ok());
    assert_ne!(preconditioned_key, Array4x16::default());
}

test_suite! {
    test_preconditioned_keys,
}
