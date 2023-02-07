/*++

Licensed under the Apache-2.0 license.

File Name:

    ecc384_tests.rs

Abstract:

    File contains test cases for ECC-384 API tests

--*/

#![no_std]
#![no_main]

use caliptra_lib::{
    Array4x12, Ecc384, Ecc384Data, Ecc384PrivKeyIn, Ecc384PrivKeyOut, Ecc384PubKey, Ecc384Scalar,
    Ecc384Seed, KeyId, KeyReadArgs, KeyUsage, KeyWriteArgs,
};

mod harness;

const PRIV_KEY: [u8; 48] = [
    0xc9, 0x8, 0x58, 0x5a, 0x48, 0x6c, 0x3b, 0x3d, 0x8b, 0xbe, 0x50, 0xeb, 0x7d, 0x2e, 0xb8, 0xa0,
    0x3a, 0xa0, 0x4e, 0x3d, 0x8b, 0xde, 0x2c, 0x31, 0xa8, 0xa2, 0xa1, 0xe3, 0x34, 0x9d, 0xc2, 0x1c,
    0xbb, 0xe6, 0xc9, 0xa, 0xe2, 0xf7, 0x49, 0x12, 0x88, 0x84, 0xb6, 0x22, 0xbb, 0x72, 0xb4, 0xc5,
];

const PUB_KEY_X: [u8; 48] = [
    0x9, 0x82, 0x33, 0xca, 0x56, 0x7a, 0x3f, 0x14, 0xbe, 0x78, 0x49, 0x4, 0xc6, 0x92, 0x1d, 0x43,
    0x3b, 0x4f, 0x85, 0x3a, 0x52, 0x37, 0x42, 0xe4, 0xbc, 0x98, 0x76, 0x7e, 0x23, 0xca, 0x3d, 0xa6,
    0x65, 0x6b, 0xec, 0x46, 0xa7, 0xb1, 0x11, 0x9e, 0x63, 0xd2, 0x66, 0xca, 0x62, 0x54, 0x97, 0x7f,
];

const PUB_KEY_Y: [u8; 48] = [
    0x75, 0xd0, 0xb4, 0x1, 0xc8, 0xba, 0xc3, 0x9a, 0xc5, 0xfb, 0xf, 0x2b, 0x3b, 0x95, 0x37, 0x2c,
    0x41, 0xd9, 0xde, 0x40, 0x55, 0xfd, 0xdb, 0x6, 0xf7, 0x48, 0x49, 0x74, 0x8d, 0xa, 0xed, 0x85,
    0x9b, 0x65, 0x50, 0xca, 0x75, 0xc, 0x3c, 0xd1, 0x18, 0x51, 0xe0, 0x50, 0xbb, 0x7d, 0x20, 0xb2,
];

const SIGNATURE_R: [u8; 48] = [
    0x36, 0xf8, 0x50, 0x14, 0x6f, 0x40, 0x4, 0x43, 0x84, 0x8c, 0xae, 0x3, 0x57, 0x59, 0x10, 0x32,
    0xe6, 0xa3, 0x95, 0xde, 0x66, 0xe7, 0x26, 0x1a, 0x3, 0x80, 0x49, 0xfb, 0xee, 0x15, 0xdb, 0x19,
    0x5d, 0xbd, 0x97, 0x86, 0x94, 0x39, 0x29, 0x2a, 0x4f, 0x57, 0x92, 0xe4, 0x3a, 0x12, 0x31, 0xb7,
];

const SIGNATURE_S: [u8; 48] = [
    0xee, 0xea, 0x42, 0x94, 0x82, 0xfd, 0x8f, 0xa9, 0xd4, 0xd5, 0xf9, 0x60, 0xa0, 0x9e, 0xdf, 0xa6,
    0xc7, 0x65, 0xef, 0xe5, 0xff, 0x4c, 0x17, 0xa5, 0x12, 0xe6, 0x94, 0xfa, 0xcc, 0x45, 0xd3, 0xf6,
    0xfc, 0x3d, 0x3b, 0x5c, 0x62, 0x73, 0x9c, 0x1f, 0xb, 0x9f, 0xca, 0xe3, 0x26, 0xf5, 0x4b, 0x43,
];

fn test_gen_key_pair() {
    let seed = [0u8; 48];
    let mut priv_key = Array4x12::default();
    let result = Ecc384::default().key_pair(
        Ecc384Seed::from(&Ecc384Scalar::from(seed)),
        Ecc384PrivKeyOut::from(&mut priv_key),
    );
    assert!(result.is_ok());
    let pub_key = result.unwrap();
    assert_eq!(priv_key, Ecc384Scalar::from(PRIV_KEY));
    assert_eq!(pub_key.x, Ecc384Scalar::from(PUB_KEY_X));
    assert_eq!(pub_key.y, Ecc384Scalar::from(PUB_KEY_Y));
}

fn test_sign() {
    let digest = [0u8; 48];
    let result = Ecc384::default().sign(
        Ecc384PrivKeyIn::from(&Array4x12::from(PRIV_KEY)),
        Ecc384Data::from(&Array4x12::from(digest)),
    );
    assert!(result.is_ok());
    let signature = result.unwrap();
    assert_eq!(signature.r, Ecc384Scalar::from(SIGNATURE_R));
    assert_eq!(signature.s, Ecc384Scalar::from(SIGNATURE_S));
}

fn test_verify() {
    let digest = [0u8; 48];
    let ecc = Ecc384::default();
    let result = ecc.sign(
        Ecc384PrivKeyIn::from(&Array4x12::from(PRIV_KEY)),
        Ecc384Data::from(&Array4x12::from(digest)),
    );
    assert!(result.is_ok());
    let signature = result.unwrap();
    let pub_key = Ecc384PubKey {
        x: Ecc384Scalar::from(PUB_KEY_X),
        y: Ecc384Scalar::from(PUB_KEY_Y),
    };
    let result = ecc.verify(&pub_key, &Ecc384Scalar::from(digest), &signature);
    assert!(result.is_ok());
    assert!(result.unwrap());
}

fn test_verify_failure() {
    let digest = [0u8; 48];
    let ecc = Ecc384::default();
    let result = ecc.sign(
        Ecc384PrivKeyIn::from(&Array4x12::from(PRIV_KEY)),
        Ecc384Data::from(&Array4x12::from(digest)),
    );
    assert!(result.is_ok());
    let signature = result.unwrap();
    let pub_key = Ecc384PubKey {
        x: Ecc384Scalar::from(PUB_KEY_X),
        y: Ecc384Scalar::from(PUB_KEY_Y),
    };
    let hash = [0xFFu8; 48];
    let result = ecc.verify(&pub_key, &Ecc384Scalar::from(hash), &signature);
    assert!(result.is_ok());
    assert!(!result.unwrap());
}

// This test primes the key-vault with the following data:
// KV0: [
//     0xc9, 0x8, 0x58, 0x5a, 0x48, 0x6c, 0x3b, 0x3d, 0x8b, 0xbe, 0x50, 0xeb, 0x7d, 0x2e, 0xb8,
//     0xa0, 0x3a, 0xa0, 0x4e, 0x3d, 0x8b, 0xde, 0x2c, 0x31, 0xa8, 0xa2, 0xa1, 0xe3, 0x34, 0x9d,
//     0xc2, 0x1c, 0xbb, 0xe6, 0xc9, 0xa, 0xe2, 0xf7, 0x49, 0x12, 0x88, 0x84, 0xb6, 0x22, 0xbb,
//     0x72, 0xb4, 0xc5,
// ];

// KV1: [
//     0xb9, 0xfe, 0xb5, 0x51, 0x8e, 0x8d, 0x57, 0x8c, 0x1f, 0x36, 0x6e, 0x4f, 0x8d, 0x9e, 0x48,
//     0xba, 0xc, 0x9a, 0x8c, 0xde, 0x62, 0xe2, 0x72, 0x25, 0xd2, 0x6, 0x2a, 0x4b, 0xdc, 0x46,
//     0xe2, 0x1c, 0x58, 0x64, 0xa3, 0x3, 0x1e, 0xd5, 0xf1, 0x9f, 0x50, 0xbe, 0xa1, 0x46, 0x14,
//     0xfb, 0x46, 0x1e,
// ];
fn test_kv_prime_kv() {
    let pub_key_x: [u8; 48] = [
        0x98, 0xaa, 0xae, 0xef, 0xba, 0x8d, 0x23, 0x8c, 0xb1, 0x87, 0xc4, 0x34, 0x73, 0xce, 0xe9,
        0x6a, 0xbe, 0xb9, 0xd7, 0x6d, 0x61, 0xe2, 0x6e, 0x9f, 0x3e, 0xbf, 0x7e, 0xcf, 0x15, 0xad,
        0x87, 0x38, 0xce, 0x2c, 0x18, 0xe6, 0x6f, 0x82, 0x1c, 0x29, 0xae, 0x51, 0xfd, 0x8b, 0x9d,
        0xa1, 0xee, 0x48,
    ];
    let pub_key_y: [u8; 48] = [
        0x17, 0xd0, 0x7a, 0x29, 0x5b, 0x64, 0xce, 0xf6, 0x0, 0x44, 0x32, 0x7c, 0xea, 0x25, 0xf,
        0xac, 0xf5, 0x22, 0xc2, 0x30, 0xe8, 0xc7, 0xad, 0x67, 0xfe, 0xe, 0xea, 0x94, 0x90, 0xc1,
        0xf2, 0xd5, 0xf4, 0xc0, 0xb8, 0x47, 0x5e, 0xdb, 0x8e, 0x6f, 0xd6, 0x40, 0x1b, 0xd9, 0x75,
        0x10, 0x70, 0xf6,
    ];

    // Prime KV0
    let seed = [0u8; 48];
    let mut key_usage = KeyUsage::default();
    key_usage.set_ecc_key_gen_seed(true);
    key_usage.set_ecc_data(true);
    let key_out_1 = KeyWriteArgs {
        id: KeyId::KeyId0,
        usage: key_usage,
        word_size: 12,
    };
    let result = Ecc384::default().key_pair(
        Ecc384Seed::from(&Ecc384Scalar::from(seed)),
        Ecc384PrivKeyOut::from(key_out_1),
    );
    assert!(result.is_ok());
    let pub_key = result.unwrap();
    assert_eq!(pub_key.x, Ecc384Scalar::from(PUB_KEY_X));
    assert_eq!(pub_key.y, Ecc384Scalar::from(PUB_KEY_Y));

    // Prime KV1
    let key_in_2 = KeyReadArgs::new(KeyId::KeyId0, 12);
    let mut key_usage = KeyUsage::default();
    key_usage.set_ecc_private_key(true);
    let key_out_2 = KeyWriteArgs {
        id: KeyId::KeyId1,
        usage: key_usage, // ecc_private_key
        word_size: 12,
    };

    let result = Ecc384::default().key_pair(
        Ecc384Seed::from(key_in_2),
        Ecc384PrivKeyOut::from(key_out_2),
    );
    assert!(result.is_ok());
    let pub_key = result.unwrap();
    assert_eq!(pub_key.x, Ecc384Scalar::from(pub_key_x));
    assert_eq!(pub_key.y, Ecc384Scalar::from(pub_key_y));
}

fn test_kv_seed_from_input_msg_from_input() {
    //
    // Step 1: Generate a key pair and store private key in kv slot 2.
    //
    let seed = [0u8; 48];
    let mut key_usage = KeyUsage::default();
    key_usage.set_ecc_private_key(true);
    let key_out_1 = KeyWriteArgs {
        id: KeyId::KeyId2,
        usage: key_usage, // ecc_private_key
        word_size: 12,
    };
    let result = Ecc384::default().key_pair(
        Ecc384Seed::from(&Ecc384Scalar::from(seed)),
        Ecc384PrivKeyOut::from(key_out_1),
    );
    assert!(result.is_ok());
    let pub_key = result.unwrap();
    assert_eq!(pub_key.x, Ecc384Scalar::from(PUB_KEY_X));
    assert_eq!(pub_key.y, Ecc384Scalar::from(PUB_KEY_Y));

    //
    // Step 2: Sign message with private key generated in step 1.
    //
    let digest = [0u8; 48];
    let key_in_1 = KeyReadArgs::new(KeyId::KeyId2, 12);

    let result =
        Ecc384::default().sign(key_in_1.into(), Ecc384Data::from(&Array4x12::from(digest)));
    assert!(result.is_ok());
    let signature = result.unwrap();
    assert_eq!(signature.r, Ecc384Scalar::from(SIGNATURE_R));
    assert_eq!(signature.s, Ecc384Scalar::from(SIGNATURE_S));

    //
    // Step 3: Verify the signature generated in step 2.
    //
    let pub_key = Ecc384PubKey {
        x: pub_key.x,
        y: pub_key.y,
    };
    let ecc = Ecc384::default();
    let result = ecc.verify(&pub_key, &Ecc384Scalar::from(digest), &signature);
    assert!(result.is_ok());
    assert!(result.unwrap());
}

fn test_kv_seed_from_input_msg_from_kv() {
    let msg: [u8; 48] = [
        0xc9, 0x8, 0x58, 0x5a, 0x48, 0x6c, 0x3b, 0x3d, 0x8b, 0xbe, 0x50, 0xeb, 0x7d, 0x2e, 0xb8,
        0xa0, 0x3a, 0xa0, 0x4e, 0x3d, 0x8b, 0xde, 0x2c, 0x31, 0xa8, 0xa2, 0xa1, 0xe3, 0x34, 0x9d,
        0xc2, 0x1c, 0xbb, 0xe6, 0xc9, 0xa, 0xe2, 0xf7, 0x49, 0x12, 0x88, 0x84, 0xb6, 0x22, 0xbb,
        0x72, 0xb4, 0xc5,
    ];
    let signature_r: [u8; 48] = [
        0xb2, 0xa1, 0xe4, 0x7f, 0xec, 0xe9, 0xc3, 0x32, 0x14, 0x88, 0x05, 0x9a, 0x3c, 0x1f, 0x12,
        0x1f, 0x89, 0x92, 0x35, 0xfe, 0x5f, 0x10, 0x60, 0xf6, 0x75, 0xa3, 0xd6, 0x48, 0x54, 0x24,
        0xe9, 0x14, 0x65, 0x9f, 0x21, 0x48, 0x95, 0xb2, 0x31, 0xd6, 0xa0, 0x61, 0x23, 0x28, 0x44,
        0xb7, 0xca, 0xed,
    ];
    let signature_s: [u8; 48] = [
        0x04, 0xeb, 0x73, 0xf7, 0x80, 0xf8, 0x47, 0xd3, 0x93, 0x67, 0xd0, 0x43, 0x6e, 0xef, 0x4c,
        0xc9, 0xc1, 0xbb, 0xbd, 0xd4, 0x20, 0x3c, 0x51, 0x15, 0xf5, 0x93, 0xe2, 0xdd, 0x73, 0x27,
        0x1f, 0x73, 0xaa, 0xef, 0x1b, 0x90, 0x96, 0xdb, 0x05, 0x97, 0x7f, 0xd6, 0xff, 0x0c, 0x84,
        0xbf, 0x1a, 0x2c,
    ];

    //
    // Step 1: Generate key pair and store private key in kv slot 3.
    //
    let seed = [0u8; 48];
    let mut key_usage = KeyUsage::default();
    key_usage.set_ecc_private_key(true);
    let key_out_1 = KeyWriteArgs {
        id: KeyId::KeyId3,
        usage: key_usage, // ecc_private_key
        word_size: 12,
    };

    let result = Ecc384::default().key_pair(
        Ecc384Seed::from(&Ecc384Scalar::from(seed)),
        Ecc384PrivKeyOut::from(key_out_1),
    );
    assert!(result.is_ok());
    let pub_key = result.unwrap();
    assert_eq!(pub_key.x, Ecc384Scalar::from(PUB_KEY_X));
    assert_eq!(pub_key.y, Ecc384Scalar::from(PUB_KEY_Y));

    //
    // Step 2: Sign message with private key generated in step 1.
    //
    let key_in_1 = KeyReadArgs::new(KeyId::KeyId2, 12); // Priv key.
    let key_in_2 = KeyReadArgs::new(KeyId::KeyId0, 12); // Msg
    let result = Ecc384::default().sign(key_in_1.into(), key_in_2.into());
    assert!(result.is_ok());
    let signature = result.unwrap();
    assert_eq!(signature.r, Ecc384Scalar::from(signature_r));
    assert_eq!(signature.s, Ecc384Scalar::from(signature_s));

    //
    // Step 3: Verify the signature generated in step 2.
    //
    let pub_key = Ecc384PubKey {
        x: pub_key.x,
        y: pub_key.y,
    };
    let ecc = Ecc384::default();
    let result = ecc.verify(&pub_key, &Ecc384Scalar::from(msg), &signature);
    assert!(result.is_ok());
    assert!(result.unwrap());
}

fn test_kv_seed_from_kv_msg_from_input() {
    let msg: [u8; 48] = [
        0xc9, 0x8, 0x58, 0x5a, 0x48, 0x6c, 0x3b, 0x3d, 0x8b, 0xbe, 0x50, 0xeb, 0x7d, 0x2e, 0xb8,
        0xa0, 0x3a, 0xa0, 0x4e, 0x3d, 0x8b, 0xde, 0x2c, 0x31, 0xa8, 0xa2, 0xa1, 0xe3, 0x34, 0x9d,
        0xc2, 0x1c, 0xbb, 0xe6, 0xc9, 0xa, 0xe2, 0xf7, 0x49, 0x12, 0x88, 0x84, 0xb6, 0x22, 0xbb,
        0x72, 0xb4, 0xc5,
    ];

    let pub_key_x: [u8; 48] = [
        0x98, 0xaa, 0xae, 0xef, 0xba, 0x8d, 0x23, 0x8c, 0xb1, 0x87, 0xc4, 0x34, 0x73, 0xce, 0xe9,
        0x6a, 0xbe, 0xb9, 0xd7, 0x6d, 0x61, 0xe2, 0x6e, 0x9f, 0x3e, 0xbf, 0x7e, 0xcf, 0x15, 0xad,
        0x87, 0x38, 0xce, 0x2c, 0x18, 0xe6, 0x6f, 0x82, 0x1c, 0x29, 0xae, 0x51, 0xfd, 0x8b, 0x9d,
        0xa1, 0xee, 0x48,
    ];

    let pub_key_y: [u8; 48] = [
        0x17, 0xd0, 0x7a, 0x29, 0x5b, 0x64, 0xce, 0xf6, 0x00, 0x44, 0x32, 0x7c, 0xea, 0x25, 0x0f,
        0xac, 0xf5, 0x22, 0xc2, 0x30, 0xe8, 0xc7, 0xad, 0x67, 0xfe, 0x0e, 0xea, 0x94, 0x90, 0xc1,
        0xf2, 0xd5, 0xf4, 0xc0, 0xb8, 0x47, 0x5e, 0xdb, 0x8e, 0x6f, 0xd6, 0x40, 0x1b, 0xd9, 0x75,
        0x10, 0x70, 0xf6,
    ];

    let sig_r: [u8; 48] = [
        0xb2, 0xe9, 0xad, 0x34, 0x3c, 0xa7, 0x73, 0xc1, 0x90, 0x4e, 0x5d, 0x70, 0xd5, 0x9a, 0x0d,
        0x05, 0x79, 0x7e, 0xe2, 0xa0, 0x86, 0x61, 0x18, 0xed, 0x1c, 0xcd, 0xdf, 0xd8, 0x1d, 0x12,
        0x84, 0x5b, 0xaf, 0x98, 0x1b, 0xa4, 0x39, 0x58, 0x53, 0x87, 0x56, 0x5c, 0x4f, 0xfa, 0xd5,
        0xfc, 0x92, 0x2e,
    ];

    let sig_s: [u8; 48] = [
        0x8d, 0x43, 0x39, 0x60, 0x12, 0x1d, 0x8a, 0x02, 0x7c, 0x3b, 0x81, 0xc1, 0xbc, 0x1c, 0x13,
        0xb9, 0x2b, 0xdf, 0xee, 0xb4, 0x5f, 0xfe, 0xf9, 0x2b, 0x1f, 0xa4, 0xbe, 0xfd, 0xe1, 0xd4,
        0x01, 0x91, 0x24, 0x4e, 0x9a, 0x1d, 0x25, 0xe3, 0xd4, 0x16, 0xa5, 0x70, 0x61, 0xa8, 0x84,
        0xbe, 0x2b, 0x9b,
    ];

    //
    // Step 1: Generate a key pair and store private key in kv slot 4.
    //
    let key_in_1 = KeyReadArgs::new(KeyId::KeyId0, 12);

    let mut key_usage = KeyUsage::default();
    key_usage.set_ecc_private_key(true);
    let key_out_1 = KeyWriteArgs {
        id: KeyId::KeyId4,
        usage: key_usage, // ecc_private_key
        word_size: 12,
    };
    let result = Ecc384::default().key_pair(
        Ecc384Seed::from(key_in_1),
        Ecc384PrivKeyOut::from(key_out_1),
    );
    assert!(result.is_ok());
    let pub_key = result.unwrap();
    assert_eq!(pub_key.x, Ecc384Scalar::from(pub_key_x));
    assert_eq!(pub_key.y, Ecc384Scalar::from(pub_key_y));

    //
    // Step 2: Sign message with private key generated in step 1.
    //
    let key_in_1 = KeyReadArgs::new(KeyId::KeyId4, 12);

    let result = Ecc384::default().sign(key_in_1.into(), Ecc384Data::from(&Array4x12::from(msg)));
    assert!(result.is_ok());
    let signature = result.unwrap();
    assert_eq!(signature.r, Ecc384Scalar::from(sig_r));
    assert_eq!(signature.s, Ecc384Scalar::from(sig_s));

    //
    // Step 3: Verify the signature generated in step 2.
    //
    let pub_key = Ecc384PubKey {
        x: pub_key.x,
        y: pub_key.y,
    };
    let ecc = Ecc384::default();
    let result = ecc.verify(&pub_key, &Ecc384Scalar::from(msg), &signature);
    assert!(result.is_ok());
    assert!(result.unwrap());
}

test_suite! {
    test_gen_key_pair,
    test_sign,
    test_verify,
    test_verify_failure,
    // Maintain the order of the tests.
    test_kv_prime_kv,
    test_kv_seed_from_input_msg_from_input,
    test_kv_seed_from_input_msg_from_kv,
    test_kv_seed_from_kv_msg_from_input,
}
