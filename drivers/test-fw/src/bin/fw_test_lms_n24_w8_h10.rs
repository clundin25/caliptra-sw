/*++

Licensed under the Apache-2.0 license.

Abstract:

    File contains test cases for LMS signature verification. This file is machine generated.

--*/

#![no_std]
#![no_main]

use caliptra_drivers::{Lms, LmsResult, Sha256};
use caliptra_lms_types::{LmsPublicKey, LmsSignature};
use caliptra_registers::sha256::Sha256Reg;
use caliptra_test_harness::test_suite;

struct LmsTest<'a> {
    test_passed: bool,
    signature: &'a [u8],
}

fn test_lms_random_suite() {
    let mut sha256 = unsafe { Sha256::new(Sha256Reg::new()) };
    	const MESSAGE :[u8; 33] = [116, 104, 105, 115, 32, 105, 115, 32, 116, 104, 101, 32, 109, 101, 115, 115, 97, 103, 101, 32, 73, 32, 119, 97, 110, 116, 32, 115, 105, 103, 110, 101, 100];
	const PUBLIC_KEY_BYTES: [u8; 48] = [0, 0, 0, 11, 0, 0, 0, 8, 62, 87, 54, 5, 228, 186, 221, 171, 146, 170, 179, 133, 230, 48, 233, 91, 246, 178, 35, 11, 225, 43, 214, 165, 247, 227, 252, 250, 247, 120, 27, 161, 15, 222, 189, 37, 130, 27, 167, 84];
	let (head, thing1, _tail): (&[u8], &[LmsPublicKey<6>], &[u8]) = unsafe { PUBLIC_KEY_BYTES.align_to::<LmsPublicKey<6>>() };
    	assert!(head.is_empty());
    	let lms_public_key = thing1[0];
	const TESTS: [LmsTest; 2] = [
		LmsTest{ test_passed: true, signature: &[0, 0, 2, 166, 0, 0, 0, 8, 9, 54, 183, 69, 27, 250, 55, 82, 192, 186, 51, 243, 49, 91, 180, 164, 10, 184, 223, 174, 186, 196, 192, 58, 237, 0, 131, 236, 119, 143, 217, 152, 208, 1, 149, 149, 49, 60, 68, 74, 103, 149, 8, 81, 149, 190, 214, 96, 83, 27, 163, 135, 83, 17, 215, 219, 108, 75, 248, 134, 213, 99, 133, 90, 145, 5, 15, 76, 120, 19, 52, 187, 232, 129, 35, 249, 42, 252, 247, 208, 55, 245, 235, 103, 130, 247, 205, 46, 78, 232, 91, 32, 52, 3, 188, 16, 228, 227, 169, 44, 14, 203, 65, 116, 159, 73, 113, 89, 205, 15, 123, 110, 81, 27, 111, 247, 245, 240, 131, 79, 196, 215, 66, 174, 181, 177, 82, 203, 93, 144, 102, 179, 14, 205, 55, 174, 143, 181, 172, 28, 19, 191, 41, 245, 193, 9, 138, 133, 75, 128, 224, 181, 17, 152, 140, 204, 37, 44, 69, 250, 93, 237, 169, 240, 131, 145, 165, 211, 251, 29, 209, 45, 71, 105, 0, 226, 17, 150, 220, 226, 79, 110, 104, 79, 247, 137, 244, 161, 246, 253, 26, 79, 195, 56, 164, 161, 131, 135, 15, 68, 212, 206, 197, 152, 103, 153, 197, 238, 125, 255, 208, 242, 175, 121, 164, 123, 141, 202, 204, 60, 221, 59, 166, 154, 48, 236, 35, 175, 25, 108, 247, 57, 127, 133, 99, 209, 71, 230, 253, 172, 150, 173, 23, 39, 251, 16, 91, 222, 182, 51, 90, 1, 129, 252, 148, 58, 195, 127, 48, 182, 204, 83, 76, 128, 198, 46, 92, 230, 40, 93, 53, 7, 112, 87, 89, 35, 252, 70, 10, 153, 78, 37, 130, 211, 247, 183, 232, 44, 37, 131, 198, 1, 110, 176, 157, 104, 57, 246, 253, 209, 58, 90, 69, 33, 58, 243, 202, 52, 22, 74, 200, 38, 51, 25, 158, 160, 26, 35, 175, 9, 120, 71, 119, 223, 245, 26, 205, 58, 30, 7, 230, 134, 210, 250, 146, 136, 169, 133, 226, 207, 177, 16, 39, 135, 217, 247, 75, 154, 153, 231, 167, 218, 175, 102, 93, 73, 216, 50, 29, 196, 83, 41, 136, 206, 121, 86, 128, 64, 42, 172, 29, 254, 190, 203, 184, 98, 159, 220, 205, 55, 48, 174, 222, 17, 97, 75, 112, 8, 57, 215, 64, 178, 51, 225, 99, 184, 245, 170, 177, 192, 178, 200, 172, 228, 100, 108, 116, 126, 29, 147, 45, 4, 66, 243, 125, 10, 204, 72, 144, 244, 229, 185, 227, 245, 148, 124, 207, 111, 242, 140, 5, 230, 98, 216, 90, 251, 158, 49, 18, 228, 208, 122, 199, 68, 210, 228, 169, 219, 115, 131, 144, 109, 59, 65, 66, 77, 149, 231, 7, 246, 166, 20, 155, 15, 53, 250, 155, 73, 239, 93, 210, 167, 55, 204, 43, 41, 194, 49, 39, 126, 1, 222, 156, 150, 199, 250, 135, 47, 168, 93, 46, 55, 70, 211, 120, 151, 202, 67, 129, 27, 33, 86, 168, 143, 196, 71, 49, 73, 201, 238, 143, 225, 169, 5, 36, 88, 97, 199, 131, 135, 111, 97, 93, 26, 85, 21, 133, 163, 44, 95, 182, 197, 231, 162, 176, 64, 156, 126, 21, 144, 36, 11, 143, 45, 14, 126, 10, 138, 114, 9, 90, 46, 185, 221, 230, 178, 50, 57, 248, 119, 93, 150, 119, 102, 5, 155, 148, 105, 243, 176, 13, 148, 134, 122, 130, 140, 25, 33, 212, 183, 243, 250, 248, 127, 28, 125, 24, 126, 64, 131, 32, 14, 60, 55, 11, 197, 232, 209, 49, 23, 187, 201, 86, 61, 196, 126, 224, 163, 22, 90, 110, 221, 207, 196, 244, 61, 215, 227, 157, 171, 190, 89, 129, 174, 220, 23, 221, 180, 248, 239, 166, 149, 72, 119, 6, 99, 65, 5, 94, 245, 198, 29, 104, 159, 27, 198, 60, 132, 0, 0, 0, 11, 93, 129, 114, 247, 236, 214, 42, 118, 103, 35, 75, 90, 225, 207, 165, 22, 242, 146, 234, 10, 122, 5, 170, 207, 14, 65, 28, 77, 249, 149, 195, 89, 197, 211, 139, 140, 164, 149, 216, 19, 232, 211, 254, 22, 236, 47, 212, 226, 146, 171, 249, 140, 59, 82, 230, 222, 67, 197, 102, 34, 113, 245, 163, 135, 155, 116, 55, 82, 79, 118, 235, 192, 85, 18, 149, 0, 199, 96, 156, 65, 149, 64, 72, 42, 213, 234, 15, 232, 53, 30, 230, 100, 200, 149, 67, 13, 153, 110, 0, 8, 85, 74, 126, 79, 33, 202, 202, 39, 153, 121, 219, 144, 182, 52, 144, 164, 84, 91, 155, 164, 62, 124, 12, 219, 168, 165, 212, 136, 9, 102, 184, 86, 117, 161, 118, 162, 140, 196, 198, 25, 80, 134, 223, 215, 100, 245, 16, 224, 4, 59, 45, 212, 167, 230, 9, 171, 165, 108, 18, 111, 208, 167, 144, 38, 0, 196, 1, 163, 134, 98, 51, 243, 216, 9, 120, 16, 225, 86, 220, 69, 207, 121, 113, 132, 116, 197, 114, 208, 175, 102, 158, 140, 15, 203, 135, 241, 138, 192, 153, 233, 132, 28, 248, 168, 39, 183, 21, 108, 206, 160, 53, 73, 185, 199, 172, 162, 55, 39, 182, 87, 59, 254, 65, 5, 209, 103, 21, 93, 146, 162, 153, 104, 188, 154, 253, 72, 180, 243, 174, 67]},
		LmsTest{ test_passed: true, signature: &[0, 0, 2, 82, 0, 0, 0, 8, 50, 3, 206, 71, 181, 68, 95, 157, 17, 47, 200, 102, 135, 238, 138, 106, 19, 219, 19, 202, 235, 172, 0, 176, 76, 89, 101, 114, 187, 55, 12, 29, 122, 201, 223, 97, 38, 129, 62, 166, 30, 76, 173, 216, 149, 249, 207, 249, 104, 29, 90, 70, 73, 225, 142, 206, 111, 119, 224, 195, 198, 5, 220, 147, 245, 175, 29, 96, 205, 227, 79, 27, 228, 233, 128, 40, 150, 154, 106, 185, 160, 121, 130, 78, 129, 48, 249, 81, 15, 108, 221, 16, 191, 177, 94, 171, 64, 100, 56, 42, 182, 15, 118, 243, 149, 199, 150, 67, 152, 230, 179, 155, 109, 44, 254, 97, 100, 77, 102, 55, 125, 193, 239, 63, 125, 155, 153, 211, 189, 33, 166, 224, 187, 172, 125, 51, 173, 226, 28, 78, 128, 188, 180, 122, 235, 133, 136, 92, 179, 16, 146, 191, 109, 197, 234, 104, 15, 99, 117, 159, 54, 176, 179, 225, 81, 87, 171, 162, 180, 183, 217, 136, 236, 233, 96, 42, 245, 27, 19, 177, 197, 57, 251, 12, 203, 118, 167, 94, 231, 181, 220, 57, 235, 175, 6, 138, 177, 223, 232, 188, 85, 112, 60, 236, 121, 235, 181, 163, 156, 192, 174, 156, 201, 213, 89, 8, 242, 189, 67, 247, 152, 104, 57, 107, 219, 64, 35, 174, 100, 191, 112, 107, 136, 12, 76, 83, 191, 211, 31, 202, 218, 117, 162, 29, 71, 116, 210, 178, 176, 70, 218, 114, 49, 195, 112, 177, 18, 91, 55, 104, 88, 108, 186, 145, 252, 47, 96, 240, 187, 64, 197, 77, 72, 247, 178, 231, 88, 100, 64, 90, 207, 128, 73, 46, 136, 245, 105, 40, 59, 120, 204, 164, 142, 249, 58, 211, 206, 29, 125, 171, 247, 129, 19, 192, 190, 203, 203, 79, 191, 229, 195, 114, 250, 182, 210, 150, 100, 145, 132, 239, 203, 112, 196, 217, 99, 101, 51, 187, 222, 43, 121, 139, 82, 176, 91, 136, 130, 35, 240, 4, 33, 144, 46, 136, 238, 167, 46, 138, 142, 237, 91, 17, 38, 139, 167, 167, 65, 75, 120, 91, 35, 223, 22, 9, 7, 171, 33, 11, 62, 134, 110, 139, 85, 75, 35, 228, 101, 246, 209, 240, 86, 26, 45, 65, 157, 113, 162, 232, 186, 71, 201, 96, 44, 93, 103, 10, 158, 215, 233, 199, 52, 195, 27, 220, 37, 151, 236, 25, 177, 58, 44, 184, 23, 218, 125, 145, 74, 51, 233, 83, 92, 68, 198, 9, 124, 170, 7, 179, 171, 221, 212, 169, 85, 190, 96, 87, 116, 36, 10, 227, 49, 99, 255, 191, 84, 16, 248, 61, 219, 52, 44, 114, 176, 177, 16, 164, 241, 109, 114, 194, 6, 167, 173, 103, 6, 58, 74, 87, 138, 245, 154, 229, 215, 225, 143, 49, 80, 0, 144, 44, 157, 57, 60, 93, 165, 118, 92, 153, 161, 120, 208, 227, 82, 105, 42, 139, 132, 49, 38, 162, 134, 113, 190, 240, 95, 53, 208, 157, 211, 215, 177, 209, 229, 131, 179, 112, 233, 26, 182, 25, 221, 125, 112, 88, 77, 176, 227, 112, 143, 191, 20, 56, 138, 149, 66, 45, 8, 193, 236, 27, 217, 229, 159, 152, 20, 123, 194, 130, 217, 251, 22, 8, 64, 86, 52, 61, 160, 43, 2, 230, 138, 82, 132, 184, 0, 210, 233, 18, 235, 71, 211, 187, 250, 234, 139, 164, 215, 105, 249, 114, 109, 119, 214, 88, 160, 162, 42, 217, 16, 134, 80, 136, 164, 50, 36, 116, 214, 162, 149, 214, 79, 144, 18, 111, 119, 22, 154, 40, 218, 54, 215, 229, 222, 191, 63, 179, 130, 79, 27, 181, 144, 3, 17, 3, 67, 23, 73, 69, 96, 118, 141, 214, 129, 193, 212, 170, 163, 112, 179, 160, 254, 245, 1, 44, 195, 129, 142, 19, 0, 0, 0, 11, 101, 192, 221, 45, 95, 189, 141, 144, 194, 249, 150, 96, 111, 165, 97, 39, 86, 41, 57, 167, 51, 253, 99, 11, 112, 38, 17, 40, 99, 170, 242, 218, 174, 165, 9, 104, 22, 167, 31, 238, 131, 202, 13, 47, 199, 230, 218, 7, 71, 239, 147, 81, 149, 147, 104, 209, 185, 232, 187, 13, 186, 188, 55, 166, 242, 252, 254, 101, 155, 120, 148, 67, 112, 158, 69, 111, 128, 246, 100, 148, 125, 133, 46, 24, 60, 66, 210, 111, 77, 14, 95, 207, 212, 76, 150, 31, 128, 43, 44, 123, 85, 128, 227, 227, 246, 200, 176, 129, 136, 225, 63, 113, 146, 184, 159, 254, 220, 138, 44, 42, 44, 9, 123, 180, 94, 4, 162, 184, 155, 114, 21, 165, 252, 92, 56, 62, 39, 87, 137, 127, 161, 165, 140, 142, 142, 51, 161, 250, 145, 110, 132, 119, 53, 45, 109, 16, 6, 211, 86, 134, 50, 127, 162, 31, 189, 150, 208, 51, 229, 168, 3, 170, 104, 45, 117, 255, 7, 16, 148, 248, 28, 9, 156, 253, 73, 185, 119, 106, 98, 64, 234, 57, 15, 203, 135, 241, 138, 192, 153, 233, 132, 28, 248, 168, 39, 183, 21, 108, 206, 160, 53, 73, 185, 199, 172, 162, 55, 39, 182, 87, 59, 254, 65, 5, 209, 103, 21, 93, 146, 162, 153, 104, 188, 154, 253, 72, 180, 243, 174, 67]},
	];
	for t in TESTS {
        let (head, thing2, _tail): (&[u8], &[LmsSignature<6, 26, 10>], &[u8]) =
            unsafe { t.signature.align_to::<LmsSignature<6, 26, 10>>() };

        assert!(head.is_empty());
        let lms_sig = thing2[0];
        let verify_result = Lms::default().verify_lms_signature_generic(
            &mut sha256,
            &MESSAGE,
            &lms_public_key,
            &lms_sig,
        );
        if t.test_passed {
            // if the test is supposed to pass then we better have no errors and a successful verification
            let result = verify_result.unwrap();
            assert_eq!(result, LmsResult::Success)
        } else {
            // if the test is supposed to fail it could be for a number of reasons that could raise a variety of errors
            // if the verification didn't error, then extract the LMS result and ensure it is a failed verification
            if verify_result.is_ok() {
                let result = verify_result.unwrap();
                assert_eq!(result, LmsResult::SigVerifyFailed)
            }
        }
    }
}

test_suite! {
    test_lms_random_suite,
}