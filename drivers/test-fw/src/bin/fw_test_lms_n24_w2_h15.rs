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
	const PUBLIC_KEY_BYTES: [u8; 48] = [0, 0, 0, 12, 0, 0, 0, 6, 244, 211, 21, 131, 158, 161, 116, 143, 65, 62, 194, 117, 26, 171, 124, 171, 68, 120, 81, 43, 22, 118, 16, 136, 59, 143, 93, 232, 107, 94, 196, 158, 228, 49, 109, 247, 249, 43, 68, 198];
	let (head, thing1, _tail): (&[u8], &[LmsPublicKey<6>], &[u8]) = unsafe { PUBLIC_KEY_BYTES.align_to::<LmsPublicKey<6>>() };
    	assert!(head.is_empty());
    	let lms_public_key = thing1[0];
	const TESTS: [LmsTest; 2] = [
		LmsTest{ test_passed: true, signature: &[0, 0, 126, 208, 0, 0, 0, 6, 53, 79, 68, 6, 186, 6, 164, 217, 159, 203, 185, 153, 129, 177, 220, 175, 122, 200, 22, 100, 68, 223, 158, 175, 110, 149, 158, 148, 21, 17, 157, 120, 232, 33, 140, 67, 24, 193, 32, 99, 151, 237, 125, 63, 37, 80, 40, 63, 121, 103, 77, 102, 137, 197, 58, 114, 15, 99, 9, 127, 35, 11, 224, 211, 149, 71, 245, 50, 244, 50, 12, 167, 102, 160, 199, 146, 108, 188, 66, 22, 249, 60, 32, 37, 12, 214, 28, 138, 84, 241, 76, 127, 42, 43, 141, 46, 231, 113, 59, 115, 157, 85, 30, 167, 247, 33, 182, 81, 54, 195, 213, 59, 150, 172, 8, 131, 146, 3, 69, 96, 201, 245, 167, 239, 46, 114, 37, 235, 101, 50, 15, 236, 111, 71, 242, 174, 222, 210, 2, 71, 164, 203, 138, 90, 207, 220, 221, 237, 150, 155, 6, 117, 126, 23, 179, 88, 81, 50, 99, 74, 224, 108, 8, 181, 215, 171, 27, 13, 77, 153, 148, 102, 99, 187, 245, 91, 24, 131, 110, 170, 11, 207, 72, 115, 33, 207, 21, 101, 29, 168, 152, 228, 199, 183, 136, 166, 165, 45, 82, 39, 127, 54, 225, 80, 228, 86, 67, 100, 43, 2, 69, 9, 66, 215, 135, 37, 148, 106, 19, 47, 136, 136, 131, 175, 69, 145, 178, 26, 2, 207, 87, 226, 163, 47, 221, 35, 141, 36, 218, 27, 54, 123, 249, 195, 111, 67, 212, 249, 34, 180, 10, 230, 202, 225, 44, 22, 166, 202, 22, 11, 172, 24, 194, 90, 105, 8, 172, 92, 8, 232, 25, 105, 53, 0, 58, 208, 77, 69, 42, 31, 21, 106, 174, 175, 183, 137, 220, 40, 43, 255, 89, 136, 156, 158, 199, 220, 9, 204, 1, 102, 253, 88, 168, 214, 126, 12, 156, 80, 185, 25, 235, 158, 126, 212, 125, 26, 42, 115, 64, 75, 107, 154, 112, 5, 114, 226, 9, 249, 248, 23, 67, 218, 187, 42, 193, 186, 82, 123, 78, 183, 153, 164, 194, 168, 15, 91, 176, 17, 222, 160, 138, 212, 241, 23, 6, 86, 1, 248, 240, 63, 54, 83, 89, 249, 43, 167, 254, 140, 104, 190, 162, 245, 32, 214, 147, 37, 188, 113, 93, 127, 8, 247, 87, 254, 164, 220, 30, 156, 22, 143, 113, 79, 96, 76, 109, 83, 52, 126, 39, 184, 98, 57, 128, 115, 94, 176, 123, 174, 166, 155, 246, 74, 98, 254, 206, 218, 48, 183, 110, 78, 170, 16, 27, 236, 18, 89, 146, 134, 237, 50, 248, 42, 66, 11, 244, 59, 92, 106, 54, 251, 64, 193, 65, 104, 91, 196, 110, 118, 167, 127, 16, 27, 105, 149, 135, 95, 192, 228, 117, 184, 27, 121, 100, 133, 94, 207, 28, 4, 30, 28, 17, 18, 76, 40, 137, 24, 182, 80, 147, 217, 135, 138, 215, 221, 214, 127, 38, 181, 35, 114, 216, 133, 152, 79, 66, 52, 151, 247, 68, 130, 124, 226, 219, 60, 66, 49, 77, 65, 230, 226, 12, 237, 202, 151, 147, 180, 61, 221, 79, 148, 166, 103, 6, 115, 115, 231, 146, 245, 243, 60, 53, 235, 141, 16, 120, 38, 60, 128, 188, 74, 153, 101, 232, 251, 0, 221, 224, 243, 62, 248, 157, 98, 98, 93, 88, 50, 33, 247, 175, 158, 254, 197, 216, 195, 239, 139, 201, 156, 148, 12, 111, 73, 43, 207, 73, 128, 40, 86, 84, 163, 38, 18, 116, 162, 254, 96, 87, 14, 19, 165, 136, 223, 250, 163, 237, 220, 95, 187, 164, 230, 37, 207, 224, 1, 110, 153, 112, 131, 213, 176, 124, 224, 109, 30, 34, 74, 120, 129, 22, 1, 46, 2, 228, 56, 102, 43, 220, 254, 197, 134, 147, 190, 66, 218, 92, 166, 86, 167, 36, 163, 77, 138, 239, 79, 102, 227, 122, 46, 202, 232, 244, 235, 135, 84, 238, 204, 229, 17, 21, 134, 213, 179, 246, 126, 53, 35, 154, 250, 48, 106, 240, 123, 78, 248, 8, 210, 211, 171, 189, 124, 244, 142, 100, 27, 242, 135, 229, 14, 11, 77, 30, 207, 18, 242, 254, 2, 163, 51, 40, 100, 237, 185, 160, 168, 251, 24, 129, 31, 124, 96, 67, 118, 70, 139, 10, 163, 217, 71, 104, 177, 46, 137, 88, 96, 226, 182, 123, 157, 161, 254, 230, 95, 43, 174, 58, 233, 235, 115, 231, 233, 230, 12, 206, 96, 118, 244, 239, 160, 137, 47, 22, 232, 52, 185, 131, 105, 41, 144, 64, 49, 9, 165, 236, 242, 247, 9, 45, 242, 10, 43, 3, 193, 94, 27, 19, 218, 71, 255, 37, 54, 191, 125, 146, 26, 150, 188, 164, 115, 183, 132, 120, 46, 191, 98, 169, 213, 103, 50, 83, 29, 166, 131, 100, 187, 95, 162, 91, 207, 165, 12, 55, 31, 32, 0, 121, 78, 126, 190, 212, 150, 90, 111, 232, 111, 9, 217, 71, 170, 142, 232, 184, 102, 233, 167, 0, 173, 117, 11, 220, 30, 10, 175, 172, 173, 203, 252, 228, 97, 30, 107, 23, 163, 201, 181, 125, 6, 194, 51, 93, 197, 201, 51, 12, 153, 207, 221, 91, 76, 217, 117, 31, 33, 23, 250, 125, 46, 47, 118, 132, 18, 93, 221, 193, 54, 32, 243, 191, 141, 34, 108, 16, 92, 10, 198, 86, 129, 52, 101, 33, 43, 28, 2, 245, 210, 101, 86, 52, 110, 161, 20, 218, 186, 89, 83, 130, 100, 87, 47, 53, 87, 136, 194, 12, 145, 106, 144, 145, 52, 221, 161, 225, 160, 81, 85, 47, 58, 174, 32, 206, 52, 207, 242, 53, 221, 254, 89, 71, 45, 48, 70, 58, 13, 110, 239, 213, 163, 25, 245, 232, 201, 234, 194, 62, 221, 82, 191, 171, 111, 85, 196, 243, 112, 239, 72, 163, 62, 204, 142, 121, 27, 138, 139, 231, 194, 10, 198, 137, 104, 243, 145, 249, 93, 17, 2, 107, 74, 78, 235, 181, 60, 88, 151, 203, 82, 44, 159, 102, 163, 18, 12, 102, 68, 191, 18, 149, 39, 242, 24, 230, 230, 123, 89, 198, 30, 44, 50, 173, 50, 173, 11, 191, 38, 164, 197, 49, 34, 135, 3, 164, 114, 212, 230, 36, 2, 80, 148, 35, 71, 91, 127, 83, 165, 162, 70, 223, 168, 167, 12, 46, 55, 154, 152, 43, 67, 156, 243, 119, 43, 207, 2, 108, 98, 187, 245, 217, 224, 19, 55, 192, 49, 121, 44, 143, 56, 159, 113, 26, 142, 175, 165, 60, 226, 213, 175, 81, 109, 179, 141, 80, 3, 198, 27, 100, 13, 11, 31, 205, 32, 9, 21, 156, 255, 98, 135, 64, 231, 238, 241, 190, 115, 166, 177, 188, 211, 121, 88, 139, 210, 253, 243, 213, 81, 248, 172, 240, 99, 161, 143, 171, 100, 229, 2, 243, 77, 240, 212, 135, 127, 178, 13, 47, 194, 100, 225, 138, 238, 89, 46, 7, 162, 241, 80, 140, 193, 245, 120, 59, 143, 93, 196, 242, 190, 84, 32, 74, 229, 56, 186, 250, 222, 93, 48, 80, 6, 128, 193, 116, 87, 27, 214, 38, 237, 35, 72, 114, 208, 80, 211, 65, 100, 26, 138, 100, 159, 231, 7, 239, 104, 182, 11, 56, 50, 230, 67, 49, 86, 180, 129, 62, 253, 107, 107, 94, 111, 113, 103, 84, 58, 127, 119, 57, 155, 202, 125, 222, 217, 25, 73, 145, 189, 13, 155, 21, 119, 22, 134, 150, 204, 128, 43, 179, 120, 17, 120, 44, 183, 43, 87, 250, 244, 169, 69, 84, 216, 50, 164, 104, 42, 181, 218, 177, 188, 63, 25, 241, 211, 255, 41, 172, 7, 142, 17, 114, 54, 175, 57, 181, 120, 230, 72, 130, 246, 7, 18, 103, 47, 205, 47, 32, 223, 210, 199, 74, 147, 133, 20, 246, 142, 17, 251, 118, 143, 245, 166, 237, 237, 60, 110, 147, 167, 2, 210, 19, 52, 237, 89, 248, 166, 169, 101, 21, 11, 210, 3, 77, 145, 65, 13, 253, 251, 242, 11, 132, 1, 23, 170, 25, 236, 60, 198, 31, 202, 33, 149, 41, 72, 157, 149, 40, 204, 40, 187, 115, 148, 27, 244, 166, 68, 195, 52, 214, 202, 15, 49, 171, 202, 172, 109, 120, 199, 230, 220, 84, 16, 216, 120, 244, 161, 100, 71, 115, 73, 67, 80, 166, 3, 64, 249, 85, 174, 82, 82, 34, 14, 195, 42, 67, 136, 23, 181, 127, 227, 57, 5, 79, 12, 82, 93, 195, 127, 217, 47, 10, 238, 10, 95, 69, 142, 41, 175, 182, 201, 13, 192, 165, 213, 208, 104, 234, 60, 173, 64, 71, 204, 178, 224, 73, 146, 4, 218, 14, 70, 0, 230, 121, 247, 244, 188, 152, 160, 175, 208, 252, 38, 3, 237, 107, 137, 52, 197, 199, 204, 182, 211, 53, 203, 233, 93, 206, 106, 21, 64, 236, 27, 112, 21, 64, 201, 118, 10, 254, 105, 174, 46, 170, 190, 104, 242, 55, 84, 113, 72, 47, 246, 182, 15, 171, 255, 249, 126, 224, 142, 8, 12, 44, 3, 94, 236, 33, 195, 63, 49, 147, 156, 143, 186, 12, 154, 112, 141, 24, 192, 90, 9, 5, 218, 169, 34, 76, 16, 20, 175, 229, 140, 90, 17, 142, 112, 176, 229, 193, 231, 160, 76, 1, 22, 43, 212, 16, 169, 122, 247, 223, 51, 105, 92, 2, 6, 175, 222, 40, 89, 55, 146, 3, 209, 177, 7, 172, 72, 159, 100, 72, 75, 46, 196, 181, 44, 133, 41, 219, 209, 126, 188, 32, 210, 198, 185, 160, 87, 121, 133, 202, 43, 7, 105, 221, 174, 226, 76, 0, 10, 77, 139, 32, 158, 87, 222, 80, 110, 151, 47, 41, 170, 179, 248, 52, 244, 92, 35, 6, 218, 125, 156, 91, 67, 125, 35, 236, 149, 244, 114, 203, 7, 11, 106, 112, 24, 81, 211, 180, 170, 105, 11, 176, 30, 204, 59, 50, 228, 235, 92, 239, 8, 247, 158, 77, 253, 97, 74, 176, 34, 246, 100, 193, 108, 249, 239, 201, 200, 11, 222, 63, 26, 92, 15, 47, 131, 109, 48, 169, 190, 39, 16, 53, 137, 93, 25, 6, 84, 136, 142, 126, 19, 15, 50, 99, 184, 141, 208, 14, 177, 73, 226, 173, 234, 197, 203, 143, 221, 139, 82, 45, 244, 242, 114, 105, 31, 133, 155, 188, 51, 130, 193, 135, 182, 92, 218, 7, 143, 5, 165, 103, 26, 28, 35, 84, 20, 102, 185, 186, 1, 218, 213, 108, 126, 176, 116, 152, 142, 128, 221, 158, 170, 111, 30, 171, 90, 178, 91, 255, 91, 24, 223, 47, 91, 79, 51, 102, 88, 239, 1, 245, 213, 225, 138, 149, 63, 134, 100, 53, 64, 162, 240, 188, 25, 33, 74, 231, 130, 88, 255, 66, 50, 241, 22, 218, 138, 54, 9, 224, 56, 133, 11, 177, 165, 234, 120, 99, 230, 232, 48, 131, 83, 130, 167, 0, 209, 114, 11, 117, 119, 119, 203, 52, 146, 242, 94, 149, 217, 31, 139, 182, 169, 224, 19, 255, 157, 235, 93, 106, 18, 168, 232, 66, 117, 197, 198, 203, 122, 82, 50, 11, 216, 192, 132, 205, 236, 198, 98, 174, 12, 253, 1, 100, 126, 67, 11, 42, 104, 41, 25, 168, 230, 43, 240, 185, 66, 146, 209, 23, 234, 48, 112, 153, 32, 63, 99, 232, 193, 107, 19, 136, 245, 6, 59, 68, 125, 65, 69, 129, 234, 137, 218, 8, 41, 139, 52, 154, 79, 95, 91, 114, 73, 88, 247, 254, 188, 91, 12, 66, 54, 62, 64, 147, 186, 159, 235, 242, 99, 74, 212, 193, 210, 204, 201, 226, 245, 240, 31, 241, 197, 178, 89, 4, 92, 193, 10, 211, 131, 48, 208, 207, 122, 28, 193, 28, 150, 64, 154, 130, 220, 241, 153, 92, 39, 187, 164, 163, 103, 166, 16, 70, 129, 41, 25, 226, 66, 76, 18, 101, 1, 208, 183, 185, 112, 119, 228, 156, 216, 50, 208, 218, 240, 176, 176, 30, 181, 89, 2, 236, 203, 147, 64, 182, 180, 94, 150, 63, 3, 239, 248, 48, 44, 1, 129, 160, 241, 20, 86, 41, 161, 148, 221, 206, 51, 251, 17, 234, 135, 201, 141, 155, 8, 141, 129, 227, 162, 101, 182, 124, 81, 57, 62, 63, 226, 155, 231, 155, 6, 11, 76, 5, 106, 86, 27, 197, 47, 62, 39, 228, 10, 218, 168, 120, 86, 18, 223, 25, 37, 186, 140, 3, 28, 104, 24, 159, 71, 33, 218, 191, 154, 164, 63, 216, 92, 254, 89, 5, 164, 179, 45, 212, 191, 210, 39, 91, 50, 19, 221, 89, 65, 142, 81, 226, 95, 177, 251, 87, 68, 71, 9, 214, 50, 253, 121, 78, 25, 39, 191, 112, 172, 230, 87, 80, 85, 122, 172, 36, 89, 220, 149, 236, 14, 185, 86, 1, 66, 211, 13, 216, 105, 235, 169, 70, 197, 155, 170, 124, 128, 61, 189, 12, 236, 69, 234, 39, 37, 173, 240, 128, 86, 62, 238, 243, 75, 41, 229, 216, 109, 181, 222, 118, 52, 232, 178, 119, 95, 76, 116, 71, 17, 221, 85, 190, 4, 192, 225, 78, 130, 176, 230, 114, 20, 90, 217, 225, 51, 139, 109, 172, 106, 30, 24, 188, 245, 213, 195, 54, 191, 168, 156, 116, 200, 154, 30, 150, 16, 122, 106, 17, 39, 136, 206, 245, 241, 162, 230, 93, 14, 244, 123, 139, 175, 114, 124, 232, 31, 101, 206, 167, 188, 229, 219, 254, 248, 153, 95, 218, 219, 57, 247, 209, 1, 213, 228, 141, 138, 10, 255, 79, 43, 232, 47, 107, 184, 206, 212, 102, 247, 141, 241, 18, 144, 167, 95, 205, 5, 170, 199, 230, 238, 117, 196, 42, 101, 206, 199, 42, 246, 166, 239, 53, 121, 129, 199, 147, 127, 196, 20, 139, 106, 236, 184, 175, 152, 48, 151, 36, 173, 59, 67, 235, 234, 62, 96, 142, 22, 171, 104, 184, 114, 69, 238, 90, 81, 218, 241, 154, 88, 51, 223, 30, 220, 241, 158, 176, 216, 191, 195, 227, 52, 108, 106, 193, 183, 128, 222, 17, 87, 141, 132, 12, 31, 231, 45, 78, 165, 27, 35, 122, 133, 36, 93, 7, 186, 215, 202, 47, 214, 102, 45, 239, 135, 39, 80, 113, 137, 188, 125, 245, 25, 87, 255, 147, 240, 188, 182, 137, 34, 149, 156, 246, 23, 169, 37, 68, 63, 192, 179, 29, 71, 76, 195, 137, 116, 45, 208, 76, 234, 18, 211, 83, 124, 160, 175, 99, 243, 8, 125, 136, 41, 210, 11, 59, 70, 176, 102, 110, 230, 66, 70, 110, 88, 238, 152, 20, 185, 0, 0, 0, 12, 204, 223, 64, 243, 150, 50, 215, 95, 60, 247, 240, 130, 99, 121, 44, 245, 249, 107, 166, 236, 17, 81, 76, 248, 191, 184, 174, 112, 233, 48, 197, 165, 183, 230, 62, 131, 245, 63, 229, 35, 216, 64, 158, 250, 171, 153, 84, 49, 224, 88, 157, 174, 9, 11, 110, 122, 209, 83, 20, 108, 128, 91, 75, 40, 193, 221, 167, 228, 213, 89, 120, 215, 234, 116, 239, 3, 210, 60, 36, 80, 137, 90, 158, 219, 138, 38, 78, 174, 179, 213, 33, 80, 221, 91, 245, 232, 248, 38, 247, 76, 211, 208, 215, 87, 221, 123, 141, 137, 12, 73, 151, 58, 119, 231, 164, 84, 246, 166, 252, 61, 130, 140, 119, 101, 80, 176, 195, 185, 212, 179, 78, 70, 218, 51, 179, 166, 173, 144, 14, 202, 79, 71, 164, 214, 74, 171, 201, 76, 138, 194, 149, 140, 177, 159, 253, 80, 31, 232, 132, 70, 14, 146, 198, 47, 199, 230, 162, 170, 143, 63, 209, 200, 111, 71, 141, 134, 102, 100, 140, 139, 82, 120, 51, 132, 1, 246, 137, 92, 36, 129, 146, 141, 41, 213, 230, 171, 18, 35, 17, 22, 56, 10, 185, 46, 157, 195, 156, 82, 9, 71, 145, 128, 133, 185, 183, 59, 186, 202, 251, 183, 25, 83, 75, 55, 133, 219, 164, 91, 113, 185, 72, 192, 144, 133, 221, 182, 191, 147, 103, 159, 122, 248, 47, 231, 85, 193, 234, 252, 2, 243, 143, 222, 247, 150, 254, 198, 29, 181, 156, 110, 11, 4, 167, 33, 22, 177, 176, 88, 26, 226, 68, 154, 137, 196, 53, 226, 143, 169, 45, 99, 18, 41, 99, 83, 191, 7, 86, 189, 93, 68, 206, 46, 200, 20, 236, 98, 56, 178, 215, 234, 181, 248, 52, 22, 218, 21, 9, 114, 226, 165, 40, 232, 249, 174, 14, 225, 125, 35, 225, 72, 101, 12, 101, 97, 244, 107, 122, 91, 208, 112, 234, 36, 1, 73, 213, 249, 239, 192, 191, 198, 232, 51, 128, 237, 6, 44, 236, 41, 34, 254, 85, 143, 230, 29, 186, 153, 54, 58, 181, 92]},
		LmsTest{ test_passed: true, signature: &[0, 0, 53, 105, 0, 0, 0, 6, 191, 246, 33, 102, 16, 205, 146, 113, 210, 25, 119, 29, 136, 1, 17, 242, 192, 157, 33, 6, 20, 103, 195, 150, 160, 230, 175, 205, 32, 252, 3, 103, 85, 116, 14, 113, 171, 206, 91, 53, 183, 190, 59, 215, 0, 153, 236, 40, 240, 68, 220, 30, 51, 14, 177, 171, 182, 23, 168, 246, 3, 163, 93, 122, 180, 177, 140, 207, 214, 188, 208, 236, 43, 226, 125, 104, 173, 89, 218, 6, 137, 0, 35, 249, 51, 89, 127, 196, 251, 35, 28, 53, 65, 156, 48, 8, 188, 225, 132, 145, 19, 74, 226, 4, 225, 132, 230, 65, 220, 138, 235, 177, 116, 174, 187, 134, 85, 226, 203, 204, 85, 188, 75, 188, 107, 102, 110, 72, 115, 198, 189, 194, 117, 110, 49, 135, 59, 93, 195, 247, 56, 19, 174, 99, 49, 86, 72, 144, 233, 22, 96, 139, 21, 199, 87, 174, 76, 2, 197, 253, 151, 163, 193, 249, 238, 204, 144, 181, 109, 166, 138, 135, 118, 61, 171, 185, 31, 200, 30, 239, 244, 29, 85, 47, 154, 185, 49, 244, 6, 6, 156, 128, 218, 83, 219, 184, 103, 172, 63, 33, 233, 250, 233, 244, 221, 151, 35, 169, 12, 142, 12, 112, 157, 155, 187, 146, 61, 29, 141, 144, 217, 145, 50, 249, 107, 11, 145, 144, 118, 151, 181, 87, 18, 52, 151, 213, 175, 231, 76, 184, 117, 199, 169, 19, 53, 36, 9, 159, 148, 70, 75, 211, 91, 123, 119, 197, 140, 227, 30, 5, 143, 10, 180, 71, 51, 40, 231, 241, 133, 138, 127, 221, 238, 213, 80, 166, 16, 25, 141, 97, 12, 84, 92, 167, 145, 223, 78, 100, 173, 83, 247, 178, 99, 186, 117, 75, 65, 156, 71, 63, 11, 245, 182, 40, 211, 165, 87, 74, 96, 221, 49, 44, 171, 232, 195, 245, 238, 115, 254, 254, 2, 160, 160, 242, 217, 147, 125, 103, 15, 205, 202, 17, 216, 2, 153, 114, 128, 37, 226, 23, 9, 57, 192, 186, 241, 49, 18, 182, 146, 118, 113, 160, 35, 141, 226, 153, 233, 86, 93, 11, 4, 248, 96, 211, 144, 93, 112, 147, 103, 236, 95, 51, 114, 147, 60, 28, 26, 57, 104, 5, 124, 180, 63, 136, 38, 197, 205, 241, 234, 0, 8, 220, 87, 10, 192, 184, 83, 12, 36, 101, 24, 253, 89, 190, 64, 163, 162, 97, 204, 106, 149, 43, 116, 141, 191, 69, 198, 14, 63, 227, 54, 121, 190, 117, 211, 227, 116, 182, 51, 229, 73, 216, 74, 49, 215, 152, 117, 96, 15, 176, 195, 153, 29, 191, 98, 211, 13, 221, 182, 165, 114, 249, 179, 93, 11, 179, 54, 33, 199, 113, 187, 114, 145, 186, 165, 249, 150, 243, 22, 203, 91, 248, 79, 138, 85, 250, 148, 62, 102, 33, 24, 162, 96, 72, 198, 224, 73, 229, 159, 195, 121, 217, 146, 50, 69, 234, 119, 47, 54, 242, 79, 175, 201, 193, 104, 188, 109, 183, 155, 43, 180, 227, 250, 198, 208, 42, 54, 124, 32, 196, 175, 151, 221, 149, 123, 243, 90, 130, 25, 219, 124, 47, 194, 170, 157, 200, 231, 251, 92, 193, 192, 92, 32, 246, 189, 236, 189, 79, 145, 138, 255, 141, 217, 251, 83, 186, 3, 115, 34, 252, 49, 218, 159, 158, 34, 66, 227, 29, 114, 70, 164, 226, 234, 88, 242, 161, 189, 64, 232, 108, 27, 254, 70, 68, 85, 225, 102, 38, 51, 253, 244, 211, 195, 255, 120, 82, 51, 51, 190, 23, 147, 202, 152, 236, 97, 125, 41, 101, 100, 190, 129, 0, 234, 230, 184, 84, 65, 202, 210, 43, 164, 115, 86, 74, 53, 195, 34, 80, 106, 193, 146, 141, 43, 45, 231, 192, 125, 126, 221, 65, 208, 158, 58, 22, 103, 129, 43, 79, 177, 147, 147, 187, 189, 78, 228, 72, 139, 4, 75, 147, 144, 255, 152, 143, 144, 200, 104, 238, 136, 20, 191, 121, 234, 228, 33, 159, 168, 101, 176, 194, 76, 95, 217, 191, 30, 91, 148, 82, 24, 102, 186, 166, 254, 15, 203, 123, 63, 31, 48, 107, 193, 53, 192, 161, 181, 253, 14, 65, 67, 213, 106, 231, 34, 9, 50, 166, 8, 224, 17, 245, 62, 120, 57, 113, 224, 148, 214, 156, 160, 212, 111, 54, 38, 47, 171, 52, 168, 61, 97, 178, 112, 195, 54, 54, 87, 178, 14, 150, 79, 179, 81, 234, 4, 205, 250, 125, 115, 177, 51, 11, 239, 46, 106, 154, 159, 185, 91, 151, 120, 180, 197, 229, 249, 12, 184, 212, 180, 53, 218, 37, 88, 118, 113, 97, 171, 82, 243, 73, 200, 0, 138, 7, 116, 169, 222, 151, 181, 172, 105, 224, 198, 45, 196, 193, 174, 215, 220, 42, 124, 146, 62, 253, 25, 29, 120, 234, 44, 95, 34, 126, 105, 152, 230, 228, 231, 181, 183, 37, 10, 59, 224, 118, 123, 188, 69, 18, 4, 113, 254, 154, 180, 68, 171, 86, 129, 132, 47, 148, 148, 0, 76, 231, 7, 50, 190, 197, 32, 34, 50, 48, 213, 236, 122, 186, 172, 154, 173, 123, 75, 125, 31, 5, 213, 126, 248, 65, 108, 97, 229, 211, 128, 187, 106, 94, 21, 184, 2, 114, 34, 75, 190, 80, 69, 53, 248, 123, 214, 236, 165, 6, 168, 67, 28, 13, 19, 93, 218, 152, 136, 110, 189, 51, 32, 63, 239, 85, 233, 245, 191, 214, 79, 13, 22, 154, 164, 72, 182, 204, 18, 80, 214, 216, 166, 21, 56, 52, 65, 99, 184, 138, 227, 179, 40, 230, 168, 5, 231, 148, 239, 59, 176, 254, 41, 220, 44, 34, 81, 28, 84, 119, 181, 226, 20, 145, 118, 104, 55, 103, 107, 207, 76, 41, 56, 221, 20, 129, 6, 127, 35, 52, 100, 183, 146, 97, 238, 240, 98, 215, 252, 96, 53, 118, 195, 40, 125, 179, 117, 51, 88, 73, 68, 43, 99, 233, 30, 166, 178, 217, 93, 66, 207, 77, 226, 36, 228, 153, 236, 26, 15, 225, 86, 19, 193, 236, 99, 119, 206, 136, 219, 202, 9, 220, 153, 241, 125, 69, 238, 164, 115, 152, 70, 7, 6, 147, 81, 109, 14, 125, 80, 227, 114, 208, 222, 232, 36, 182, 146, 188, 17, 63, 169, 97, 96, 53, 31, 71, 22, 158, 156, 76, 2, 56, 227, 91, 167, 249, 225, 156, 126, 91, 170, 223, 12, 88, 249, 124, 100, 135, 177, 57, 36, 124, 41, 153, 90, 154, 32, 127, 174, 122, 221, 36, 197, 159, 216, 58, 191, 174, 111, 155, 44, 51, 212, 222, 184, 188, 85, 198, 5, 29, 147, 4, 218, 163, 19, 125, 37, 59, 89, 224, 170, 56, 239, 183, 156, 115, 56, 245, 173, 49, 241, 114, 37, 203, 215, 172, 239, 57, 231, 206, 129, 136, 219, 51, 0, 173, 187, 92, 186, 53, 237, 221, 39, 232, 82, 111, 109, 13, 102, 196, 171, 163, 8, 117, 161, 86, 15, 237, 30, 243, 60, 85, 163, 221, 109, 65, 205, 134, 75, 68, 145, 9, 49, 154, 52, 166, 6, 79, 89, 4, 81, 67, 91, 157, 203, 249, 74, 161, 34, 196, 203, 87, 39, 201, 228, 173, 241, 203, 39, 220, 59, 43, 125, 60, 172, 18, 9, 235, 131, 193, 130, 82, 115, 57, 201, 4, 175, 79, 139, 52, 203, 252, 146, 130, 72, 208, 91, 52, 122, 194, 126, 88, 106, 79, 34, 54, 157, 158, 242, 26, 223, 70, 14, 17, 191, 76, 162, 88, 167, 172, 173, 135, 214, 66, 25, 100, 87, 203, 236, 223, 82, 139, 17, 162, 98, 146, 26, 18, 161, 253, 187, 62, 41, 192, 193, 221, 37, 255, 109, 105, 84, 147, 75, 137, 133, 121, 100, 229, 7, 178, 225, 236, 73, 177, 243, 7, 159, 215, 177, 2, 95, 116, 49, 206, 238, 240, 42, 52, 214, 18, 6, 207, 113, 146, 193, 166, 36, 147, 9, 122, 23, 238, 214, 253, 1, 187, 72, 33, 107, 253, 212, 141, 28, 100, 54, 52, 41, 90, 238, 181, 165, 177, 102, 165, 66, 42, 251, 143, 223, 96, 16, 54, 229, 58, 145, 109, 56, 48, 140, 250, 60, 170, 22, 150, 32, 170, 69, 162, 183, 139, 72, 71, 18, 113, 91, 87, 16, 38, 7, 252, 191, 63, 118, 106, 52, 123, 131, 240, 80, 77, 66, 165, 190, 253, 15, 84, 205, 41, 197, 130, 41, 86, 134, 228, 6, 214, 161, 244, 132, 180, 14, 223, 241, 167, 156, 243, 99, 215, 157, 68, 25, 225, 58, 101, 69, 119, 34, 217, 87, 238, 54, 220, 88, 30, 194, 79, 255, 213, 34, 183, 185, 89, 72, 90, 108, 220, 18, 59, 171, 245, 223, 245, 145, 20, 92, 131, 16, 173, 203, 232, 177, 75, 184, 38, 189, 5, 99, 167, 150, 122, 174, 250, 174, 25, 25, 153, 37, 181, 23, 87, 17, 130, 21, 141, 7, 194, 158, 25, 12, 135, 250, 239, 244, 185, 62, 108, 216, 1, 59, 186, 225, 58, 73, 151, 109, 254, 117, 176, 164, 236, 182, 117, 118, 255, 198, 232, 150, 228, 144, 48, 175, 229, 33, 164, 178, 68, 202, 78, 87, 122, 14, 122, 102, 154, 216, 139, 209, 213, 254, 71, 170, 147, 196, 110, 202, 246, 216, 140, 211, 244, 189, 91, 41, 138, 5, 247, 192, 186, 24, 4, 209, 200, 172, 134, 63, 139, 226, 30, 99, 31, 141, 79, 162, 229, 139, 240, 88, 110, 24, 47, 107, 150, 214, 97, 11, 253, 114, 48, 120, 152, 88, 152, 232, 45, 48, 226, 16, 208, 133, 130, 246, 229, 169, 248, 51, 33, 154, 184, 3, 40, 77, 249, 19, 22, 146, 30, 241, 54, 148, 143, 245, 58, 0, 80, 86, 214, 99, 241, 7, 142, 245, 212, 236, 246, 185, 59, 168, 123, 127, 97, 73, 103, 241, 245, 125, 114, 86, 61, 30, 250, 184, 164, 106, 1, 60, 187, 210, 221, 244, 216, 39, 6, 49, 6, 130, 195, 5, 201, 71, 159, 212, 19, 83, 107, 111, 227, 67, 232, 6, 85, 107, 161, 199, 56, 64, 186, 237, 232, 214, 84, 162, 127, 234, 10, 163, 76, 183, 68, 87, 200, 228, 41, 115, 147, 119, 167, 100, 149, 159, 89, 75, 194, 168, 143, 22, 198, 131, 240, 137, 71, 39, 133, 26, 107, 59, 48, 130, 121, 33, 39, 74, 93, 97, 73, 218, 128, 32, 206, 145, 153, 145, 146, 231, 231, 64, 198, 112, 219, 226, 35, 96, 165, 17, 138, 193, 211, 145, 123, 19, 172, 65, 185, 22, 100, 224, 227, 135, 92, 60, 77, 244, 66, 62, 188, 191, 230, 231, 115, 118, 242, 208, 76, 242, 223, 25, 123, 150, 165, 150, 178, 38, 223, 228, 103, 36, 215, 244, 41, 23, 30, 222, 208, 139, 152, 89, 79, 134, 31, 20, 212, 230, 86, 179, 156, 27, 98, 255, 243, 144, 189, 164, 174, 188, 101, 155, 106, 49, 158, 32, 178, 239, 211, 232, 140, 183, 184, 27, 226, 156, 184, 232, 125, 104, 229, 128, 37, 164, 50, 74, 86, 194, 223, 66, 165, 202, 228, 39, 250, 147, 191, 168, 239, 12, 152, 149, 114, 230, 109, 126, 211, 173, 32, 249, 83, 185, 84, 40, 6, 176, 117, 29, 105, 200, 167, 112, 120, 60, 210, 0, 181, 90, 53, 236, 63, 212, 248, 243, 241, 224, 70, 11, 253, 113, 97, 137, 20, 240, 232, 243, 232, 163, 139, 153, 83, 202, 46, 160, 225, 18, 68, 80, 115, 29, 249, 51, 84, 51, 98, 197, 145, 189, 99, 183, 27, 236, 252, 208, 231, 77, 74, 210, 166, 241, 24, 106, 7, 239, 114, 9, 145, 74, 205, 212, 207, 223, 207, 176, 60, 217, 27, 176, 234, 46, 34, 195, 236, 31, 11, 226, 212, 159, 229, 249, 204, 158, 130, 227, 43, 89, 154, 124, 35, 26, 108, 208, 246, 140, 165, 58, 100, 62, 139, 57, 162, 163, 66, 6, 30, 135, 191, 176, 223, 170, 11, 245, 69, 136, 125, 148, 15, 13, 95, 143, 240, 71, 42, 45, 7, 16, 243, 1, 34, 31, 204, 32, 204, 227, 176, 130, 28, 36, 69, 126, 20, 183, 193, 135, 129, 81, 55, 252, 136, 191, 58, 157, 25, 118, 121, 222, 142, 224, 134, 133, 31, 203, 177, 181, 150, 100, 159, 74, 63, 41, 181, 156, 155, 133, 189, 94, 114, 38, 169, 150, 117, 247, 192, 77, 31, 84, 139, 23, 161, 217, 168, 66, 83, 109, 55, 100, 247, 59, 215, 150, 157, 15, 141, 23, 122, 183, 74, 7, 32, 183, 251, 162, 55, 113, 242, 148, 107, 5, 87, 49, 146, 49, 252, 179, 230, 175, 197, 30, 136, 182, 42, 248, 1, 119, 95, 180, 187, 143, 35, 12, 8, 70, 75, 183, 225, 239, 208, 99, 162, 206, 198, 232, 93, 47, 52, 110, 183, 249, 20, 137, 116, 237, 132, 49, 91, 216, 146, 60, 16, 244, 72, 65, 1, 111, 214, 162, 206, 186, 88, 255, 198, 252, 194, 39, 181, 185, 65, 214, 39, 130, 166, 82, 244, 205, 199, 90, 49, 206, 212, 90, 202, 240, 137, 166, 138, 247, 115, 244, 211, 21, 193, 156, 222, 173, 214, 146, 0, 42, 152, 149, 138, 155, 128, 225, 173, 198, 184, 129, 151, 29, 106, 61, 101, 194, 113, 13, 219, 210, 85, 243, 153, 209, 194, 201, 164, 86, 196, 149, 36, 58, 118, 69, 177, 46, 162, 43, 195, 130, 227, 93, 191, 93, 242, 53, 145, 139, 14, 249, 231, 99, 4, 222, 146, 49, 162, 207, 116, 157, 205, 17, 168, 131, 253, 115, 201, 132, 220, 51, 132, 51, 30, 250, 149, 111, 173, 231, 59, 112, 4, 150, 34, 152, 127, 121, 33, 221, 105, 91, 181, 21, 89, 222, 228, 96, 162, 81, 161, 112, 23, 32, 247, 186, 3, 198, 140, 108, 126, 253, 114, 102, 230, 66, 116, 175, 60, 79, 175, 51, 116, 129, 185, 94, 36, 94, 189, 250, 108, 47, 29, 239, 77, 155, 203, 132, 101, 187, 218, 157, 221, 171, 96, 32, 196, 112, 214, 72, 56, 170, 212, 14, 27, 171, 244, 197, 124, 179, 89, 187, 245, 51, 141, 106, 50, 230, 123, 125, 100, 187, 223, 161, 77, 122, 195, 41, 133, 169, 9, 169, 251, 81, 153, 13, 19, 128, 217, 126, 17, 136, 84, 18, 190, 210, 219, 80, 238, 217, 155, 12, 111, 179, 16, 190, 38, 5, 181, 213, 9, 248, 102, 15, 236, 135, 179, 112, 177, 0, 0, 0, 12, 14, 134, 128, 168, 129, 69, 49, 167, 21, 230, 233, 10, 191, 52, 111, 212, 232, 197, 103, 246, 79, 199, 103, 13, 85, 48, 168, 225, 67, 24, 163, 150, 38, 3, 36, 90, 100, 17, 206, 134, 166, 246, 58, 60, 199, 46, 46, 201, 230, 204, 130, 3, 6, 122, 240, 53, 235, 43, 119, 221, 199, 100, 37, 8, 123, 15, 36, 107, 147, 113, 83, 244, 164, 232, 108, 230, 243, 214, 63, 184, 88, 0, 91, 250, 42, 30, 228, 177, 188, 173, 246, 77, 24, 111, 43, 145, 158, 99, 247, 243, 46, 229, 9, 117, 4, 218, 141, 51, 22, 22, 2, 74, 74, 86, 223, 191, 146, 218, 60, 72, 148, 250, 179, 155, 164, 187, 179, 133, 32, 253, 231, 167, 237, 55, 159, 118, 138, 182, 230, 24, 180, 166, 204, 147, 27, 214, 132, 160, 243, 102, 161, 189, 168, 52, 40, 186, 40, 154, 83, 156, 44, 90, 184, 33, 20, 18, 66, 123, 204, 18, 103, 42, 71, 132, 155, 169, 4, 147, 14, 210, 105, 99, 175, 172, 191, 23, 239, 165, 179, 203, 199, 210, 214, 60, 196, 90, 59, 47, 13, 198, 131, 93, 20, 230, 39, 20, 228, 240, 17, 104, 192, 227, 82, 75, 176, 6, 121, 166, 11, 83, 209, 206, 142, 147, 209, 49, 109, 75, 113, 67, 7, 22, 85, 211, 166, 27, 168, 97, 252, 211, 231, 52, 187, 232, 141, 122, 242, 127, 9, 154, 240, 239, 220, 133, 26, 127, 129, 98, 221, 102, 131, 122, 247, 215, 77, 15, 17, 225, 179, 221, 218, 23, 200, 87, 114, 234, 14, 95, 246, 115, 204, 122, 18, 239, 232, 78, 38, 147, 76, 7, 87, 138, 171, 46, 212, 23, 155, 119, 211, 110, 41, 98, 6, 163, 128, 56, 240, 0, 222, 99, 226, 231, 66, 126, 102, 90, 51, 229, 156, 195, 37, 149, 54, 48, 41, 59, 185, 118, 139, 224, 159, 5, 18, 25, 56, 232, 114, 12, 55, 181, 155, 202, 70, 185, 168, 80, 183, 234, 34, 82, 43, 56, 203, 160, 30, 90, 169, 207, 193, 16]},
	];
	for t in TESTS {
        let (head, thing2, _tail): (&[u8], &[LmsSignature<6, 101, 15>], &[u8]) =
            unsafe { t.signature.align_to::<LmsSignature<6, 101, 15>>() };

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