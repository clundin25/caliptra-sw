// Licensed under the Apache-2.0 license
//
#![no_std]

#[cfg(hw_rev_latest)]
pub use caliptra_registers_latest::*;

#[cfg(hw_rev_2_1)]
pub use caliptra_registers_rev_2_1::*;

#[cfg(hw_rev_2_0)]
compile_error!("TODO: add v2.0 HW register definitions");
