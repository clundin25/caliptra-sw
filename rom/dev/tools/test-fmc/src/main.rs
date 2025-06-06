/*++

Licensed under the Apache-2.0 license.

File Name:

    main.rs

Abstract:

    File contains main entry point for Caliptra ROM Test FMC

--*/
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), no_main)]

use caliptra_common::pcr::PCR_ID_STASH_MEASUREMENT;
use caliptra_common::PcrLogEntry;
use caliptra_common::{mailbox_api, FuseLogEntry, FuseLogEntryId};
use caliptra_drivers::pcr_log::MeasurementLogEntry;
use caliptra_drivers::{
    ColdResetEntry4::*, DataVault, Mailbox, PcrBank, PcrId, PersistentDataAccessor,
    WarmResetEntry4::*,
};
use caliptra_registers::dv::DvReg;
use caliptra_registers::pv::PvReg;
use caliptra_registers::soc_ifc::SocIfcReg;
use caliptra_x509::{Ecdsa384CertBuilder, Ecdsa384Signature, FmcAliasCertTbs, LocalDevIdCertTbs};
use ureg::RealMmioMut;
use zerocopy::IntoBytes;

#[cfg(not(feature = "std"))]
core::arch::global_asm!(include_str!("start.S"));

mod exception;
mod print;

const FW_LOAD_CMD_OPCODE: u32 = mailbox_api::CommandId::FIRMWARE_LOAD.0;

#[cfg(feature = "std")]
pub fn main() {}

// Dummy RO data to max out FMC image size to 16K.
// Note: Adjust this value to account for new changes in this FMC image.
#[cfg(all(feature = "interactive_test_fmc", not(feature = "fake-fmc")))]
const PAD_LEN: usize = 4988; // TEST_FMC_INTERACTIVE
#[cfg(all(feature = "fake-fmc", not(feature = "interactive_test_fmc")))]
const PAD_LEN: usize = 5224; // FAKE_TEST_FMC_WITH_UART
#[cfg(all(feature = "interactive_test_fmc", feature = "fake-fmc"))]
const PAD_LEN: usize = 5452; // FAKE_TEST_FMC_INTERACTIVE
#[cfg(not(any(feature = "interactive_test_fmc", feature = "fake-fmc")))]
const PAD_LEN: usize = 0;

static PAD: [u32; PAD_LEN / 4] = {
    let mut result = [0xdeadbeef_u32; PAD_LEN / 4];
    let mut i = 0;
    while i < result.len() {
        result[i] = result[i].wrapping_add(i as u32);
        i += 1;
    }
    result
};

const BANNER: &str = r#"
Running Caliptra FMC ...
"#;

#[no_mangle]
pub extern "C" fn fmc_entry() -> ! {
    cprintln!("{}", BANNER);

    if cfg!(not(feature = "fake-fmc")) {
        let persistent_data = unsafe { PersistentDataAccessor::new() };
        assert!(persistent_data.get().fht.is_valid());
    }

    process_mailbox_commands();

    caliptra_drivers::ExitCtrl::exit(0)
}

#[no_mangle]
#[inline(never)]
#[allow(clippy::empty_loop)]
extern "C" fn exception_handler(exception: &exception::ExceptionRecord) {
    cprintln!(
        "FMC EXCEPTION mcause=0x{:08X} mscause=0x{:08X} mepc=0x{:08X}",
        exception.mcause,
        exception.mscause,
        exception.mepc
    );

    loop {
        unsafe { Mailbox::abort_pending_soc_to_uc_transactions() };
    }
}

#[no_mangle]
#[inline(never)]
#[allow(clippy::empty_loop)]
extern "C" fn nmi_handler(exception: &exception::ExceptionRecord) {
    cprintln!(
        "FMC NMI mcause=0x{:08X} mscause=0x{:08X} mepc=0x{:08X}",
        exception.mcause,
        exception.mscause,
        exception.mepc
    );

    loop {
        unsafe { Mailbox::abort_pending_soc_to_uc_transactions() };
    }
}

#[panic_handler]
#[inline(never)]
#[cfg(not(feature = "std"))]
#[allow(clippy::empty_loop)]
fn fmc_panic(_: &core::panic::PanicInfo) -> ! {
    cprintln!("FMC Panic!!");
    loop {}
}

fn create_certs(mbox: &caliptra_registers::mbox::RegisterBlock<RealMmioMut>) {
    //
    // Create LDEVID cert.
    //

    // Retrieve the public key and signature from the data vault.
    let data_vault = unsafe { DataVault::new(DvReg::new()) };
    let ldevid_pub_key = data_vault.ldev_dice_pub_key();
    let mut _pub_der: [u8; 97] = ldevid_pub_key.to_der();
    cprint_slice!("[fmc] LDEVID PUBLIC KEY DER", _pub_der);

    let sig = data_vault.ldev_dice_signature();

    let ecdsa_sig = Ecdsa384Signature {
        r: sig.r.into(),
        s: sig.s.into(),
    };
    let mut tbs: [u8; core::mem::size_of::<LocalDevIdCertTbs>()] =
        [0u8; core::mem::size_of::<LocalDevIdCertTbs>()];
    copy_tbs(&mut tbs, true);

    let mut cert: [u8; 1024] = [0u8; 1024];
    let builder = Ecdsa384CertBuilder::new(
        &tbs[..core::mem::size_of::<LocalDevIdCertTbs>()],
        &ecdsa_sig,
    )
    .unwrap();
    let _cert_len = builder.build(&mut cert).unwrap();
    cprint_slice_ref!("[fmc] LDEVID cert", &cert[.._cert_len]);

    //
    // Create FMCALIAS cert.
    //

    // Retrieve the public key and signature from the data vault.
    let fmcalias_pub_key = data_vault.fmc_pub_key();
    let _pub_der: [u8; 97] = fmcalias_pub_key.to_der();
    cprint_slice!("[fmc] FMCALIAS PUBLIC KEY DER", _pub_der);

    let sig = data_vault.fmc_dice_signature();
    let ecdsa_sig = Ecdsa384Signature {
        r: sig.r.into(),
        s: sig.s.into(),
    };

    let mut tbs: [u8; core::mem::size_of::<FmcAliasCertTbs>()] =
        [0u8; core::mem::size_of::<FmcAliasCertTbs>()];
    copy_tbs(&mut tbs, false);

    let mut cert: [u8; 1024] = [0u8; 1024];
    let builder =
        Ecdsa384CertBuilder::new(&tbs[..core::mem::size_of::<FmcAliasCertTbs>()], &ecdsa_sig)
            .unwrap();
    let _cert_len = builder.build(&mut cert).unwrap();
    cprint_slice_ref!("[fmc] FMCALIAS cert", &cert[.._cert_len]);

    mbox.status().write(|w| w.status(|w| w.cmd_complete()));
}

fn copy_tbs(tbs: &mut [u8], ldevid_tbs: bool) {
    let persistent_data = unsafe { PersistentDataAccessor::new() };
    // Copy the tbs from DCCM
    let src = if ldevid_tbs {
        &persistent_data.get().ldevid_tbs
    } else {
        &persistent_data.get().fmcalias_tbs
    };
    tbs.copy_from_slice(&src[..tbs.len()]);
}

fn process_mailbox_command(mbox: &caliptra_registers::mbox::RegisterBlock<RealMmioMut>) {
    if !mbox.status().read().mbox_fsm_ps().mbox_execute_uc() {
        return;
    }
    let cmd = mbox.cmd().read();
    cprintln!("[fmc] Received command: 0x{:08X}", cmd);
    match cmd {
        0x1000_0000 => {
            read_pcr_log(mbox);
        }
        0x1000_0001 => {
            create_certs(mbox);
        }
        0x1000_0002 => {
            read_fuse_log(mbox);
        }
        0x1000_0003 => {
            read_fht(mbox);
        }
        0x1000_0004 => {
            mbox.status().write(|w| w.status(|w| w.cmd_complete()));
            // Reset the CPU with no command in the mailbox
            trigger_update_reset();
        }

        0x1000_0005 => {
            read_datavault_coldresetentry4(mbox);
        }
        0x1000_0006 => {
            read_pcrs(mbox);
        }
        0x1000_0007 => {
            try_to_reset_pcrs(mbox);
        }
        0x1000_0008 => {
            read_rom_info(mbox);
        }
        0x1000_0009 => {
            read_pcr31(mbox);
        }
        0x1000_000A => {
            read_measurement_log(mbox);
        }
        0x1000_000B => {
            // Reset the CPU with an unknown command in the mailbox
            trigger_update_reset();
        }
        FW_LOAD_CMD_OPCODE => {
            // Reset the CPU with the firmware-update command in the mailbox
            trigger_update_reset();
        }
        // Exit with success
        0x1000_000C => {
            mbox.status().write(|w| w.status(|w| w.cmd_complete()));
            caliptra_drivers::ExitCtrl::exit(0);
        }
        0x1000_000D => {
            read_datavault_warmresetentry4(mbox);
        }
        0x1000_000E => {
            validate_fmc_rt_load_in_iccm(mbox);
        }
        _ => {}
    }
}

fn process_mailbox_commands() {
    let mut mbox = unsafe { caliptra_registers::mbox::MboxCsr::new() };
    let mbox = mbox.regs_mut();

    #[cfg(feature = "interactive_test_fmc")]
    loop {
        if mbox.status().read().mbox_fsm_ps().mbox_execute_uc() {
            process_mailbox_command(&mbox);
        }
    }

    #[cfg(not(feature = "interactive_test_fmc"))]
    process_mailbox_command(&mbox);
}

fn validate_fmc_rt_load_in_iccm(mbox: &caliptra_registers::mbox::RegisterBlock<RealMmioMut>) {
    let data_vault = unsafe { DataVault::new(DvReg::new()) };
    let fmc_load_addr = data_vault.fmc_entry_point();
    let rt_load_addr = data_vault.rt_entry_point();
    let fmc_size = mbox.dataout().read() as usize;
    let rt_size = mbox.dataout().read() as usize;

    let fmc_iccm = unsafe {
        let ptr = fmc_load_addr as *mut u32;
        core::slice::from_raw_parts_mut(ptr, fmc_size / 4)
    };

    let rt_iccm = unsafe {
        let ptr = rt_load_addr as *mut u32;
        core::slice::from_raw_parts_mut(ptr, rt_size / 4)
    };

    let mut mismatch = false;
    for (idx, _) in fmc_iccm.iter().enumerate().take(fmc_size / 4) {
        let temp = mbox.dataout().read();
        if temp != fmc_iccm[idx] {
            cprint!(
                "FMC load mismatch at index {} (0x{:08X} != 0x{:08X})",
                idx,
                temp,
                fmc_iccm[idx]
            );
            mismatch = true;
            cprint!("PAD[{}] = 0x{:08X}", idx, PAD[idx]);
        }
    }
    for (idx, _) in rt_iccm.iter().enumerate().take(rt_size / 4) {
        let temp = mbox.dataout().read();
        if temp != rt_iccm[idx] {
            cprint!(
                "RT load mismatch at index {} (0x{:08X} != 0x{:08X})",
                idx,
                temp,
                rt_iccm[idx]
            );
            mismatch = true;
        }
    }

    if mismatch {
        send_to_mailbox(mbox, &[1], false);
    } else {
        send_to_mailbox(mbox, &[0], false);
    }
    mbox.dlen().write(|_| 1.try_into().unwrap());
    mbox.status().write(|w| w.status(|w| w.data_ready()));
}

fn read_pcr31(mbox: &caliptra_registers::mbox::RegisterBlock<RealMmioMut>) {
    let pcr_bank = unsafe { PcrBank::new(PvReg::new()) };
    let pcr31: [u8; 48] = pcr_bank.read_pcr(PCR_ID_STASH_MEASUREMENT).into();
    send_to_mailbox(mbox, &pcr31, true);
}

fn read_datavault_coldresetentry4(mbox: &caliptra_registers::mbox::RegisterBlock<RealMmioMut>) {
    let data_vault = unsafe { DataVault::new(DvReg::new()) };
    send_to_mailbox(mbox, (FmcSvn as u32).as_bytes(), false);
    send_to_mailbox(mbox, data_vault.fmc_svn().as_bytes(), false);

    send_to_mailbox(mbox, (RomColdBootStatus as u32).as_bytes(), false);
    send_to_mailbox(mbox, data_vault.rom_cold_boot_status().as_bytes(), false);

    send_to_mailbox(mbox, (FmcEntryPoint as u32).as_bytes(), false);
    send_to_mailbox(mbox, data_vault.fmc_entry_point().as_bytes(), false);

    send_to_mailbox(mbox, (EccVendorPubKeyIndex as u32).as_bytes(), false);
    send_to_mailbox(mbox, data_vault.ecc_vendor_pk_index().as_bytes(), false);

    send_to_mailbox(mbox, (LmsVendorPubKeyIndex as u32).as_bytes(), false);
    send_to_mailbox(mbox, data_vault.lms_vendor_pk_index().as_bytes(), false);

    mbox.dlen()
        .write(|_| (core::mem::size_of::<u32>() * 10).try_into().unwrap());
    mbox.status().write(|w| w.status(|w| w.data_ready()));
}

fn read_datavault_warmresetentry4(mbox: &caliptra_registers::mbox::RegisterBlock<RealMmioMut>) {
    let data_vault = unsafe { DataVault::new(DvReg::new()) };
    send_to_mailbox(mbox, (RtSvn as u32).as_bytes(), false);
    send_to_mailbox(mbox, data_vault.rt_svn().as_bytes(), false);

    send_to_mailbox(mbox, (RtEntryPoint as u32).as_bytes(), false);
    send_to_mailbox(mbox, data_vault.rt_entry_point().as_bytes(), false);

    send_to_mailbox(mbox, (ManifestAddr as u32).as_bytes(), false);
    send_to_mailbox(mbox, data_vault.manifest_addr().as_bytes(), false);

    send_to_mailbox(mbox, (RtMinSvn as u32).as_bytes(), false);
    send_to_mailbox(mbox, data_vault.rt_min_svn().as_bytes(), false);

    send_to_mailbox(mbox, (RomUpdateResetStatus as u32).as_bytes(), false);
    send_to_mailbox(mbox, data_vault.rom_update_reset_status().as_bytes(), false);

    mbox.dlen()
        .write(|_| (core::mem::size_of::<u32>() * 10).try_into().unwrap());
    mbox.status().write(|w| w.status(|w| w.data_ready()));
}

fn trigger_update_reset() {
    unsafe { SocIfcReg::new() }
        .regs_mut()
        .internal_fw_update_reset()
        .write(|w| w.core_rst(true));
}

fn read_pcr_log(mbox: &caliptra_registers::mbox::RegisterBlock<RealMmioMut>) {
    let persistent_data = unsafe { PersistentDataAccessor::new() };
    let pcr_entry_count = persistent_data.get().fht.pcr_log_index as usize;

    for i in 0..pcr_entry_count {
        let pcr_entry = persistent_data.get().pcr_log[i];
        send_to_mailbox(mbox, pcr_entry.as_bytes(), false);
    }

    mbox.dlen().write(|_| {
        (core::mem::size_of::<PcrLogEntry>() * pcr_entry_count)
            .try_into()
            .unwrap()
    });
    mbox.status().write(|w| w.status(|w| w.data_ready()));
}

fn read_measurement_log(mbox: &caliptra_registers::mbox::RegisterBlock<RealMmioMut>) {
    let persistent_data = unsafe { PersistentDataAccessor::new() };
    let measurement_entry_count = persistent_data.get().fht.meas_log_index as usize;

    for i in 0..measurement_entry_count {
        let meas_entry = persistent_data.get().measurement_log[i];
        send_to_mailbox(mbox, meas_entry.as_bytes(), false);
    }

    mbox.dlen().write(|_| {
        (core::mem::size_of::<MeasurementLogEntry>() * measurement_entry_count)
            .try_into()
            .unwrap()
    });
    mbox.status().write(|w| w.status(|w| w.data_ready()));
}

fn swap_word_bytes_inplace(words: &mut [u32]) {
    for word in words.iter_mut() {
        *word = word.swap_bytes()
    }
}

fn read_pcrs(mbox: &caliptra_registers::mbox::RegisterBlock<RealMmioMut>) {
    let pcr_bank = unsafe { PcrBank::new(PvReg::new()) };
    const PCR_COUNT: usize = 32;
    for i in 0..PCR_COUNT {
        let pcr = pcr_bank.read_pcr(PcrId::try_from(i as u8).unwrap());
        let mut pcr_bytes: [u32; 12] = pcr.try_into().unwrap();

        swap_word_bytes_inplace(&mut pcr_bytes);
        send_to_mailbox(mbox, pcr.as_bytes(), false);
    }

    mbox.dlen().write(|_| (48 * PCR_COUNT).try_into().unwrap());
    mbox.status().write(|w| w.status(|w| w.data_ready()));
}

// Returns a list of u8 values, 0 on success, 1 on failure:
//   - Whether PCR0 is locked
//   - Whether PCR1 is locked
//   - Whether PCR2 is unlocked
//   - Whether PCR31 is locked
fn try_to_reset_pcrs(mbox: &caliptra_registers::mbox::RegisterBlock<RealMmioMut>) {
    let mut pcr_bank = unsafe { PcrBank::new(PvReg::new()) };

    let res0 = pcr_bank.erase_pcr(PcrId::PcrId0);
    let res1 = pcr_bank.erase_pcr(PcrId::PcrId1);
    let res2 = pcr_bank.erase_pcr(PcrId::PcrId2);
    let res31 = pcr_bank.erase_pcr(PcrId::PcrId31);

    let ret_vals: [u8; 4] = [
        if res0.is_err() { 0 } else { 1 },
        if res1.is_err() { 0 } else { 1 },
        if res2.is_ok() { 0 } else { 1 },
        if res31.is_err() { 0 } else { 1 },
    ];

    send_to_mailbox(mbox, &ret_vals, false);
    mbox.dlen().write(|_| ret_vals.len().try_into().unwrap());
    mbox.status().write(|w| w.status(|w| w.data_ready()));
}

fn read_rom_info(mbox: &caliptra_registers::mbox::RegisterBlock<RealMmioMut>) {
    let persistent_data = unsafe { PersistentDataAccessor::new() };
    send_to_mailbox(
        mbox,
        persistent_data
            .get()
            .fht
            .rom_info_addr
            .get()
            .unwrap()
            .as_bytes(),
        true,
    );
}

fn read_fuse_log(mbox: &caliptra_registers::mbox::RegisterBlock<RealMmioMut>) {
    let mut fuse_entry_count = 0;
    loop {
        let fuse_entry = get_fuse_entry(fuse_entry_count);
        if FuseLogEntryId::from(fuse_entry.entry_id) == FuseLogEntryId::Invalid {
            break;
        }

        fuse_entry_count += 1;
        send_to_mailbox(mbox, fuse_entry.as_bytes(), false);
    }

    mbox.dlen().write(|_| {
        (core::mem::size_of::<FuseLogEntry>() * fuse_entry_count)
            .try_into()
            .unwrap()
    });
    mbox.status().write(|w| w.status(|w| w.data_ready()));
}

fn get_fuse_entry(entry_index: usize) -> FuseLogEntry {
    let persistent_data = unsafe { PersistentDataAccessor::new() };
    persistent_data.get().fuse_log[entry_index]
}

fn read_fht(mbox: &caliptra_registers::mbox::RegisterBlock<RealMmioMut>) {
    let persistent_data = unsafe { PersistentDataAccessor::new() };
    send_to_mailbox(mbox, persistent_data.get().fht.as_bytes(), true);
}

fn send_to_mailbox(
    mbox: &caliptra_registers::mbox::RegisterBlock<RealMmioMut>,
    data: &[u8],
    update_mb_state: bool,
) {
    let data_len = data.len();
    let word_size = core::mem::size_of::<u32>();
    let remainder = data_len % word_size;
    let n = data_len - remainder;
    for idx in (0..n).step_by(word_size) {
        mbox.datain()
            .write(|_| u32::from_le_bytes(data[idx..idx + word_size].try_into().unwrap()));
    }

    if remainder > 0 {
        let mut last_word = data[n] as u32;
        for idx in 1..remainder {
            last_word |= (data[n + idx] as u32) << (idx << 3);
        }
        mbox.datain().write(|_| last_word);
    }

    if update_mb_state {
        mbox.dlen().write(|_| data_len as u32);
        mbox.status().write(|w| w.status(|w| w.data_ready()));
    }
}
