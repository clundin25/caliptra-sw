use caliptra_api::{
    mailbox::{
        CommandId, MailboxReq, MailboxReqHeader, ReportHekMetadataReq, ReportHekMetadataResp,
        ReportHekMetadataRespFlags,
    },
    SocManager,
};
use caliptra_builder::firmware::runtime_tests;
use caliptra_drivers::HekSeedState;
use caliptra_hw_model::{
    otp_provision::LifecycleControllerState, DeviceLifecycle, HwModel, SecurityState,
};
use caliptra_runtime::RtBootStatus;
use dpe::U8Bool;
use zerocopy::{FromBytes, IntoBytes};

use crate::common::{run_rt_test, RuntimeTestArgs};

#[test]
fn test_hek_metadata_never_reported() {
    let mut model = run_rt_test(RuntimeTestArgs {
        test_fwid: Some(&runtime_tests::MBOX_FPGA),
        ..Default::default()
    });

    model.step_until_boot_status(u32::from(RtBootStatus::RtReadyForCommands), true);

    let expected_val = U8Bool::new(false);
    // HEK can NEVER be valid if MCU ROM never reported the HEK metadata.
    let resp = model.mailbox_execute(0xF100_0000, &[]).unwrap().unwrap();
    assert_eq!(resp.as_bytes(), expected_val.as_bytes());
}

#[test]
fn test_hek_available() {
    let mut model = run_rt_test(RuntimeTestArgs {
        test_fwid: Some(&runtime_tests::MBOX_FPGA),
        successful_reach_rt: false,
        ..Default::default()
    });

    let mut cmd = MailboxReq::ReportHekMetadata(ReportHekMetadataReq {
        hdr: MailboxReqHeader { chksum: 0 },
        seed_state: HekSeedState::Programmed.into(),
        ..Default::default()
    });

    cmd.populate_chksum().unwrap();
    let response = model
        .mailbox_execute(
            CommandId::REPORT_HEK_METADATA.into(),
            cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .unwrap();

    let response = ReportHekMetadataResp::ref_from_bytes(response.as_bytes()).unwrap();
    assert!(response
        .flags
        .contains(ReportHekMetadataRespFlags::HEK_AVAILABLE));

    // Signal to boot into runtime FW
    model
        .mailbox_execute(CommandId::RI_DOWNLOAD_FIRMWARE.into(), &[])
        .unwrap();
    model.step_until_boot_status(u32::from(RtBootStatus::RtReadyForCommands), true);

    // We reported HEK metadata so it should be available.
    let expected_val = U8Bool::new(true);
    let resp = model.mailbox_execute(0xF100_0000, &[]).unwrap().unwrap();
    assert_eq!(resp.as_bytes(), expected_val.as_bytes());
}
