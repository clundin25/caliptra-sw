// Licensed under the Apache-2.0 license

use caliptra_api::SocManager;
use caliptra_common::mailbox_api::{
    CommandId, MailboxReq, MailboxReqHeader, SignWithExportedReq, SignWithExportedResp,
};
use caliptra_hw_model::HwModel;
use caliptra_runtime::RtBootStatus;
use dpe::{
    commands::{Command, DeriveContextCmd, DeriveContextFlags},
    context::ContextHandle,
    response::Response,
    DPE_PROFILE,
};
use openssl::{bn::BigNum, ecdsa::EcdsaSig, x509::X509};
use zerocopy::{FromBytes, IntoBytes};

use crate::common::{execute_dpe_cmd, run_rt_test, DpeResult, RuntimeTestArgs, TEST_DIGEST};

#[test]
fn test_sign_with_exported_cdi() {
    let mut model = run_rt_test(RuntimeTestArgs::default());
    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let get_cert_chain_cmd = DeriveContextCmd {
        handle: ContextHandle::default(),
        data: [0; DPE_PROFILE.get_tci_size()],
        flags: DeriveContextFlags::EXPORT_CDI | DeriveContextFlags::CREATE_CERTIFICATE,
        tci_type: 0,
        target_locality: 0,
    };
    let resp = execute_dpe_cmd(
        &mut model,
        &mut Command::DeriveContext(&get_cert_chain_cmd),
        DpeResult::Success,
    );

    let resp = match resp {
        Some(Response::DeriveContextExportedCdi(resp)) => resp,
        _ => panic!("expected derive context resp!"),
    };

    let mut cmd = MailboxReq::SignWithExported(SignWithExportedReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi: resp.exported_cdi,
        digest: TEST_DIGEST,
    });
    cmd.populate_chksum().unwrap();

    let result = model.mailbox_execute(
        CommandId::SIGN_WITH_EXPORTED.into(),
        cmd.as_bytes().unwrap(),
    );

    let response = result.unwrap().unwrap();
    let response = SignWithExportedResp::ref_from_bytes(response.as_bytes()).unwrap();
    let r = &response.signature[..DPE_PROFILE.get_ecc_int_size() as usize];
    let s = &response.signature[r.len()..response.signature_size as usize];
    let sig = EcdsaSig::from_private_components(
        BigNum::from_slice(r).unwrap(),
        BigNum::from_slice(s)
        .unwrap(),
    )
    .unwrap();

    let x509 =
        X509::from_der(&resp.new_certificate[..resp.certificate_size.try_into().unwrap()]).unwrap();
    let ec_pub_key = x509.public_key().unwrap().ec_key().unwrap();
    assert!(sig.verify(&TEST_DIGEST, &ec_pub_key).unwrap());
}
