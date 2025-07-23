// Licensed under the Apache-2.0 license

use caliptra_api::SocManager;
use caliptra_hw_model::HwModel;
use caliptra_runtime::RtBootStatus;

use crate::common::{run_rt_test, RuntimeTestArgs};

#[test]
fn test_supports_ocp_lock() {
    let mut model = run_rt_test(RuntimeTestArgs::default());
    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });
}
