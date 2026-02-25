// Licensed under the Apache-2.0 license

use anyhow::{bail, Result};
use std::fs;
use std::io::{self, Write};
use std::str::FromStr;

#[derive(Debug)]
struct ReleaseTag {
    component: String,
    major: u32,
    minor: u32,
    patch: u32,
}

impl FromStr for ReleaseTag {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() != 2 {
            bail!("Invalid tag format. Expected component-major.minor.patch (e.g., fmc-1.2.3)");
        }
        let component = parts[0].to_string();
        let version = parts[1];
        let version_parts: Vec<&str> = version.split('.').collect();
        if version_parts.len() != 3 {
            bail!("Invalid version format. Expected major.minor.patch (e.g., 1.2.3)");
        }
        let major: u32 = version_parts[0].parse()?;
        let minor: u32 = version_parts[1].parse()?;
        let patch: u32 = version_parts[2].parse()?;

        Ok(ReleaseTag {
            component,
            major,
            minor,
            patch,
        })
    }
}

fn verify_rom(tag: &ReleaseTag, version_rs: &str, common_rs: &str, readme: &str) -> Result<()> {
    let major = tag.major;
    let minor = tag.minor;
    let patch = tag.patch;

    if !version_rs.contains(&format!("pub const ROM_VERSION_MAJOR: u16 = {};", major)) ||
       !version_rs.contains(&format!("pub const ROM_VERSION_MINOR: u16 = {};", minor)) ||
       !version_rs.contains(&format!("pub const ROM_VERSION_PATCH: u16 = {};", patch)) {
        bail!("builder/src/version.rs does not have correct ROM version");
    }

    let rom_hex = ((major & 0x1F) << 11) | ((minor & 0x1F) << 6) | (patch & 0x3F);
    let expected_hex = format!("0x{:04x}", rom_hex);
    if !common_rs.contains(&expected_hex) {
        bail!("test/tests/fips_test_suite/common.rs does not contain expected ROM hex version {}", expected_hex);
    }

    if !readme.contains(&format!("v{}.{}", major, minor)) {
        bail!("rom/dev/README.md does not contain expected version v{}.{}", major, minor);
    }
    Ok(())
}

fn verify_fmc(tag: &ReleaseTag, version_rs: &str, common_rs: &str, toml: &str, readme: &str) -> Result<()> {
    let major = tag.major;
    let minor = tag.minor;
    let patch = tag.patch;

    if !version_rs.contains(&format!("pub const FMC_VERSION_MAJOR: u16 = {};", major)) ||
       !version_rs.contains(&format!("pub const FMC_VERSION_MINOR: u16 = {};", minor)) ||
       !version_rs.contains(&format!("pub const FMC_VERSION_PATCH: u16 = {};", patch)) {
        bail!("builder/src/version.rs does not have correct FMC version");
    }

    let fmc_hex = ((major & 0x1F) << 11) | ((minor & 0x1F) << 6) | (patch & 0x3F);
    let expected_hex = format!("0x{:04x}", fmc_hex);

    if !toml.contains(&format!("fmc_version = {}", expected_hex)) {
        bail!("builder/test_data/default_image_options.toml does not contain expected FMC hex version {}", expected_hex);
    }

    if !common_rs.contains(&expected_hex) {
        bail!("test/tests/fips_test_suite/common.rs does not contain expected FMC hex version {}", expected_hex);
    }

    if !readme.contains(&format!("v{}.{}", major, minor)) {
        bail!("fmc/README.md does not contain expected version v{}.{}", major, minor);
    }
    Ok(())
}

fn verify_fw(tag: &ReleaseTag, version_rs: &str, common_rs: &str, toml: &str, readme: &str) -> Result<()> {
    let major = tag.major;
    let minor = tag.minor;
    let patch = tag.patch;

    if !version_rs.contains(&format!("pub const RUNTIME_VERSION_MAJOR: u32 = {};", major)) ||
       !version_rs.contains(&format!("pub const RUNTIME_VERSION_MINOR: u32 = {};", minor)) ||
       !version_rs.contains(&format!("pub const RUNTIME_VERSION_PATCH: u32 = {};", patch)) {
        bail!("builder/src/version.rs does not have correct RUNTIME version");
    }

    let fw_hex = ((major & 0xFF) << 24) | ((minor & 0xFF) << 16) | (patch & 0xFFFF);
    
    if !toml.contains(&format!("app_version = 0x{:x}", fw_hex)) {
        bail!("builder/test_data/default_image_options.toml does not contain expected FW hex version 0x{:x}", fw_hex);
    }

    let common_rs_clean = common_rs.replace("_", "");
    if !common_rs_clean.contains(&format!("0x{:08x}", fw_hex)) {
        bail!("test/tests/fips_test_suite/common.rs does not contain expected FW hex version 0x{:08x}", fw_hex);
    }

    if !readme.contains(&format!("v{}.{}", major, minor)) {
        bail!("runtime/README.md does not contain expected version v{}.{}", major, minor);
    }
    Ok(())
}

pub(crate) fn release(tag_str: &str) -> Result<()> {
    let tag: ReleaseTag = tag_str.parse()?;

    println!("Verifying version for {} to be {}.{}.{}\n", tag.component, tag.major, tag.minor, tag.patch);

    let version_rs = fs::read_to_string("builder/src/version.rs")?;
    let common_rs = fs::read_to_string("test/tests/fips_test_suite/common.rs")?;
    let toml = fs::read_to_string("builder/test_data/default_image_options.toml")?;

    match tag.component.as_str() {
        "rom" => {
            let readme = fs::read_to_string("rom/dev/README.md")?;
            verify_rom(&tag, &version_rs, &common_rs, &readme)?;
        }
        "fmc" => {
            let readme = fs::read_to_string("fmc/README.md")?;
            verify_fmc(&tag, &version_rs, &common_rs, &toml, &readme)?;
        }
        "fw" => {
            let readme = fs::read_to_string("runtime/README.md")?;
            verify_fw(&tag, &version_rs, &common_rs, &toml, &readme)?;
        }
        _ => bail!("Unknown component '{}'. Expected 'rom', 'fmc', or 'fw'", tag.component),
    }

    println!("All version checks passed for {} {}.{}.{}!\n", tag.component, tag.major, tag.minor, tag.patch);

    println!("Caliptra Firmware Release Process");
    println!("=================================\n");

    println!("Step 1: Update Versions in caliptra-sw");
    println!("--------------------------------------");
    println!("- Update version numbers in:");
    println!("  - builder/src/version.rs");
    println!("  - builder/test_data/default_image_options.toml");
    println!("- Update expected values in:");
    println!("  - test/tests/fips_test_suite/common.rs");
    println!("- Update versions in the appropriate README files:");
    println!("  - rom/dev/README.md");
    println!("  - fmc/README.md");
    println!("  - runtime/README.md");
    println!("- Regenerate frozen sums (See `./ci.sh update_frozen_images`)");
    println!("- Push changes in a single commit titled: Updating <ROM, FMC, RT FW> version to x.y.z");
    pause();

    println!("Step 2: Perform Release on GitHub");
    println!("---------------------------------");
    println!("- Run the nightly release GitHub Action and wait for it to complete.");
    println!("- Update the existing GitHub release:");
    println!("  - Update the release title (e.g. ROM-1.2.3)");
    println!("  - Uncheck \"Set as a pre-release\"");
    println!("  - Check \"Set as the latest release\"");
    println!("  - Select \"Update release\"");
    pause();

    println!("Step 3: Tag the Release");
    println!("-----------------------");
    println!("- Create a new git tag corresponding to the released component:");
    println!("  - ROM: rom-x.y.z");
    println!("  - FMC: fmc-x.y.z");
    println!("  - Runtime Firmware: rt-x.y.z");
    println!("- Push the new git tag(s) to origin.");
    pause();

    println!("Step 4: Notify Users");
    println!("--------------------");
    println!("- Update version information on the Caliptra site.");
    println!("- Post an announcement on the Caliptra blog.");
    pause();

    println!("Release process complete!");
    Ok(())
}

fn pause() {
    print!("Press Enter to continue...");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    println!();
}
