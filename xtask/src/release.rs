// Licensed under the Apache-2.0 license

use anyhow::{bail, Result};
use log::info;
use std::fs;
use std::io;
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

struct ReleaseRelevantFiles {
    version_rs: String,
    common_rs: String,
    toml: String,
    readme: String,
}

fn verify_rom(tag: &ReleaseTag, files: &ReleaseRelevantFiles) -> Result<()> {
    let major = tag.major;
    let minor = tag.minor;
    let patch = tag.patch;

    if !files.version_rs.contains(&format!("pub const ROM_VERSION_MAJOR: u16 = {};", major)) ||
       !files.version_rs.contains(&format!("pub const ROM_VERSION_MINOR: u16 = {};", minor)) ||
       !files.version_rs.contains(&format!("pub const ROM_VERSION_PATCH: u16 = {};", patch)) {
        bail!("builder/src/version.rs does not have correct ROM version");
    }

    let rom_hex = ((major & 0x1F) << 11) | ((minor & 0x1F) << 6) | (patch & 0x3F);
    let expected_hex = format!("0x{:04x}", rom_hex);
    if !files.common_rs.contains(&expected_hex) {
        bail!("test/tests/fips_test_suite/common.rs does not contain expected ROM hex version {}", expected_hex);
    }

    if !files.readme.contains(&format!("v{}.{}", major, minor)) {
        bail!("rom/dev/README.md does not contain expected version v{}.{}", major, minor);
    }
    Ok(())
}

fn verify_fmc(tag: &ReleaseTag, files: &ReleaseRelevantFiles) -> Result<()> {
    let major = tag.major;
    let minor = tag.minor;
    let patch = tag.patch;

    if !files.version_rs.contains(&format!("pub const FMC_VERSION_MAJOR: u16 = {};", major)) ||
       !files.version_rs.contains(&format!("pub const FMC_VERSION_MINOR: u16 = {};", minor)) ||
       !files.version_rs.contains(&format!("pub const FMC_VERSION_PATCH: u16 = {};", patch)) {
        bail!("builder/src/version.rs does not have correct FMC version");
    }

    let fmc_hex = ((major & 0x1F) << 11) | ((minor & 0x1F) << 6) | (patch & 0x3F);
    let expected_hex = format!("0x{:04x}", fmc_hex);

    if !files.toml.contains(&format!("fmc_version = {}", expected_hex)) {
        bail!("builder/test_data/default_image_options.toml does not contain expected FMC hex version {}", expected_hex);
    }

    if !files.common_rs.contains(&expected_hex) {
        bail!("test/tests/fips_test_suite/common.rs does not contain expected FMC hex version {}", expected_hex);
    }

    if !files.readme.contains(&format!("v{}.{}", major, minor)) {
        bail!("fmc/README.md does not contain expected version v{}.{}", major, minor);
    }
    Ok(())
}

fn verify_fw(tag: &ReleaseTag, files: &ReleaseRelevantFiles) -> Result<()> {
    let major = tag.major;
    let minor = tag.minor;
    let patch = tag.patch;

    if !files.version_rs.contains(&format!("pub const RUNTIME_VERSION_MAJOR: u32 = {};", major)) ||
       !files.version_rs.contains(&format!("pub const RUNTIME_VERSION_MINOR: u32 = {};", minor)) ||
       !files.version_rs.contains(&format!("pub const RUNTIME_VERSION_PATCH: u32 = {};", patch)) {
        bail!("builder/src/version.rs does not have correct RUNTIME version");
    }

    let fw_hex = ((major & 0xFF) << 24) | ((minor & 0xFF) << 16) | (patch & 0xFFFF);
    
    if !files.toml.contains(&format!("app_version = 0x{:x}", fw_hex)) {
        bail!("builder/test_data/default_image_options.toml does not contain expected FW hex version 0x{:x}", fw_hex);
    }

    let common_rs_clean = files.common_rs.replace("_", "");
    if !common_rs_clean.contains(&format!("0x{:08x}", fw_hex)) {
        bail!("test/tests/fips_test_suite/common.rs does not contain expected FW hex version 0x{:08x}", fw_hex);
    }

    if !files.readme.contains(&format!("v{}.{}", major, minor)) {
        bail!("runtime/README.md does not contain expected version v{}.{}", major, minor);
    }
    Ok(())
}

pub(crate) fn check(tag_str: &str) -> Result<()> {
    let tag: ReleaseTag = tag_str.parse()?;

    info!("Verifying version for {} to be {}.{}.{}\n", tag.component, tag.major, tag.minor, tag.patch);

    let version_rs = fs::read_to_string("builder/src/version.rs")?;
    let common_rs = fs::read_to_string("test/tests/fips_test_suite/common.rs")?;
    let toml = fs::read_to_string("builder/test_data/default_image_options.toml")?;

    match tag.component.as_str() {
        "rom" => {
            let readme = fs::read_to_string("rom/dev/README.md")?;
            let files = ReleaseRelevantFiles { version_rs, common_rs, toml, readme };
            verify_rom(&tag, &files)?;
        }
        "fmc" => {
            let readme = fs::read_to_string("fmc/README.md")?;
            let files = ReleaseRelevantFiles { version_rs, common_rs, toml, readme };
            verify_fmc(&tag, &files)?;
        }
        "fw" => {
            let readme = fs::read_to_string("runtime/README.md")?;
            let files = ReleaseRelevantFiles { version_rs, common_rs, toml, readme };
            verify_fw(&tag, &files)?;
        }
        _ => bail!("Unknown component '{}'. Expected 'rom', 'fmc', or 'fw'", tag.component),
    }

    info!("All version checks passed for {} {}.{}.{}!\n", tag.component, tag.major, tag.minor, tag.patch);

    info!("Caliptra Firmware Release Process");
    info!("=================================\n");

    info!("Step 1: Update Versions in caliptra-sw");
    info!("--------------------------------------");
    info!("- Update version numbers in:");
    info!("  - builder/src/version.rs");
    info!("  - builder/test_data/default_image_options.toml");
    info!("- Update expected values in:");
    info!("  - test/tests/fips_test_suite/common.rs");
    info!("- Update versions in the appropriate README files:");
    info!("  - rom/dev/README.md");
    info!("  - fmc/README.md");
    info!("  - runtime/README.md");
    info!("- Regenerate frozen sums (See `./ci.sh update_frozen_images`)");
    info!("- Push changes in a single commit titled: Updating <ROM, FMC, RT FW> version to x.y.z");
    pause();

    info!("Step 2: Perform Release on GitHub");
    info!("---------------------------------");
    info!("- Run the nightly release GitHub Action and wait for it to complete.");
    info!("- Update the existing GitHub release:");
    info!("  - Update the release title (e.g. ROM-1.2.3)");
    info!("  - Uncheck \"Set as a pre-release\"");
    info!("  - Check \"Set as the latest release\"");
    info!("  - Select \"Update release\"");
    pause();

    info!("Step 3: Tag the Release");
    info!("-----------------------");
    info!("- Create a new git tag corresponding to the released component:");
    info!("  - ROM: rom-x.y.z");
    info!("  - FMC: fmc-x.y.z");
    info!("  - Runtime Firmware: rt-x.y.z");
    info!("- Push the new git tag(s) to origin.");
    pause();

    info!("Step 4: Notify Users");
    info!("--------------------");
    info!("- Update version information on the Caliptra site.");
    info!("- Post an announcement on the Caliptra blog.");
    pause();

    info!("Release process complete!");
    Ok(())
}

pub(crate) fn deploy(tag_str: &str) -> Result<()> {
    check(tag_str)?;
    
    info!("Creating git tag: {}", tag_str);
    let tag_status = std::process::Command::new("git")
        .args(["tag", tag_str])
        .status()?;

    if !tag_status.success() {
        bail!("Failed to create git tag '{}'", tag_str);
    }

    info!("Pushing git tag to origin: {}", tag_str);
    let push_status = std::process::Command::new("git")
        .args(["push", "origin", tag_str])
        .status()?;

    if !push_status.success() {
        bail!("Failed to push git tag '{}' to origin", tag_str);
    }

    info!("Successfully deployed tag {}", tag_str);
    Ok(())
}

fn pause() {
    info!("Press Enter to continue...");
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
}
