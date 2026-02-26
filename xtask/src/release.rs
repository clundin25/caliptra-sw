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

fn verify_common(
    tag: &ReleaseTag,
    files: &ReleaseRelevantFiles,
    version_prefix: &str,
    version_type: &str,
    readme_path: &str,
) -> Result<()> {
    let major = tag.major;
    let minor = tag.minor;
    let patch = tag.patch;

    if !files.version_rs.contains(&format!("pub const {}_VERSION_MAJOR: {} = {};", version_prefix, version_type, major)) ||
       !files.version_rs.contains(&format!("pub const {}_VERSION_MINOR: {} = {};", version_prefix, version_type, minor)) ||
       !files.version_rs.contains(&format!("pub const {}_VERSION_PATCH: {} = {};", version_prefix, version_type, patch)) {
        bail!("builder/src/version.rs does not have correct {} version", version_prefix);
    }

    if !files.readme.contains(&format!("v{}.{}", major, minor)) {
        bail!("{} does not contain expected version v{}.{}", readme_path, major, minor);
    }
    Ok(())
}

fn verify_rom(tag: &ReleaseTag, files: &ReleaseRelevantFiles) -> Result<()> {
    verify_common(tag, files, "ROM", "u16", "rom/dev/README.md")?;

    let major = tag.major;
    let minor = tag.minor;
    let patch = tag.patch;

    let rom_hex = ((major & 0x1F) << 11) | ((minor & 0x1F) << 6) | (patch & 0x3F);
    let expected_hex = format!("0x{:04x}", rom_hex);
    if !files.common_rs.contains(&expected_hex) {
        bail!("test/tests/fips_test_suite/common.rs does not contain expected ROM hex version {}", expected_hex);
    }

    Ok(())
}

fn verify_fmc(tag: &ReleaseTag, files: &ReleaseRelevantFiles) -> Result<()> {
    verify_common(tag, files, "FMC", "u16", "fmc/README.md")?;

    let major = tag.major;
    let minor = tag.minor;
    let patch = tag.patch;

    let fmc_hex = ((major & 0x1F) << 11) | ((minor & 0x1F) << 6) | (patch & 0x3F);
    let expected_hex = format!("0x{:04x}", fmc_hex);

    if !files.toml.contains(&format!("fmc_version = {}", expected_hex)) {
        bail!("builder/test_data/default_image_options.toml does not contain expected FMC hex version {}", expected_hex);
    }

    if !files.common_rs.contains(&expected_hex) {
        bail!("test/tests/fips_test_suite/common.rs does not contain expected FMC hex version {}", expected_hex);
    }

    Ok(())
}

fn verify_fw(tag: &ReleaseTag, files: &ReleaseRelevantFiles) -> Result<()> {
    verify_common(tag, files, "RUNTIME", "u32", "runtime/README.md")?;

    let major = tag.major;
    let minor = tag.minor;
    let patch = tag.patch;

    let fw_hex = ((major & 0xFF) << 24) | ((minor & 0xFF) << 16) | (patch & 0xFFFF);
    
    if !files.toml.contains(&format!("app_version = 0x{:x}", fw_hex)) {
        bail!("builder/test_data/default_image_options.toml does not contain expected FW hex version 0x{:x}", fw_hex);
    }

    let common_rs_clean = files.common_rs.replace("_", "");
    if !common_rs_clean.contains(&format!("0x{:08x}", fw_hex)) {
        bail!("test/tests/fips_test_suite/common.rs does not contain expected FW hex version 0x{:08x}", fw_hex);
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

    crate::update_frozen_images::update_frozen_images()?;

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

#[derive(serde::Deserialize, Debug)]
struct WorkflowRuns {
    workflow_runs: Vec<WorkflowRun>,
}

#[derive(serde::Deserialize, Debug)]
struct WorkflowRun {
    conclusion: Option<String>,
}

struct ReleaseMetadata {
    crab: octocrab::Octocrab,
    owner: String,
    repo: String,
    head_commit: String,
    tag_str: String,
    component: String,
    version_str: String,
}

async fn check_nightly_workflow(meta: &ReleaseMetadata) -> Result<()> {
    let url = format!("/repos/{}/{}/actions/workflows/nightly-release.yml/runs?head_sha={}", meta.owner, meta.repo, meta.head_commit);
    let runs: WorkflowRuns = meta.crab.get(url, None::<&()>).await?;

    let run = runs.workflow_runs.into_iter().next().ok_or_else(|| anyhow::anyhow!("No nightly workflow run found for commit {}", meta.head_commit))?;
    
    let conclusion = run.conclusion.unwrap_or_else(|| "in_progress".to_string());
    if conclusion != "success" {
        bail!("Nightly workflow for commit {} did not succeed (status: '{}'). Cannot deploy.", meta.head_commit, conclusion);
    }
    Ok(())
}

async fn create_github_release(meta: &ReleaseMetadata) -> Result<()> {
    info!("Creating GitHub release for tag {}...", meta.tag_str);
    
    let release_name = format!("{}-{}", meta.component.to_uppercase(), meta.version_str);
    
    let release_body = format!("Release {}", release_name);
    // octocrab exposes repos().releases().create()
    let release = meta.crab.repos(&meta.owner, &meta.repo)
        .releases()
        .create(&meta.tag_str)
        .name(&release_name)
        .body(&release_body)
        .draft(false)
        .prerelease(false)
        .make_latest(octocrab::repos::releases::MakeLatest::True)
        .send()
        .await?;

    info!("Successfully created GitHub release: {}", release.html_url);
    Ok(())
}

pub(crate) fn deploy(tag_str: &str) -> Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    rt.block_on(deploy_async(tag_str))
}

async fn deploy_async(tag_str: &str) -> Result<()> {
    let tag: ReleaseTag = tag_str.parse()?;
    
    let head_output = std::process::Command::new("git").args(["rev-parse", "HEAD"]).output()?;
    let head_commit = String::from_utf8_lossy(&head_output.stdout).trim().to_string();

    info!("Checking if nightly release workflow passed for commit {}...", head_commit);
    
    let token = std::env::var("GH_TOKEN").or_else(|_| std::env::var("GITHUB_TOKEN")).unwrap_or_default();
    let mut builder = octocrab::Octocrab::builder();
    if !token.is_empty() {
        builder = builder.personal_token(token);
    }
    let crab = builder.build()?;

    let output = std::process::Command::new("git").args(["remote", "get-url", "origin"]).output()?;
    let url = String::from_utf8_lossy(&output.stdout).trim().to_string();
    
    let (owner, repo) = if url.contains("github.com") {
        let path = url.split("github.com").last().unwrap().trim_start_matches(&[':', '/'][..]).trim_end_matches(".git");
        let parts: Vec<&str> = path.split('/').collect();
        if parts.len() == 2 {
            (parts[0].to_string(), parts[1].to_string())
        } else {
            ("chipsalliance".to_string(), "caliptra-sw".to_string())
        }
    } else {
        ("chipsalliance".to_string(), "caliptra-sw".to_string())
    };

    let version_str = format!("{}.{}.{}", tag.major, tag.minor, tag.patch);

    let meta = ReleaseMetadata {
        crab,
        owner,
        repo,
        head_commit,
        tag_str: tag_str.to_string(),
        component: tag.component.clone(),
        version_str,
    };
    
    check_nightly_workflow(&meta).await?;

    info!("Nightly workflow passed! Proceeding with deployment.");

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
    
    create_github_release(&meta).await?;

    Ok(())
}

fn pause() {
    info!("Press Enter to continue...");
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
}
