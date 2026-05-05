// Licensed under the Apache-2.0 license

use std::{env, error::Error, io, path::Path, process::Command};

use anyhow::anyhow;
use caliptra_builder::{elf_size, firmware, FwId};
use size_history::{
    ArtifactBuilder, Cache, FsCache, GitHubStepSummary, GithubActionCache, HtmlTableReport,
    OutputDestination, SizeHistory, Stdout,
};

const CACHE_FORMAT_VERSION: &str = "v4";

pub(crate) fn size_history() -> Result<(), anyhow::Error> {
    let cache = create_cache().map_err(|e| anyhow::anyhow!("{}", e))?;
    let reporter = HtmlTableReport::new("https://github.com/chipsalliance/caliptra-sw");
    let output: Box<dyn OutputDestination> = if env::var("GITHUB_STEP_SUMMARY").is_ok() {
        Box::new(GitHubStepSummary)
    } else {
        Box::new(Stdout)
    };

    SizeHistory::new(reporter, output, cache)
        .worktree_path("/tmp/caliptra-size-history-wt")
        .cache_version(CACHE_FORMAT_VERSION)
        .with_pr_squashing(true)
        .add_builder(Box::new(CaliptraFirmwareBuilder::new(
            "ROM prod size",
            firmware::ROM,
        )))
        .add_builder(Box::new(CaliptraFirmwareBuilder::new(
            "ROM with-uart size",
            firmware::ROM_WITH_UART,
        )))
        .add_builder(Box::new(CaliptraFirmwareBuilder::new(
            "FMC size",
            firmware::FMC_WITH_UART,
        )))
        .add_builder(Box::new(CaliptraFirmwareBuilder::new(
            "App size",
            firmware::APP_WITH_UART,
        )))
        .add_builder(Box::new(CaliptraFirmwareBuilder::new(
            "App with OCP LOCK size",
            firmware::APP_WITH_UART_OCP_LOCK,
        )))
        .run()
        .map_err(|e| anyhow::anyhow!("{}", e))
}

fn create_cache() -> Result<Box<dyn Cache>, Box<dyn Error>> {
    Ok(GithubActionCache::new().map(box_cache).or_else(|e| {
        let fs_cache_path = "/tmp/caliptra-size-cache";
        println!(
            "Unable to create github action cache: {e}; using fs-cache instead at {fs_cache_path}"
        );
        FsCache::new(fs_cache_path.into()).map(box_cache)
    })?)
}

fn box_cache(val: impl Cache + 'static) -> Box<dyn Cache> {
    Box::new(val)
}

/// Builds Caliptra firmware using caliptra_builder and measures ELF size.
struct CaliptraFirmwareBuilder {
    name: String,
    fwid: FwId<'static>,
}

impl CaliptraFirmwareBuilder {
    fn new(name: impl Into<String>, fwid: FwId<'static>) -> Self {
        Self {
            name: name.into(),
            fwid,
        }
    }

    fn build_elf(&self, workspace: &Path) -> io::Result<u64> {
        let elf_bytes = caliptra_builder::build_firmware_elf_uncached(Some(workspace), &self.fwid)?;
        elf_size(&elf_bytes)
    }
}

impl ArtifactBuilder for CaliptraFirmwareBuilder {
    fn name(&self) -> &str {
        &self.name
    }

    fn build_and_measure(&self, workspace: &Path) -> Option<u64> {
        match self.build_elf(workspace) {
            Ok(size) => Some(size),
            Err(err) => {
                log::error!("Error building {}: {err}", self.name);
                None
            }
        }
    }
}

pub fn bitstream_download(manifest_path: String) -> Result<(), anyhow::Error> {
    let out_path = bitstream_downloader::download_bitstream(Path::new(manifest_path.as_str()))
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    let out = out_path
        .to_str()
        .ok_or_else(|| anyhow!("invalid output file path"))?;
    log::info!("Download path bitstream: {}", out);
    Ok(())
}

pub fn build() -> Result<(), anyhow::Error> {
    let mut cmd = Command::new("cargo");
    cmd.arg("--config")
       .arg("target.'cfg(all())'.rustflags = [\"-Dwarnings\"]")
       .arg("build")
       .arg("--locked");
    crate::util::run_command(&mut cmd)?;

    let mut cmd = Command::new("cargo");
    cmd.arg("build")
       .arg("--locked")
       .arg("--target")
       .arg("riscv32imc-unknown-none-elf")
       .arg("--features=riscv")
       .arg("--profile=firmware");
    crate::util::run_command(&mut cmd)?;

    let mut cmd = Command::new("cargo");
    cmd.arg("build")
       .arg("--locked")
       .arg("--target")
       .arg("riscv32imc-unknown-none-elf")
       .arg("--profile=firmware")
       .arg("--no-default-features")
       .arg("--features=riscv,cfi")
       .arg("--bin=caliptra-fmc")
       .current_dir("fmc");
    crate::util::run_command(&mut cmd)?;

    let mut cmd = Command::new("cargo");
    cmd.arg("build")
       .arg("--locked")
       .arg("--target")
       .arg("riscv32imc-unknown-none-elf")
       .arg("--profile=firmware")
       .arg("--no-default-features")
       .arg("--features=cfi")
       .arg("--bin=caliptra-runtime")
       .current_dir("runtime");
    crate::util::run_command(&mut cmd)?;

    let mut cmd = Command::new("cargo");
    cmd.arg("build")
       .arg("--locked")
       .arg("--target")
       .arg("riscv32imc-unknown-none-elf")
       .arg("--profile=firmware")
       .arg("--no-default-features")
       .arg("--features=cfi")
       .arg("--bin=caliptra-rom")
       .current_dir("rom/dev");
    crate::util::run_command(&mut cmd)?;

    for proj in &[
        "caliptra-auth-manifest-app",
        "caliptra-builder",
        "caliptra-image-crypto",
        "caliptra-image-app",
    ] {
        let mut cmd = Command::new("cargo");
        cmd.arg("build")
           .arg("-p")
           .arg(proj)
           .arg("--locked")
           .arg("--no-default-features")
           .arg("--features=openssl");
        crate::util::run_command(&mut cmd)?;
    }

    for proj in &[
        "caliptra-auth-manifest-app",
        "caliptra-builder",
        "caliptra-image-crypto",
        "caliptra-image-app",
    ] {
        let mut cmd = Command::new("cargo");
        cmd.arg("build")
           .arg("-p")
           .arg(proj)
           .arg("--locked")
           .arg("--no-default-features")
           .arg("--features=rustcrypto");
        crate::util::run_command(&mut cmd)?;
    }

    for feature in &["fpga_realtime", "fpga_subsystem", "itrng", "coverage"] {
        let mut cmd = Command::new("cargo");
        cmd.arg("build")
           .arg("--locked")
           .arg("--features")
           .arg(feature);
        crate::util::run_command(&mut cmd)?;
    }

    let mut cmd = Command::new("cargo");
    cmd.arg("run")
       .arg("-p")
       .arg("caliptra-x509-gen")
       .arg("--locked");
    crate::util::run_command(&mut cmd)?;

    let mut cmd = Command::new("git");
    cmd.arg("diff")
       .arg("--exit-code")
       .arg("--")
       .arg("x509/build/")
       .arg("x509/src/");
    crate::util::run_command(&mut cmd)?;

    Ok(())
}

pub fn test_unit() -> Result<(), anyhow::Error> {
    let mut cmd = Command::new("cargo");
    cmd.arg("--config")
       .arg("target.'cfg(all())'.rustflags = [\"-Dwarnings\"]")
       .arg("test")
       .arg("--locked")
       .env("CPTRA_COVERAGE_PATH", "/tmp");
    crate::util::run_command(&mut cmd)?;

    let mut cmd = Command::new("cargo");
    cmd.arg("--config")
       .arg("target.'cfg(all())'.rustflags = [\"-Dwarnings\"]")
       .arg("run")
       .arg("--manifest-path")
       .arg("./coverage/Cargo.toml")
       .env("CPTRA_COVERAGE_PATH", "/tmp");
    crate::util::run_command(&mut cmd)?;

    let mut cmd = Command::new("cargo");
    cmd.arg("--config")
       .arg("target.'cfg(all())'.rustflags = [\"-Dwarnings\"]")
       .arg("test")
       .arg("-p")
       .arg("caliptra-runtime")
       .arg("--features")
       .arg("ocp-lock")
       .arg("test_ocp_lock")
       .arg("--locked")
       .env("CPTRA_COVERAGE_PATH", "/tmp");
    crate::util::run_command(&mut cmd)?;

    Ok(())
}

pub fn test_compliance() -> Result<(), anyhow::Error> {
    if !Path::new("/tmp/riscv-arch-test").exists() {
        let mut cmd = Command::new("git");
        cmd.arg("clone")
           .arg("--depth")
           .arg("1")
           .arg("--branch")
           .arg("old-framework-2.x")
           .arg("https://github.com/riscv-non-isa/riscv-arch-test")
           .current_dir("/tmp");
        crate::util::run_command(&mut cmd)?;
    }

    let mut cmd = Command::new("cargo");
    cmd.arg("--config")
       .arg("target.'cfg(all())'.rustflags = [\"-Dwarnings\"]")
       .arg("run")
       .arg("--locked")
       .arg("-p")
       .arg("compliance-test")
       .arg("--")
       .arg("--test_root_path")
       .arg("/tmp/riscv-arch-test");
    crate::util::run_command(&mut cmd)?;

    Ok(())
}

pub fn test_rom() -> Result<(), anyhow::Error> {
    let mut cmd = Command::new("cargo");
    cmd.arg("build").arg("--locked").arg("--target").arg("riscv32imc-unknown-none-elf").arg("--features=riscv").arg("--profile=firmware");
    crate::util::run_command(&mut cmd)?;

    let mut cmd = Command::new("cargo");
    cmd.arg("build").arg("--locked").arg("--target").arg("riscv32imc-unknown-none-elf").arg("--profile=firmware").arg("--no-default-features").arg("--features=riscv,cfi").arg("--bin=caliptra-fmc").current_dir("fmc");
    crate::util::run_command(&mut cmd)?;

    let mut cmd = Command::new("cargo");
    cmd.arg("build").arg("--locked").arg("--target").arg("riscv32imc-unknown-none-elf").arg("--profile=firmware").arg("--no-default-features").arg("--features=cfi").arg("--bin=caliptra-runtime").current_dir("runtime");
    crate::util::run_command(&mut cmd)?;

    let mut cmd = Command::new("cargo");
    cmd.arg("build").arg("--locked").arg("--target").arg("riscv32imc-unknown-none-elf").arg("--profile=firmware").arg("--no-default-features").arg("--features=cfi").arg("--bin=caliptra-rom").current_dir("rom/dev");
    crate::util::run_command(&mut cmd)?;

    let make_vars = [
        ("unprovisioned", "run"),
        ("manufacturing", "run"),
        ("production", "run"),
        ("unprovisioned", "run-active"),
        ("manufacturing", "run-active"),
        ("production", "run-active"),
    ];

    for (lifecycle, target) in &make_vars {
        let mut cmd = Command::new("make");
        cmd.arg(target)
           .env("DEVICE_LIFECYCLE", lifecycle)
           .current_dir("rom/dev");
        crate::util::run_command(&mut cmd)?;
    }

    Ok(())
}

pub fn test_integration() -> Result<(), anyhow::Error> {
    let mut cmd = Command::new("make");
    cmd.arg("run")
       .current_dir("hw-model/c-binding/examples");
    crate::util::run_command(&mut cmd)?;

    let mut cmd = Command::new("make");
    cmd.current_dir("libcaliptra/examples/hwmodel");
    crate::util::run_command(&mut cmd)?;

    let mut cmd = Command::new("./hwmodel");
    cmd.current_dir("libcaliptra/examples/hwmodel");
    crate::util::run_command(&mut cmd)?;

    let mut cmd = Command::new("make");
    cmd.arg("run")
       .current_dir("test/dpe_verification");
    crate::util::run_command(&mut cmd)?;

    Ok(())
}
