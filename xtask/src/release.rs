// Licensed under the Apache-2.0 license

use anyhow::Result;
use std::io::{self, Write};

pub(crate) fn release() -> Result<()> {
    println!("Caliptra Firmware Release Process");
    println!("=================================
");

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
    print!("
Press Enter to continue...");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    println!();
}
