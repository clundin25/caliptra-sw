// Licensed under the Apache-2.0 license

fn main() {
    cfg_if::cfg_if! {
        if #[cfg(not(feature = "std"))] {
            use std::env;
            use std::fs;
            use std::path::PathBuf;
            use caliptra_gen_linker_scripts::gen_memory_x;

            let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

            cfg_if::cfg_if! {
                if #[cfg(feature = "fmc")] {
                    fs::write(out_dir.join("memory.x"),gen_memory_x(caliptra_common::FMC_ORG, caliptra_common::FMC_SIZE)
                    .as_bytes())
                    .expect("Unable to generate memory.x");
                } else {
                    fs::write(out_dir.join("memory.x"),gen_memory_x(caliptra_common::RUNTIME_ORG, caliptra_common::RUNTIME_SIZE)
                    .as_bytes())
                    .expect("Unable to generate memory.x");
                }
            }

            fs::write(out_dir.join("link.x"), include_bytes!("src/link.x")).unwrap();

            let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

            println!("cargo:rustc-link-search={}", out_dir.display());

            println!("cargo:rerun-if-changed=memory.x");
            println!("cargo:rustc-link-arg=-Tmemory.x");

            println!("cargo:rerun-if-changed=link.x");
            println!("cargo:rustc-link-arg=-Tlink.x");
            println!("cargo:rerun-if-changed=build.rs");
        }
    }
}
