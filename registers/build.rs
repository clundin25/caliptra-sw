// Licensed under the Apache-2.0 license.

fn main() {
    println!("cargo::rustc-check-cfg=cfg(hw_rev_latest, hw_rev_2_1, hw_rev_2_0)");
    let rev = std::env::var("CALIPTRA_HW_REV").unwrap_or_else(|_| "latest".to_string());
    match rev.as_str() {
        "latest" | "rev-latest" => println!("cargo:rustc-cfg=hw_rev_latest"),
        "2.1" | "rev-2_1" => println!("cargo:rustc-cfg=hw_rev_2_1"),
        "2.0" | "rev-2_0" => println!("cargo:rustc-cfg=hw_rev_2_0"),
        _ => panic!("Unsupported CALIPTRA_HW_REV: {}", rev),
    }
    println!("cargo:rerun-if-env-changed=CALIPTRA_HW_REV");
}
