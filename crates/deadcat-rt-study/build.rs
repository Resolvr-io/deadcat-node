use std::process::Command;

const EXPECTED_SMPLX_VERSION: &str = "0.0.6";

fn main() {
    println!("cargo::rerun-if-changed=simplicityhl");
    println!("cargo::rerun-if-changed=Simplex.toml");

    let version = Command::new("simplex")
        .arg("--version")
        .output()
        .unwrap_or_else(|error| {
            panic!("failed to invoke `simplex` ({error}); build inside `nix develop .#default`")
        });
    assert!(version.status.success(), "`simplex --version` failed");
    let version = String::from_utf8_lossy(&version.stdout);
    assert!(
        version.contains(EXPECTED_SMPLX_VERSION),
        "simplex CLI/library skew: expected {EXPECTED_SMPLX_VERSION}, got {version:?}"
    );

    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let status = Command::new("simplex")
        .arg("build")
        .current_dir(manifest_dir)
        .status()
        .expect("failed to run `simplex build`");
    assert!(status.success(), "`simplex build` exited with {status}");
}
