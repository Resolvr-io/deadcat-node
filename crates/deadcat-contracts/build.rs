use std::{process::Command, str};

const EXPECTED_SMPLX_VERSION: &str = "0.0.9";

fn main() {
    println!("cargo::rerun-if-changed=simplicityhl");
    println!("cargo::rerun-if-changed=Simplex.toml");

    let version = Command::new("simplex")
        .arg("--version")
        .output()
        .unwrap_or_else(|error| {
            panic!("failed to invoke `simplex` ({error}); build inside `nix develop .#default`")
        });
    assert!(
        version.status.success(),
        "`simplex --version` failed: {}",
        String::from_utf8_lossy(&version.stderr)
    );

    let version_output = str::from_utf8(&version.stdout)
        .unwrap_or_else(|error| panic!("`simplex --version` returned invalid UTF-8: {error}"));
    let mut version_lines = version_output.lines();
    let actual_version = match (version_lines.next(), version_lines.next()) {
        (Some(line), None) => line
            .strip_prefix("Simplex ")
            .unwrap_or_else(|| panic!("unexpected `simplex --version` output: {version_output:?}")),
        _ => panic!("unexpected `simplex --version` output: {version_output:?}"),
    };
    assert_eq!(
        actual_version, EXPECTED_SMPLX_VERSION,
        "simplex CLI/library skew: expected {EXPECTED_SMPLX_VERSION}, got {actual_version}"
    );

    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let status = Command::new("simplex")
        .arg("build")
        .current_dir(manifest_dir)
        .status()
        .expect("failed to run `simplex build`");
    assert!(status.success(), "`simplex build` exited with {status}");
}
