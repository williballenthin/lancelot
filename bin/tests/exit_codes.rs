//! the CLI tools must exit nonzero on failure,
//! so that scripts and pipelines can detect errors.
//! see https://github.com/williballenthin/lancelot/issues/247
use std::process::Command;

/// path to a file that does not exist,
/// so tools fail inside their `_main` (not during argument parsing).
const MISSING: &str = "./tests/data/definitely-does-not-exist.exe";

/// path to a small, valid PE within this repository.
fn nop_exe() -> String {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("..");
    path.push("core");
    path.push("resources");
    path.push("test");
    path.push("nop.exe");
    path.to_str().unwrap().to_string()
}

fn run(bin: &str, args: &[&str]) -> std::process::Output {
    Command::new(bin)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn {bin}: {e}"))
}

fn assert_failure(bin: &str, args: &[&str]) {
    let output = run(bin, args);
    assert!(
        !output.status.success(),
        "expected nonzero exit: {bin} {args:?}\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_success(bin: &str, args: &[&str]) {
    let output = run(bin, args);
    assert!(
        output.status.success(),
        "expected zero exit: {bin} {args:?}\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn lancelot_missing_input() {
    assert_failure(env!("CARGO_BIN_EXE_lancelot"), &["functions", MISSING]);
}

#[test]
fn lancelot_no_subcommand() {
    assert_failure(env!("CARGO_BIN_EXE_lancelot"), &[]);
}

#[test]
fn lancelot_ok() {
    assert_success(env!("CARGO_BIN_EXE_lancelot"), &["-q", "functions", &nop_exe()]);
}

#[test]
fn be2_missing_input() {
    assert_failure(env!("CARGO_BIN_EXE_be2"), &[MISSING]);
}

#[test]
fn be2_ok() {
    let output = run(env!("CARGO_BIN_EXE_be2"), &["-q", &nop_exe()]);
    assert!(output.status.success());
    // a successful run writes the BinExport2 document to stdout.
    assert!(!output.stdout.is_empty());
}

#[test]
fn jh_missing_input() {
    assert_failure(
        env!("CARGO_BIN_EXE_jh"),
        &["i686-pc-windows-msvc", "msvc", "libtest", "1.0", "release", MISSING],
    );
}

#[test]
fn jh_unrecognized_format() {
    // a file that exists but is neither PE, COFF, nor archive.
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    assert_failure(
        env!("CARGO_BIN_EXE_jh"),
        &[
            "i686-pc-windows-msvc",
            "msvc",
            "libtest",
            "1.0",
            "release",
            path.to_str().unwrap(),
        ],
    );
}

#[test]
fn match_flirt_missing_input() {
    assert_failure(env!("CARGO_BIN_EXE_match_flirt"), &[MISSING, "sigs.sig"]);
}
