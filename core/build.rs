use std::io::Result;

fn main() -> Result<()> {
    prost_build::compile_protos(&["src/workspace/export/binexport2.proto"], &["src/"])?;

    let src = format!("{}/_.rs", std::env::var("OUT_DIR").unwrap());
    let dst = format!("{}/binexport2.rs", std::env::var("OUT_DIR").unwrap());

    std::fs::copy(src, dst).expect("Failed to copy file");

    Ok(())
}
