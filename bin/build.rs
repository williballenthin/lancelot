use std::io::Result;
fn main() -> Result<()> {
    prost_build::compile_protos(&["src/binexport2.proto"], &["src/"])?;
    Ok(())
}
