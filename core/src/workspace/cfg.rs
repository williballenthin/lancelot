use std::path::{Path, PathBuf};

use anyhow::Result;

use lancelot_flirt::{FlirtSignature, FlirtSignatureSet};

pub trait Configuration {
    fn get_sigs(&self) -> Result<FlirtSignatureSet>;
}

// dummy configuration with only empty values.
pub struct EmptyConfiguration {}

impl Configuration for EmptyConfiguration {
    fn get_sigs(&self) -> Result<FlirtSignatureSet> {
        Ok(FlirtSignatureSet::with_signatures(vec![]))
    }
}

pub fn empty() -> Box<dyn Configuration> {
    Box::new(EmptyConfiguration {})
}

/// Directory that contains:
///   - sigs/  FLIRT signatures, ending with .sig, .pat, .sig.gz, .pat.gz
pub struct FileSystemConfiguration {
    path: PathBuf,
}

impl FileSystemConfiguration {
    pub fn from_path(path: &Path) -> FileSystemConfiguration {
        FileSystemConfiguration {
            path: path.to_path_buf(),
        }
    }
}

impl Configuration for FileSystemConfiguration {
    fn get_sigs(&self) -> Result<FlirtSignatureSet> {
        let mut sigs: Vec<FlirtSignature> = Default::default();

        let mut path = self.path.clone();
        path.push("sigs");

        for path in path.read_dir()? {
            if let Ok(entry) = path {
                if let Ok(filename) = entry.file_name().into_string() {
                    if filename.ends_with(".sig") {
                        let buf = std::fs::read(entry.path())?;
                        sigs.extend(lancelot_flirt::sig::parse(&buf)?);
                    } else if filename.ends_with(".pat") {
                        let buf = String::from_utf8(std::fs::read(entry.path())?)?;
                        sigs.extend(lancelot_flirt::pat::parse(&buf)?);
                    }
                }
            }
        }

        Ok(FlirtSignatureSet::with_signatures(sigs))
    }
}
