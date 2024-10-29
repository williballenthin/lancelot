use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::VA;
use lancelot_flirt::{FlirtSignature, FlirtSignatureSet};

pub trait Configuration: Send {
    fn get_sigs(&self) -> Result<FlirtSignatureSet>;
    fn get_function_hints(&self) -> Result<Vec<VA>>;
    fn clone(&self) -> Box<dyn Configuration>;
}

// dummy configuration with only empty values.
pub struct EmptyConfiguration {}

impl Configuration for EmptyConfiguration {
    fn get_sigs(&self) -> Result<FlirtSignatureSet> {
        Ok(FlirtSignatureSet::with_signatures(vec![]))
    }

    fn get_function_hints(&self) -> Result<Vec<VA>> {
        Ok(vec![])
    }

    fn clone(&self) -> Box<dyn Configuration> {
        Box::new(EmptyConfiguration {})
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

        for entry in path.read_dir()?.flatten() {
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

        Ok(FlirtSignatureSet::with_signatures(sigs))
    }

    // not supported at this time
    // its probably ok to make this return an empty list, as necessary
    fn get_function_hints(&self) -> Result<Vec<VA>> {
        unimplemented!("FileSystemConfiguration::get_function_hints()")
    }

    fn clone(&self) -> Box<dyn Configuration> {
        Box::new(FileSystemConfiguration {
            path: self.path.clone(),
        })
    }
}
