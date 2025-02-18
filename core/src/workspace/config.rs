use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::VA;
use lancelot_flirt::{FlirtSignature, FlirtSignatureSet};

pub trait Configuration: Send {
    /// provide the FLIRT signatures to be used to recognize known code.
    fn get_sigs(&self) -> Result<FlirtSignatureSet>;

    /// provide the addresses known to be functions.
    fn get_function_hints(&self) -> Result<Vec<VA>>;

    fn clone(&self) -> Box<dyn Configuration>;
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

    fn get_function_hints(&self) -> Result<Vec<VA>> {
        Ok(vec![])
    }

    fn clone(&self) -> Box<dyn Configuration> {
        Box::new(FileSystemConfiguration {
            path: self.path.clone(),
        })
    }
}

#[derive(Default)]
pub struct DynamicConfiguration {
    sig_paths:      Vec<PathBuf>,
    function_hints: Vec<VA>,
}

impl DynamicConfiguration {
    pub fn with_sig_path(mut self, sig_path: &Path) -> DynamicConfiguration {
        self.sig_paths.push(sig_path.to_path_buf());
        self
    }

    pub fn with_sig_paths(mut self, sig_paths: &[PathBuf]) -> DynamicConfiguration {
        self.sig_paths.extend_from_slice(sig_paths);
        self
    }

    pub fn with_function_hints(mut self, function_hints: &[VA]) -> DynamicConfiguration {
        self.function_hints.extend_from_slice(function_hints);
        self
    }
}

impl Configuration for DynamicConfiguration {
    fn get_sigs(&self) -> Result<FlirtSignatureSet> {
        let mut sigs: Vec<FlirtSignature> = Default::default();

        for sig_path in self.sig_paths.iter() {
            if let Some(filename) = sig_path.file_name() {
                if filename.to_string_lossy().ends_with(".sig") {
                    let buf = std::fs::read(sig_path.as_path())?;
                    sigs.extend(lancelot_flirt::sig::parse(&buf)?);
                } else if filename.to_string_lossy().ends_with(".pat") {
                    let buf = String::from_utf8(std::fs::read(sig_path.as_path())?)?;
                    sigs.extend(lancelot_flirt::pat::parse(&buf)?);
                }
            }
        }

        Ok(FlirtSignatureSet::with_signatures(sigs))
    }

    fn get_function_hints(&self) -> Result<Vec<VA>> {
        Ok(self.function_hints.clone())
    }

    fn clone(&self) -> Box<dyn Configuration> {
        Box::new(DynamicConfiguration {
            sig_paths:      self.sig_paths.clone(),
            function_hints: self.function_hints.clone(),
        })
    }
}

pub fn empty() -> Box<dyn Configuration> {
    Box::new(DynamicConfiguration::default())
}
