use strum_macros::{Display};
use super::arch::{Arch, Arch32, rva_plus_usize};

use failure::{Error, Fail};

#[derive(Debug, Fail)]
pub enum LoaderError {
    #[fail(display = "The given buffer is not supported (arch/plat/file format)")]
    NotSupported,
}

#[derive(Display, Clone, Copy)]
pub enum DetectedArch {
    X32,
    X64
}

#[derive(Display, Clone, Copy)]
pub enum FileFormat {
    Raw,  // shellcode
    PE,
}

#[derive(Display, Clone, Copy)]
pub enum Platform {
    Windows,
}

pub struct Section<A: Arch> {
    pub addr: A::RVA,
    pub buf: Vec<u8>,
    // TODO
    pub perms: u8,
    pub name: String,
}

impl <A: Arch> Section<A> {
    pub fn contains(self: &Section<A>, rva: A::RVA) -> bool {
        if rva < self.addr {
            return false;
        }

        if let Some(max) = rva_plus_usize::<A>(self.addr, self.buf.len()) {
            if rva >= max {
                return false
            }
        } else {
            return false
        }

        true
    }
}

pub struct LoadedModule<A: Arch> {
    pub base_address: A::VA,
    pub sections: Vec<Section<A>>,
}

pub trait Loader {
    fn get_arch(&self) -> DetectedArch;
    fn get_plat(&self) -> Platform;
    fn get_file_format(&self) -> FileFormat;

    fn get_name(&self) -> String {
        return format!("{}/{}/{}", self.get_plat(), self.get_arch(), self.get_file_format());
    }

    fn taste(&self, buf: &[u8]) -> bool;

    /// Load the given buffer as a 32-bit module.
    ///
    /// Panics if this isn't a loader that supports 32-bit modules.
    fn load32(&self, buf: &[u8]) -> Result<LoadedModule<Arch32>, Error>;
}


// TODO: implement loaders/x32/windows/pe
// TODO: implement loaders/x64/windows/pe


pub struct ShellcodeLoader {
    arch: DetectedArch,
    plat: Platform,
}

impl ShellcodeLoader {
    pub fn new(arch: DetectedArch, plat: Platform) -> ShellcodeLoader {
        ShellcodeLoader {
            arch,
            plat,
        }
    }
}

impl Loader for ShellcodeLoader {
    fn get_arch(&self) -> DetectedArch {
        self.arch
    }

    fn get_plat(&self) -> Platform {
        self.plat
    }

    fn get_file_format(&self) -> FileFormat {
        FileFormat::Raw
    }

    fn taste(&self, _buf: &[u8]) -> bool {
        // we can load anything as shellcode
        true
    }

    /// ```
    /// use lancelot::loader::*;
    ///
    /// let loader = lancelot::loader::ShellcodeLoader::new(DetectedArch::X32, Platform::Windows);
    /// loader.load32(b"MZ\x90\x00")
    ///   .map(|module| {
    ///     assert_eq!(module.base_address,     0x0);
    ///     assert_eq!(module.sections[0].name, "raw");
    ///   })
    ///   .map_err(|e| panic!(e));
    /// ```
    fn load32(&self, buf: &[u8]) -> Result<LoadedModule<Arch32>, Error> {
        if let DetectedArch::X32 = self.arch {
            Ok(LoadedModule::<Arch32>{
                base_address: 0x0,
                sections: vec![
                    Section::<Arch32> {
                        addr: 0x0,
                        buf: buf.to_vec(),
                        perms: 0x0, // TODO
                        name: "raw".to_string(),
                    }
                ]
            })
        } else {
            panic!("not a 32-bit loader")
        }
    }
}

pub fn default_loaders() -> Vec<Box<dyn Loader>> {
    // we might like these to come from a lazy_static global,
    //  however, then these have to be Sync.
    // I'm not sure if that's a good idea yet.
    let mut loaders: Vec<Box<dyn Loader>> = vec![];
    // the order here matters!
    // the default `load32` routine will pick the first matching loader,
    //  so the earlier entries here have higher precedence.
    loaders.push(Box::new(ShellcodeLoader::new(DetectedArch::X32, Platform::Windows)));
    loaders.push(Box::new(ShellcodeLoader::new(DetectedArch::X64, Platform::Windows)));
    loaders
}

/// Find the loaders that support loading the given sample.
///
/// The result is an iterator so that the caller can use the first
///  matching result without waiting for all Loaders to taste the bytes.
///
/// Loaders are tasted in the order defined in `default_loaders`.
///
/// Example:
///
/// ```
/// use lancelot::loader::*;
///
/// match taste(b"\xEB\xFE").nth(0) {
///   Some(loader) => assert_eq!(loader.get_name(), "Windows/X32/Raw"),
///   None => panic!("no matching loaders"),
/// };
/// ```
pub fn taste(buf: &[u8]) -> impl Iterator<Item=Box<dyn Loader>> {
    default_loaders()
        .into_iter()
        .filter(move |loader| loader.taste(buf))
}

/// Load the given sample as a 32-bit module using the first matching
///  loader from `default_loaders`.
///
/// Example:
///
/// ```
/// use lancelot::loader::*;
///
/// load32(b"\xEB\xFE")
///   .map(|module| {
///     assert_eq!(module.base_address,     0x0);
///     assert_eq!(module.sections[0].name, "raw");
///   })
///   .map_err(|e| panic!(e));
/// ```
pub fn load32(buf: &[u8]) -> Result<LoadedModule<Arch32>, Error> {
    match taste(buf).nth(0) {
        Some(loader) => {
            loader.load32(buf)
        },
        None => Err(LoaderError::NotSupported.into()),
    }
}
