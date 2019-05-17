use failure::{Error, Fail};
use strum_macros::Display;
use log::{info};

use super::arch;
use super::arch::Arch;
use super::loaders::pe::PELoader;
use super::loaders::sc::ShellcodeLoader;
use super::analysis::{Analyzer};

#[derive(Debug, Fail)]
pub enum LoaderError {
    #[fail(display = "The given buffer is not supported (arch/plat/file format)")]
    NotSupported,
    #[fail(display = "The given buffer uses a bitness incompatible with the architecture")]
    MismatchedBitness,
}

#[derive(Display, Clone, Copy)]
pub enum FileFormat {
    Raw, // shellcode
    PE,
}

#[derive(Display, Clone, Copy)]
pub enum Platform {
    Windows,
}

#[derive(Debug)]
pub struct Section<A: Arch> {
    pub addr: A::RVA,
    pub buf: Vec<u8>,
    // TODO
    pub perms: u8,
    pub name: String,
}

impl<A: Arch> Section<A> {
    pub fn contains(self: &Section<A>, rva: A::RVA) -> bool {
        if rva < self.addr {
            return false;
        }

        if let Some(max) = arch::rva_add_usize::<A>(self.addr, self.buf.len()) {
            if rva >= max {
                return false;
            }
        } else {
            return false;
        }

        true
    }

    pub fn is_executable(&self) -> bool {
        // TODO
        true
    }
}

pub struct LoadedModule<A: Arch> {
    pub base_address: A::VA,
    pub sections: Vec<Section<A>>,
}

pub trait Loader<A: Arch> {
    /// Fetch the number of bits for a pointer in this architecture.
    fn get_arch(&self) -> u8;
    fn get_plat(&self) -> Platform;
    fn get_file_format(&self) -> FileFormat;

    fn get_name(&self) -> String {
        return format!(
            "{}/{}/{}",
            self.get_plat(),
            self.get_arch(),
            self.get_file_format()
        );
    }

    /// Returns True if this Loader knows how to load the given bytes.
    fn taste(&self, buf: &[u8]) -> bool;

    /// Load the given bytes into a Module.
    fn load(&self, buf: &[u8]) -> Result<(LoadedModule<A>, Vec<Box<dyn Analyzer<A>>>), Error>;
}

pub fn default_loaders<A: Arch + 'static + std::fmt::Debug>() -> Vec<Box<dyn Loader<A>>> {
    // we might like these to come from a lazy_static global,
    //  however, then these have to be Sync.
    // I'm not sure if that's a good idea yet.
    let mut loaders: Vec<Box<dyn Loader<A>>> = vec![];
    // the order here matters!
    // the default `load` routine will pick the first matching loader,
    //  so the earlier entries here have higher precedence.

    loaders.push(Box::new(PELoader::<A>::new()));
    loaders.push(Box::new(ShellcodeLoader::<A>::new(Platform::Windows)));

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
/// use lancelot::arch::*;
/// use lancelot::loader::*;
///
/// match taste::<Arch32>(b"\xEB\xFE").nth(0) {
///   Some(loader) => assert_eq!(loader.get_name(), "Windows/32/Raw"),
///   None => panic!("no matching loaders"),
/// };
/// ```
pub fn taste<A: Arch + 'static + std::fmt::Debug>(buf: &[u8]) -> impl Iterator<Item = Box<dyn Loader<A>>> {
    default_loaders::<A>()
        .into_iter()
        .filter(move |loader| loader.taste(buf))
}

/// Load the given sample as a 32-bit module using the first matching
///  loader from `default_loaders`.
///
/// Example:
///
/// ```
/// use lancelot::arch::*;
/// use lancelot::loader::*;
///
/// load::<Arch32>(b"\xEB\xFE")
///   .map(|(loader, module)| {
///     assert_eq!(loader.get_name(),       "Windows/32/Raw");
///     assert_eq!(module.base_address,     0x0);
///     assert_eq!(module.sections[0].name, "raw");
///   })
///   .map_err(|e| panic!(e));
/// ```
pub fn load<A: Arch + 'static + std::fmt::Debug>(buf: &[u8]) -> Result<(Box<dyn Loader<A>>,
                                                                        LoadedModule<A>,
                                                                        Vec<Box<dyn Analyzer<A>>>), Error> {
    match taste::<A>(buf).nth(0) {
        Some(loader) => {
            info!("auto-detected loader: {}", loader.get_name());
            loader.load(buf).map(|(module, analyzers)| (loader, module, analyzers))
        },
        None => Err(LoaderError::NotSupported.into()),
    }
}
