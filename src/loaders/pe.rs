use failure::{Error, Fail};
use num::Zero;
use std::marker::PhantomData;

use super::super::arch;
use super::super::arch::Arch;
use super::super::loader::{FileFormat, LoadedModule, Loader, Platform, Section};

pub struct PELoader<A: Arch> {
    // PELoader must have a type parameter for it
    //  to implement Loader<A>.
    // however, it doesn't actually use this type itself.
    // so, we use a phantom data marker which has zero type,
    //  to ensure there is not an unused type parameter,
    //  which is a compile error.
    _phantom: PhantomData<A>,
}

impl<A: Arch> PELoader<A> {
    pub fn new() -> PELoader<A> {
        PELoader {
            _phantom: PhantomData {},
        }
    }
}

impl<A: Arch> Loader<A> for PELoader<A> {
    fn get_arch(&self) -> u8 {
        A::get_bits()
    }

    fn get_plat(&self) -> Platform {
        Platform::Windows
    }

    fn get_file_format(&self) -> FileFormat {
        FileFormat::PE
    }

    /// ```
    /// use lancelot::arch::*;
    /// use lancelot::loader::*;
    ///
    /// let loader = lancelot::loaders::pe::PELoader::<Arch32>::new();
    /// assert_eq!(loader.taste(b"MZ\x90\x00"), true);
    /// ```
    fn taste(&self, buf: &[u8]) -> bool {
        &buf[0..2] == b"MZ"
    }

    fn load(&self, buf: &[u8]) -> Result<LoadedModule<A>, Error> {
        Ok(LoadedModule::<A> {
            base_address: A::VA::zero(),
            sections: vec![Section::<A> {
                addr: A::RVA::zero(),
                buf: buf.to_vec(),
                perms: 0x0, // TODO
                name: "raw".to_string(),
            }],
        })
    }
}
