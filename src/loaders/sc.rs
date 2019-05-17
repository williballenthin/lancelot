use failure::{Error};
use num::Zero;
use std::marker::PhantomData;

use super::super::arch::Arch;
use super::super::loader::{FileFormat, LoadedModule, Loader, Platform, Section};

pub struct ShellcodeLoader<A: Arch> {
    plat: Platform,
    // ShellcodeLoader must have a type parameter for it
    //  to implement Loader<A>.
    // however, it doesn't actually use this type itself.
    // so, we use a phantom data marker which has zero type,
    //  to ensure there is not an unused type parameter,
    //  which is a compile error.
    _phantom: PhantomData<A>,
}

impl<A: Arch> ShellcodeLoader<A> {
    pub fn new(plat: Platform) -> ShellcodeLoader<A> {
        ShellcodeLoader {
            plat,
            _phantom: PhantomData {},
        }
    }
}

impl<A: Arch> Loader<A> for ShellcodeLoader<A> {
    fn get_arch(&self) -> u8 {
        A::get_bits()
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
    /// use lancelot::arch::*;
    /// use lancelot::loader::*;
    ///
    /// let loader = lancelot::loaders::sc::ShellcodeLoader::<Arch32>::new(Platform::Windows);
    /// loader.load(b"MZ\x90\x00")
    ///   .map(|module| {
    ///     assert_eq!(module.base_address,     0x0);
    ///     assert_eq!(module.sections[0].name, "raw");
    ///   })
    ///   .map_err(|e| panic!(e));
    /// ```
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
