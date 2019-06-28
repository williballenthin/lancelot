use failure::{Error};

use super::super::arch::{Arch, VA, RVA};
use super::super::loader::{FileFormat, LoadedModule, Loader, Platform, Section, Permissions};
use super::super::analysis::{Analyzer};

pub struct ShellcodeLoader {
    plat: Platform,
    arch: Arch,
}

impl ShellcodeLoader {
    pub fn new(plat: Platform, arch: Arch) -> ShellcodeLoader {
        ShellcodeLoader {
            plat,
            arch,
        }
    }
}

impl Loader for ShellcodeLoader {
    fn get_arch(&self) -> Arch {
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
    /// use lancelot::arch::*;
    /// use lancelot::loader::*;
    ///
    /// let loader = lancelot::loaders::sc::ShellcodeLoader::new(Platform::Windows, Arch::X32);
    /// loader.load(b"MZ\x90\x00")
    ///   .map(|(module, analyzers)| {
    ///     assert_eq!(module.base_address,     VA(0x0));
    ///     assert_eq!(module.sections[0].name, "raw");
    ///   })
    ///   .map_err(|e| panic!(e));
    /// ```
    fn load(&self, buf: &[u8]) -> Result<(LoadedModule, Vec<Box<dyn Analyzer>>), Error> {
        Ok((LoadedModule {
            base_address: VA(0x0),
            sections: vec![Section {
                addr: RVA(0x0),
                buf: buf.to_vec(),
                perms: Permissions::RWX,
                name: "raw".to_string(),
            }],
        },
        vec![]))
    }
}
