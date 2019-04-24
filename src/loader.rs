use num::FromPrimitive;
use strum_macros::{Display};
use super::arch::{Arch, Arch32, rva_plus_usize};

// TODO: figure out how to use failure for error (or some other pattern)
#[derive(Debug)]
pub enum Error {
    Foo
}

#[derive(Display)]
pub enum DetectedArch {
    X32,
    X64
}

#[derive(Display)]
pub enum FileFormat {
    Raw,  // shellcode
    PE,
}

#[derive(Display)]
pub enum Platform {
    Windows,
}

struct Section<A: Arch> {
    addr: A::RVA,
    buf: Vec<u8>,
    // TODO
    perms: u8,
    name: String,
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

struct LoadedModule<A: Arch> {
    base_address: A::VA,
    sections: Vec<Section<A>>,
}

trait Loader {
    fn get_arch(&self) -> DetectedArch;
    fn get_plat(&self) -> Platform;
    fn get_file_format(&self) -> FileFormat;
    // TODO: compiler?

    fn get_name(&self) -> String {
        return format!("{}/{}/{}", self.get_plat(), self.get_arch(), self.get_file_format());
    }

    fn taste(&self, buf: &[u8]) -> bool;

    fn load32(&self, buf: &[u8]) -> Result<LoadedModule<Arch32>, Error>;
}


// TODO: implement loaders/x32/windows/shellcode
// TODO: implement loaders/x32/windows/pe
// TODO: implement loaders/x64/windows/shellcode
// TODO: implement loaders/x64/windows/pe


/*******

struct ShellcodeLoader {
    arch: Arch,
    plat: Platform,
    file_format: FileFormat,
}

impl ShellcodeLoader {
    pub fn new(arch: impl Arch, plat: Platform, file_format: FileFormat) -> ShellcodeLoader {
        ShellcodeLoader {
            arch,
            plat,
            file_format,
        }
    }
}

impl Loader for ShellcodeLoader {
    fn get_arch(&self) -> impl Arch {
        self.arch
    }

    fn get_plat(&self) -> Platform {
        self.plat
    }

    fn get_file_format(&self) -> FileFormat {
        self.file_format
    }

    fn taste(&self, buf: &[u8]) -> bool {
        true
    }

    /// ```
    /// use lancelot::arch::ARCH32;
    /// use lancelot::loader::{ShellcodeLoader, Platform, FileFormat};
    /// let loader = lancelot::loader::ShellcodeLoader::new(ARCH32, Platform::Windows, FileFormat::Raw);
    /// match loader.load32(b"MZ\x90\x00".as_bytes()) {
    ///   Ok(mod) => {
    ///     assert_eq!(mod.name, "raw");
    ///   },
    ///   Err(e) => panic!(e),
    /// };
    /// ```
    fn load32(&self, buf: &[u8]) -> Result<LoadedModule<Arch32>, Error> {
        if self.arch != ARCH32 {
            panic!("not a 32-bit loader")
        }

        Ok(LoadedModule::<Arch32>{
            base_address: 0x0,
            sections: vec![
                Section::<Arch32> {
                    addr: 0x0,
                    buf: buf.clone(),
                    perms: 0x0, // TODO
                    name: "raw".to_string(),
                }
            ]
        })
    }
}


fn taste(buf: &[u8]) -> Vec<Loader> {
    vec![
        ShellcodeLoader::new(ARCH32, Platform::Windows, FileFormat::Raw),
        ShellcodeLoader::new(ARCH64, Platform::Windows, FileFormat::Raw),
    ].iter()
        .filter(|loader| loader.taste(buf))
        .collect()
}

fn load(buf: &[u8]) -> Result<LoadedModule, Error> {
    Err(Error::Foo)
}

*********/
