use num::{FromPrimitive, ToPrimitive};

use byteorder::{ByteOrder, LittleEndian};
use failure::{Error, Fail};
use zydis::gen::*;
use zydis::Decoder;
use log::{info};

use super::analysis::Analysis;
use super::arch::Arch;
use super::loader;
use super::loader::{LoadedModule, Loader};
use super::util;

#[derive(Debug, Fail)]
pub enum WorkspaceError {
    #[fail(display = "The given buffer is not supported (arch/plat/file format)")]
    NotSupported,
    #[fail(display = "The given address is not mapped")]
    InvalidAddress,
    #[fail(display = "Buffer overrun")]
    BufferOverrun,
    #[fail(display = "The instruction at the given address is invalid")]
    InvalidInstruction,
}

pub struct WorkspaceBuilder<A: Arch> {
    filename: String,
    buf: Vec<u8>,

    loader: Option<Box<dyn Loader<A>>>,
}

impl<A: Arch + 'static + std::fmt::Debug> WorkspaceBuilder<A> {
    /// Override the default loader picker with the given loader.
    pub fn with_loader(
        self: WorkspaceBuilder<A>,
        loader: Box<dyn Loader<A>>,
    ) -> WorkspaceBuilder<A> {
        info!("using explicitly chosen loader: {}", loader.get_name());
        WorkspaceBuilder {
            loader: Some(loader),
            ..self
        }
    }

    /// Construct a workspace with the given builder configuration.
    ///
    /// This invokes the loaders, analyzers, and another other logic,
    ///  resulting in an initialized Workspace instance.
    ///
    /// Example (with default loader):
    ///
    /// ```
    /// use lancelot::arch::*;
    /// use lancelot::workspace::Workspace;
    ///
    /// Workspace::<Arch32>::from_bytes("foo.bin", b"\xEB\xFE")
    ///   .load()
    ///   .map(|ws| {
    ///     assert_eq!(ws.loader.get_name(),       "Windows/32/Raw");
    ///     assert_eq!(ws.module.base_address,     0x0);
    ///     assert_eq!(ws.module.sections[0].name, "raw");
    ///   })
    ///   .map_err(|e| panic!(e));
    /// ```
    ///
    /// Example (with specific loader):
    ///
    /// ```
    /// use lancelot::arch::*;
    /// use lancelot::loader::Platform;
    /// use lancelot::workspace::Workspace;
    /// use lancelot::loaders::sc::ShellcodeLoader;
    ///
    /// Workspace::<Arch32>::from_bytes("foo.bin", b"\xEB\xFE")
    ///   .with_loader(Box::new(ShellcodeLoader::<Arch32>::new(Platform::Windows)))
    ///   .load()
    ///   .map(|ws| {
    ///     assert_eq!(ws.loader.get_name(),       "Windows/32/Raw");
    ///     assert_eq!(ws.module.base_address,     0x0);
    ///     assert_eq!(ws.module.sections[0].name, "raw");
    ///   })
    ///   .map_err(|e| panic!(e));
    /// ```
    pub fn load(self: WorkspaceBuilder<A>) -> Result<Workspace<A>, Error> {
        // if the user provided a loader, use that.
        // otherwise, use the default detected loader.
        let (ldr, module) = match self.loader {
            Some(ldr) => {
                let module = ldr.load(&self.buf)?;
                (ldr, module)
            }
            None => loader::load::<A>(&self.buf)?,
        };

        info!("loaded {} sections:", module.sections.len());
        module.sections.iter().for_each(|sec| {
            info!("  - {:8} {:>8x}", sec.name, sec.addr);
        });

        let analysis = Analysis::new(&module);

        let decoder = if A::get_bits() == 32 {
            Decoder::new(ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_ADDRESS_WIDTH_32).unwrap()
        } else {
            Decoder::new(ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64).unwrap()
        };

        Ok(Workspace::<A> {
            filename: self.filename,
            buf: self.buf,

            loader: ldr,
            module,

            decoder,

            analysis,
        })
    }
}

pub struct Workspace<A: Arch> {
    // name or source of the file
    pub filename: String,
    // raw bytes of the file
    pub buf: Vec<u8>,

    pub loader: Box<dyn Loader<A>>,
    pub module: LoadedModule<A>,

    pub decoder: Decoder,

    // pub only so that we can split the impl
    pub analysis: Analysis<A>,
}

impl<A: Arch + 'static> Workspace<A> {
    /// Create a workspace and load the given bytes.
    ///
    /// See example on `WorkspaceBuilder::load()`
    pub fn from_bytes(filename: &str, buf: &[u8]) -> WorkspaceBuilder<A> {
        WorkspaceBuilder {
            filename: filename.to_string(),
            buf: buf.to_vec(),
            loader: None,
        }
    }

    pub fn from_file(filename: &str) -> Result<WorkspaceBuilder<A>, Error> {
        Ok(WorkspaceBuilder {
            filename: filename.to_string(),
            buf: util::read_file(filename)?,
            loader: None,
        })
    }

    /// Read bytes from the given RVA.
    ///
    /// Errors:
    ///
    ///   - InvalidAddress - if the address is not mapped.
    ///   - BufferOverrun - if the requested region runs beyond the matching section.
    ///
    /// Example:
    ///
    /// ```
    /// use lancelot::test;
    ///
    /// let ws = test::get_shellcode32_workspace(b"\xEB\xFE");
    /// assert_eq!(ws.read_bytes(0x0, 0x1).unwrap().to_vec(), b"\xEB");
    /// assert_eq!(ws.read_bytes(0x1, 0x1).unwrap().to_vec(), b"\xFE");
    /// assert_eq!(ws.read_bytes(0x0, 0x2).unwrap().to_vec(), b"\xEB\xFE");
    /// assert_eq!(ws.read_bytes(0x0, 0x3).is_err(), true);
    /// assert_eq!(ws.read_bytes(0x2, 0x1).is_err(), true);
    /// ```
    pub fn read_bytes(&self, rva: A::RVA, length: usize) -> Result<&[u8], Error> {
        self.module
            .sections
            .iter()
            .filter(|section| section.contains(rva))
            .nth(0)
            .ok_or_else(|| WorkspaceError::InvalidAddress.into())
            .and_then(|section| -> Result<&[u8], Error> {
                // rva is guaranteed to be within this section,
                // so we can do an unchecked subtract here.
                let offset = rva - section.addr;
                A::RVA::to_usize(&offset)
                    .ok_or_else(|| WorkspaceError::InvalidAddress.into())
                    .and_then(|offset| {
                        if offset + length > section.buf.len() {
                            Err(WorkspaceError::BufferOverrun.into())
                        } else {
                            Ok(&section.buf[offset..offset + length])
                        }
                    })
            })
    }

    /// Is the given range mapped?
    ///
    /// Example:
    ///
    /// ```
    /// use lancelot::test;
    ///
    /// let ws = test::get_shellcode32_workspace(b"\xEB\xFE");
    /// assert!( ws.probe(0x0, 1));
    /// assert!( ws.probe(0x0, 2));
    /// assert!(!ws.probe(0x0, 3));
    /// assert!( ws.probe(0x1, 1));
    /// assert!(!ws.probe(0x2, 1));
    /// ```
    pub fn probe(&self, rva: A::RVA, length: usize) -> bool {
        self.read_bytes(rva, length).is_ok()
    }

    /// Read a byte from the given RVA.
    ///
    /// Errors: same as `read_bytes`.
    ///
    /// Example:
    ///
    /// ```
    /// use lancelot::test;
    ///
    /// let ws = test::get_shellcode32_workspace(b"\xEB\xFE");
    /// assert_eq!(ws.read_u8(0x0).unwrap(), 0xEB);
    /// assert_eq!(ws.read_u8(0x1).unwrap(), 0xFE);
    /// assert_eq!(ws.read_u8(0x2).is_err(), true);
    /// ```
    pub fn read_u8(&self, rva: A::RVA) -> Result<u8, Error> {
        self.read_bytes(rva, 1).and_then(|buf| Ok(buf[0]))
    }

    /// Read a word from the given RVA.
    ///
    /// Errors: same as `read_bytes`.
    ///
    /// Example:
    ///
    /// ```
    /// use lancelot::test;
    ///
    /// let ws = test::get_shellcode32_workspace(b"\xEB\xFE");
    /// assert_eq!(ws.read_u16(0x0).unwrap(), 0xFEEB);
    /// assert_eq!(ws.read_u16(0x1).is_err(), true);
    /// assert_eq!(ws.read_u16(0x2).is_err(), true);
    /// ```
    pub fn read_u16(&self, rva: A::RVA) -> Result<u16, Error> {
        self.read_bytes(rva, 2)
            .and_then(|buf| Ok(LittleEndian::read_u16(buf)))
    }

    /// Read a dword from the given RVA.
    pub fn read_u32(&self, rva: A::RVA) -> Result<u32, Error> {
        self.read_bytes(rva, 4)
            .and_then(|buf| Ok(LittleEndian::read_u32(buf)))
    }

    /// Read a qword from the given RVA.
    pub fn read_u64(&self, rva: A::RVA) -> Result<u64, Error> {
        self.read_bytes(rva, 8)
            .and_then(|buf| Ok(LittleEndian::read_u64(buf)))
    }

    /// Read an RVA from the given RVA.
    /// Note that the size of the read is dependent on the architecture.
    ///
    /// Errors: same as `read_bytes`.
    ///
    /// Example:
    ///
    /// ```
    /// use lancelot::test;
    ///
    /// let ws = test::get_shellcode32_workspace(b"\x00\x11\x22\x33");
    /// assert_eq!(ws.read_rva(0x0).unwrap(), 0x33221100);
    /// assert_eq!(ws.read_rva(0x1).is_err(), true);
    /// ```
    pub fn read_rva(&self, rva: A::RVA) -> Result<A::RVA, Error> {
        match A::get_bits() {
            // these conversions will never fail
            32 => Ok(A::RVA::from_u32(self.read_u32(rva)?).unwrap()),
            64 => Ok(A::RVA::from_u64(self.read_u64(rva)?).unwrap()),
            _ => panic!("unexpected architecture"),
        }
    }

    /// Read a VA from the given RVA.
    /// Note that the size of the read is dependent on the architecture.
    pub fn read_va(&self, rva: A::RVA) -> Result<A::VA, Error> {
        match A::get_bits() {
            // these conversions will never fail
            32 => Ok(A::VA::from_u32(self.read_u32(rva)?).unwrap()),
            64 => Ok(A::VA::from_u64(self.read_u64(rva)?).unwrap()),
            _ => panic!("unexpected architecture"),
        }
    }

    /// Decode an instruction at the given RVA.
    ///
    /// Errors:
    ///
    ///   - InvalidAddress - if the address is not mapped.
    ///   - BufferOverrun - if the requested region runs beyond the matching section.
    ///   - InvalidInstruction - if an instruction cannot be decoded.
    ///
    /// Example:
    ///
    /// ```
    /// use zydis::gen::*;
    /// use lancelot::test;
    ///
    /// let ws = test::get_shellcode32_workspace(b"\xEB\xFE");
    /// assert_eq!(ws.read_insn(0x0).is_ok(), true);
    /// assert_eq!(ws.read_insn(0x0).unwrap().length, 2);
    /// assert_eq!(ws.read_insn(0x0).unwrap().mnemonic as i32, ZYDIS_MNEMONIC_JMP);
    /// ```
    pub fn read_insn(&self, rva: A::RVA) -> Result<ZydisDecodedInstruction, Error> {
        // this is `read_bytes` except that it reads at most 0x10 bytes.
        // if less are available, then less are returned.
        let buf = self
            .module
            .sections
            .iter()
            .filter(|section| section.contains(rva))
            .nth(0)
            .ok_or_else(|| WorkspaceError::InvalidAddress.into())
            .and_then(|section| -> Result<&[u8], Error> {
                // rva is guaranteed to be within this section,
                // so we can do an unchecked subtract here.
                let offset = rva - section.addr;
                A::RVA::to_usize(&offset)
                    .ok_or_else(|| WorkspaceError::InvalidAddress.into())
                    .and_then(|offset| {
                        if offset + 0x10 > section.buf.len() {
                            Ok(&section.buf[offset..])
                        } else {
                            Ok(&section.buf[offset..offset + 0x10])
                        }
                    })
            })?;

        // RVA will always be either u32 or u64 (never bigger),
        // so we can always fit this into a u64.
        let pc = A::RVA::to_u64(&rva).unwrap();

        match self.decoder.decode(&buf, pc) {
            Ok(Some(insn)) => Ok(insn),
            Ok(None) => Err(WorkspaceError::InvalidInstruction.into()),
            Err(_) => Err(WorkspaceError::InvalidInstruction.into()),
        }
    }

    // API:
    //   get_insn
    //   get_xrefs_to
    //   get_xrefs_from
    //   get_functions

    // elsewhere:
    //   call graph
    //   control flow graph

    // see: `analysis::impl Workspace`
}
