use byteorder::{ByteOrder, LittleEndian};
use failure::{Error, Fail};
use zydis::gen::*;
use zydis::Decoder;
use log::{info};

use super::analysis::Analysis;
use super::arch::{Arch, VA, RVA};
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

pub struct WorkspaceBuilder {
    filename: String,
    buf: Vec<u8>,

    loader: Option<Box<dyn Loader>>,

    should_analyze: bool,
}

impl WorkspaceBuilder {
    /// Override the default loader picker with the given loader.
    pub fn with_loader(
        self: WorkspaceBuilder,
        loader: Box<dyn Loader>,
    ) -> WorkspaceBuilder {
        info!("using explicitly chosen loader: {}", loader.get_name());
        WorkspaceBuilder {
            loader: Some(loader),
            ..self
        }
    }

    pub fn disable_analysis(self: WorkspaceBuilder) -> WorkspaceBuilder {
        info!("disabling analysis");
        WorkspaceBuilder {
            should_analyze: false,
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
    /// Workspace::from_bytes("foo.bin", b"\xEB\xFE")
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
    /// Workspace::from_bytes("foo.bin", b"\xEB\xFE")
    ///   .with_loader(Box::new(ShellcodeLoader::new(Platform::Windows)))
    ///   .load()
    ///   .map(|ws| {
    ///     assert_eq!(ws.loader.get_name(),       "Windows/32/Raw");
    ///     assert_eq!(ws.module.base_address,     0x0);
    ///     assert_eq!(ws.module.sections[0].name, "raw");
    ///   })
    ///   .map_err(|e| panic!(e));
    /// ```
    pub fn load(self: WorkspaceBuilder) -> Result<Workspace, Error> {
        // if the user provided a loader, use that.
        // otherwise, use the default detected loader.
        let (ldr, module, analyzers) = match self.loader {
            // TODO: let users specify analyzers via builder
            Some(ldr) => {
                let (module, analyzers) = ldr.load(&self.buf)?;
                (ldr, module, analyzers)
            }
            None => loader::load(&self.buf)?,
        };

        info!("loaded {} sections:", module.sections.len());
        module.sections.iter().for_each(|sec| {
            info!("  - {:8} {:>8x}", sec.name, sec.addr);
        });

        let analysis = Analysis::new(&module);

        let decoder = match ldr.get_arch() {
            Arch::X32 => Decoder::new(ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_ADDRESS_WIDTH_32).unwrap(),
            Arch::X64 => Decoder::new(ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64).unwrap(),
        };

        let mut ws = Workspace {
            filename: self.filename,
            buf: self.buf,

            loader: ldr,
            module,

            decoder,

            analysis,
        };

        if self.should_analyze {
            for analyzer in analyzers.iter() {
                info!("analyzing with {}", analyzer.get_name());
                analyzer.analyze(&mut ws)?;
            }
        }

        Ok(ws)
    }
}

pub struct Workspace {
    // name or source of the file
    pub filename: String,
    // raw bytes of the file
    pub buf: Vec<u8>,

    pub loader: Box<dyn Loader>,
    pub module: LoadedModule,

    pub decoder: Decoder,

    // pub only so that we can split the impl
    pub analysis: Analysis,
}

impl Workspace {
    /// Create a workspace and load the given bytes.
    ///
    /// See example on `WorkspaceBuilder::load()`
    pub fn from_bytes(filename: &str, buf: &[u8]) -> WorkspaceBuilder {
        WorkspaceBuilder {
            filename: filename.to_string(),
            buf: buf.to_vec(),
            loader: None,
            should_analyze: true,
        }
    }

    pub fn from_file(filename: &str) -> Result<WorkspaceBuilder, Error> {
        Ok(WorkspaceBuilder {
            filename: filename.to_string(),
            buf: util::read_file(filename)?,
            loader: None,
            should_analyze: true,
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
    /// use lancelot::arch::RVA;
    ///
    /// let ws = test::get_shellcode32_workspace(b"\xEB\xFE");
    /// assert_eq!(ws.read_bytes(RVA(0x0), 0x1).unwrap().to_vec(), b"\xEB");
    /// assert_eq!(ws.read_bytes(RVA(0x1), 0x1).unwrap().to_vec(), b"\xFE");
    /// assert_eq!(ws.read_bytes(RVA(0x0), 0x2).unwrap().to_vec(), b"\xEB\xFE");
    /// assert_eq!(ws.read_bytes(RVA(0x0), 0x3).is_err(), true);
    /// assert_eq!(ws.read_bytes(RVA(0x2), 0x1).is_err(), true);
    /// ```
    pub fn read_bytes(&self, rva: RVA, length: usize) -> Result<&[u8], Error> {
        self.module
            .sections
            .iter()
            .filter(|section| section.contains(rva))
            .nth(0)
            .ok_or_else(|| WorkspaceError::InvalidAddress.into())
            .and_then(|section| -> Result<&[u8], Error> {
                // rva is guaranteed to be within this section,
                // so we can do an unchecked subtract here.
                let offset = RVA(rva.0 - section.addr.0);
                if offset + length > section.buf.len().into() {
                    Err(WorkspaceError::BufferOverrun.into())
                } else {
                    let end: usize = ((offset.0 as u64) + (length as u64)) as usize;
                    Ok(&section.buf[offset.into()..end])
                }
            })
    }

    /// Is the given range mapped?
    ///
    /// Example:
    ///
    /// ```
    /// use lancelot::test;
    /// use lancelot::arch::RVA;
    ///
    /// let ws = test::get_shellcode32_workspace(b"\xEB\xFE");
    /// assert!( ws.probe(RVA(0x0), 1));
    /// assert!( ws.probe(RVA(0x0), 2));
    /// assert!(!ws.probe(RVA(0x0), 3));
    /// assert!( ws.probe(RVA(0x1), 1));
    /// assert!(!ws.probe(RVA(0x2), 1));
    /// ```
    pub fn probe(&self, rva: RVA, length: usize) -> bool {
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
    /// use lancelot::arch::RVA;
    ///
    /// let ws = test::get_shellcode32_workspace(b"\xEB\xFE");
    /// assert_eq!(ws.read_u8(RVA(0x0)).unwrap(), 0xEB);
    /// assert_eq!(ws.read_u8(RVA(0x1)).unwrap(), 0xFE);
    /// assert_eq!(ws.read_u8(RVA(0x2)).is_err(), true);
    /// ```
    pub fn read_u8(&self, rva: RVA) -> Result<u8, Error> {
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
    /// use lancelot::arch::RVA;
    ///
    /// let ws = test::get_shellcode32_workspace(b"\xEB\xFE");
    /// assert_eq!(ws.read_u16(RVA(0x0)).unwrap(), 0xFEEB);
    /// assert_eq!(ws.read_u16(RVA(0x1)).is_err(), true);
    /// assert_eq!(ws.read_u16(RVA(0x2)).is_err(), true);
    /// ```
    pub fn read_u16(&self, rva: RVA) -> Result<u16, Error> {
        self.read_bytes(rva, 2)
            .and_then(|buf| Ok(LittleEndian::read_u16(buf)))
    }

    /// Read a dword from the given RVA.
    pub fn read_u32(&self, rva: RVA) -> Result<u32, Error> {
        self.read_bytes(rva, 4)
            .and_then(|buf| Ok(LittleEndian::read_u32(buf)))
    }

    /// Read a qword from the given RVA.
    pub fn read_u64(&self, rva: RVA) -> Result<u64, Error> {
        self.read_bytes(rva, 8)
            .and_then(|buf| Ok(LittleEndian::read_u64(buf)))
    }

    /// Read a dword from the given RVA.
    pub fn read_i32(&self, rva: RVA) -> Result<i32, Error> {
        self.read_bytes(rva, 4)
            .and_then(|buf| Ok(LittleEndian::read_i32(buf)))
    }

    /// Read a qword from the given RVA.
    pub fn read_i64(&self, rva: RVA) -> Result<i64, Error> {
        self.read_bytes(rva, 8)
            .and_then(|buf| Ok(LittleEndian::read_i64(buf)))
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
    /// use lancelot::arch::RVA;
    ///
    /// let ws = test::get_shellcode32_workspace(b"\x00\x11\x22\x33");
    /// assert_eq!(ws.read_rva(RVA(0x0)).unwrap(), 0x33221100);
    /// assert_eq!(ws.read_rva(RVA(0x1)).is_err(), true);
    /// ```
    pub fn read_rva(&self, rva: RVA) -> Result<RVA, Error> {
        match self.loader.get_arch() {
            Arch::X32 => Ok(RVA::from(self.read_i32(rva)?)),
            Arch::X64 => Ok(RVA::from(self.read_i64(rva)?)),
        }
    }

    /// Read a VA from the given RVA.
    /// Note that the size of the read is dependent on the architecture.
    pub fn read_va(&self, rva: RVA) -> Result<VA, Error> {
        match self.loader.get_arch() {
            Arch::X32 => Ok(VA::from(self.read_u32(rva)?)),
            Arch::X64 => Ok(VA::from(self.read_u64(rva)?)),
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
    pub fn read_insn(&self, rva: RVA) -> Result<ZydisDecodedInstruction, Error> {
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
                let offset = RVA(rva.0 - section.addr.0);
                if offset + 0x10 > section.buf.len().into() {
                    Ok(&section.buf[offset.into()..])
                } else {
                    let end: usize = ((offset.0 as u64) + 0x10) as usize;
                    Ok(&section.buf[offset.into()..end])
                }
            })?;

        let pc = rva.into();

        match self.decoder.decode(&buf, pc) {
            Ok(Some(insn)) => Ok(insn),
            Ok(None) => Err(WorkspaceError::InvalidInstruction.into()),
            Err(_) => Err(WorkspaceError::InvalidInstruction.into()),
        }
    }

    /// Read a utf-8 encoded string at the given RVA.
    ///
    /// Errors:
    ///
    ///   - InvalidAddress - if the address is not mapped.
    ///   - std::str::Utf8Error - if the data is not valid utf8.
    ///
    /// Example:
    ///
    /// ```
    /// use zydis::gen::*;
    /// use lancelot::test;
    /// use lancelot::arch::RVA;
    ///
    /// let ws = test::get_shellcode32_workspace(b"\x00\x41\x41\x00");
    /// assert!(ws.read_utf8(RVA(0x1)).is_ok());
    /// assert_eq!(ws.read_utf8(RVA(0x1)).unwrap(), "AA");
    /// ```
    pub fn read_utf8(&self, rva: RVA) -> Result<String, Error> {
        // this is `read_bytes` except that it reads until the end of the section.
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
                let offset = RVA(rva.0 - section.addr.0);
                Ok(&section.buf[offset.into()..])
            })?;

        // when we split, we're guaranteed at have at least one entry,
        // so .next().unwrap() is safe.
        let sbuf = buf.split(|&b| b == 0x0).next().unwrap();
        Ok(std::str::from_utf8(sbuf)?.to_string())
    }

    pub fn rva(&self, va: VA) -> Option<RVA> {
        self.module.base_address.rva(va)
    }

    pub fn va(&self, rva: RVA) -> Option<VA> {
        self.module.base_address.va(rva)
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
