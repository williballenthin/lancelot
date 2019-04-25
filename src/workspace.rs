use num::{ToPrimitive};
use failure::{Error, Fail, bail, ensure};

use super::util;
use super::loader;
use super::arch;
use super::arch::{Arch};
use super::loader::{LoadedModule, Loader, Section};


#[derive(Debug, Fail)]
pub enum WorkspaceError {
    #[fail(display = "The given buffer is not supported (arch/plat/file format)")]
    NotSupported,
    #[fail(display = "The given address is not mapped")]
    InvalidAddress,
    #[fail(display = "Buffer overrun")]
    BufferOverrun,
}

pub struct Workspace<A: Arch> {
    // name or source of the file
    pub filename: String,
    // raw bytes of the file
    pub buf: Vec<u8>,

    pub loader: Box<dyn Loader<A>>,
    pub module: LoadedModule<A>,

    // analysis {
    //   flowmeta,
    //   datameta,
    //   symbols,
    //   functions,
    // }
}

impl<A: Arch + 'static> Workspace<A> {
    /// Create a workspace and load the given bytes.
    ///
    /// Example:
    ///
    /// ```
    /// use lancelot::arch::*;
    /// use lancelot::workspace::Workspace;
    ///
    /// Workspace::<Arch32>::from_bytes("foo.bin", b"\xEB\xFE")
    ///   .map(|ws| {
    ///     assert_eq!(ws.loader.get_name(),       "Windows/32/Raw");
    ///     assert_eq!(ws.module.base_address,     0x0);
    ///     assert_eq!(ws.module.sections[0].name, "raw");
    ///   })
    ///   .map_err(|e| panic!(e));
    /// ```
    pub fn from_bytes(filename: &str, buf: &[u8]) -> Result<Workspace<A>, Error> {
        let buf = buf.to_vec();
        let (ldr, module) = loader::load::<A>(&buf)?;

        Ok(Workspace::<A>{
            filename: filename.to_string(),
            buf: buf,
            loader: ldr,
            module: module,
        })
    }

    // TODO: maybe use the builder pattern here,
    //  so that you can optionally specify the loader you'd like to use.
    //
    // For example:
    //
    // ```
    //  Workspace::<Arch32>::new()
    //    .with_file("foo.bin")
    //    .with_loader(loader::ShellcodeLoader::<Arch32>::new(...))
    //    .load();
    // ```
    pub fn from_file(filename: &str) -> Result<Workspace<A>, Error> {
        let buf = util::read_file(filename)?;
        Workspace::from_bytes(filename, &buf)
    }

    /// Create a workspace and load the given bytes.
    ///
    /// Errors:
    ///
    ///   - InvalidAddress - if the address is not mapped.
    ///   - BufferOverrun - if the requested region runs beyond the matching section.
    ///
    /// Example:
    ///
    /// ```
    /// use lancelot::arch::*;
    /// use lancelot::workspace::Workspace;
    ///
    /// // TODO: use exactly the shellcode loader.
    ///
    /// Workspace::<Arch32>::from_bytes("foo.bin", b"\xEB\xFE")
    ///   .map(|ws| {
    ///     assert_eq!(ws.read_bytes(0x0, 0x1).unwrap().to_vec(), b"\xEB");
    ///     assert_eq!(ws.read_bytes(0x1, 0x1).unwrap().to_vec(), b"\xFE");
    ///     assert_eq!(ws.read_bytes(0x0, 0x2).unwrap().to_vec(), b"\xEB\xFE");
    ///     assert_eq!(ws.read_bytes(0x0, 0x3).is_err(), true);
    ///     assert_eq!(ws.read_bytes(0x2, 0x1).is_err(), true);
    ///   })
    ///   .map_err(|e| panic!(e));
    /// ```
    pub fn read_bytes(&self, rva: A::RVA, length: usize) -> Result<&[u8], Error> {
        self.module.sections
            .iter()
            .filter(|section| section.contains(rva))
            .nth(0)
            .ok_or(WorkspaceError::InvalidAddress.into())
            .and_then(|section| -> Result<&[u8], Error> {
                // rva is guaranteed to be within this section,
                // so we can do an unchecked subtract here.
                let offset = rva - section.addr;
                A::RVA::to_usize(&offset)
                    .ok_or(WorkspaceError::InvalidAddress.into())
                    .and_then(|offset| {
                        if offset + length > section.buf.len() {
                            Err(WorkspaceError::BufferOverrun.into())
                        } else {
                            Ok(&section.buf[offset..offset+length])
                        }
                    })
            })
    }

    // API:
    //   get_insn
    //   get_byte/word/dword
    //   get_xrefs_to
    //   get_xrefs_from
    //   get_functions

    // elsewhere:
    //   call graph
    //   control flow graph
}
