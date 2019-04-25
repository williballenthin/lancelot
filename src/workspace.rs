use failure::{Error, Fail, bail, ensure};

use super::util;
use super::loader;
use super::arch::{Arch};
use super::loader::{LoadedModule, Loader};


#[derive(Debug, Fail)]
pub enum WorkspaceError {
    #[fail(display = "The given buffer is not supported (arch/plat/file format)")]
    NotSupported,
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
    pub fn from_bytes(filename: &str, buf: Vec<u8>) -> Result<Workspace<A>, Error> {
        ensure!(A::get_bits() == 32, "only 32-bit loading right now");

        let (ldr, module) = loader::load::<A>(&buf)?;

        Ok(Workspace::<A>{
            filename: filename.to_string(),
            buf: buf,
            loader: ldr,
            module: module,
        })
    }

    pub fn from_file(filename: &str) -> Result<Workspace<A>, Error> {
        let buf = util::read_file(filename)?;
        Workspace::from_bytes(filename, buf)
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
