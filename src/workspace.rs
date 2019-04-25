// 1. loaders taste file
//   a. detect arch
//   b. detect platform
//   c. detect file format
// 2. create workspace
// 3. load via loader
// 4. run analysis passes (from loader?)

use super::util;
use super::arch::{Arch};
use super::loader::{LoadedModule, Loader};

use failure::{Error, Fail};

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

    pub loader: Box<dyn Loader>,
    pub module: LoadedModule<A>,

    // analysis {
    //   flowmeta,
    //   datameta,
    //   symbols,
    //   functions,
    // }
}

impl<A: Arch> Workspace<A> {

    pub fn from_bytes(filename: &str, buf: Vec<u8>) -> Result<Workspace<A>, Error> {
        Err(WorkspaceError::NotSupported.into())
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
