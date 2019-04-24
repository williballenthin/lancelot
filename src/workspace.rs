// 1. loaders taste file
//   a. detect arch
//   b. detect platform
//   c. detect file format
// 2. create workspace
// 3. load via loader
// 4. run analysis passes (from loader?)

pub struct Workspace {
    // name or source of the file
    pub filename: String,
    // raw bytes of the file
    pub buf: Vec<u8>,

    // loader: Loader,
    // module (from loader) {
    //   base addr,
    //   sections [{
    //     buf
    //     name
    //     permissions
    //   }]
    // }

    // analysis {
    //   flowmeta,
    //   datameta,
    //   symbols,
    //   functions,
    // }
}

impl Workspace {
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
