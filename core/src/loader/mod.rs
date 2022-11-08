//! loaders are responsible for populating an AddressSpace and Module,
//! and optionally additional metadata.

// today, the results go into specific structs, which workspaces can load
// with specific routines, like `workspace.from_pe()`.
// somewhere we should introduce a generic trait over the common functionality
// of loading/workspacing.

pub mod coff;
pub mod pe;
