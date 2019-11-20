extern crate bitflags;
extern crate log;
extern crate rust_embed;

pub mod analysis;
pub mod arch;
pub mod basicblock;
pub mod config;
pub mod flowmeta;
pub mod loader;
pub mod loaders;
pub mod pagemap;
pub mod util;
pub mod workspace;
pub mod xref;

pub use basicblock::BasicBlock;
pub use workspace::Workspace;
pub use xref::Xref;

// helpers that are useful during doctests, tests.
//#[cfg(feature="test")]
pub mod rsrc;
pub mod test;
