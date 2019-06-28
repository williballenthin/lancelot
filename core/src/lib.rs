extern crate log;
extern crate bitflags;
extern crate simplelog;
extern crate rust_embed;

pub mod analysis;
pub mod arch;
pub mod flowmeta;
pub mod loader;
pub mod loaders;
pub mod util;
pub mod workspace;
pub mod xref;

// helpers that are useful during doctests, tests.
//#[cfg(feature="test")]
pub mod test;
pub mod rsrc;
