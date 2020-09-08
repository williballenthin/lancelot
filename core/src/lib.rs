extern crate bitflags;
#[macro_use]
extern crate lazy_static;
extern crate log;

pub mod analysis;
pub mod arch;
pub mod aspace;
pub mod config;
pub mod loader;
pub mod module;
pub mod pagemap;
pub mod util;

// helpers that are useful during doctests, tests.
// TODO: restrict this to tests only
pub mod rsrc;

pub mod test;

pub type VA = u64;
pub type RVA = u64;
