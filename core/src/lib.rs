extern crate bitflags;
extern crate log;

pub mod aspace;
pub mod basicblock;
pub mod config;
pub mod insn;
pub mod module;
pub mod pagemap;
pub mod pe;
pub mod util;

// helpers that are useful during doctests, tests.
// TODO: restrict this to tests only
pub mod rsrc;
pub mod test;

type VA = u64;
type RVA = u64;
