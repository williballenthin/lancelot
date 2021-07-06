#![allow(clippy::upper_case_acronyms)]

extern crate bitflags;
#[macro_use]
extern crate lazy_static;
extern crate log;

pub mod analysis;
pub mod arch;
pub mod aspace;
pub mod config;
#[cfg(feature = "emulator")]
pub mod emu;
pub mod loader;
pub mod module;
pub mod pagemap;
pub mod util;

#[cfg(any(test, doctest, feature = "test"))]
pub mod rsrc;
#[cfg(all(any(test, doctest, feature = "test"), feature = "emulator"))]
pub mod test;

pub type VA = u64;
pub type RVA = u64;
