#![allow(clippy::upper_case_acronyms)]
// for thiserror derive macros
#![feature(error_generic_member_access)]

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
pub mod workspace;

#[cfg(any(test, doctest, feature = "test"))]
pub mod rsrc;
#[cfg(any(test, doctest, feature = "test"))]
pub mod test;

pub type VA = u64;
pub type RVA = u64;
