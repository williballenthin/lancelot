extern crate log;
extern crate simplelog;

// enabled only during testing.
// supports reaching into the resources dir for test data.
// TODO: doesn't work nicely work vscode-rls (which doesn't pass along the features=test)
// #[cfg(feature = "test")]
//pub mod rsrc;

//pub mod analysis;

pub mod arch;
pub mod util;
pub mod xref;
pub mod loader;
pub mod flowmeta;
pub mod analysis;
pub mod workspace;
