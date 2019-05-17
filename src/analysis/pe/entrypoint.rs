use num::{FromPrimitive};
use std::marker::PhantomData;

use log::{debug};
use goblin::{Object};
use failure::{Error};

use super::super::super::arch::Arch;
use super::super::super::workspace::Workspace;
use super::super::{Analyzer, AnalysisError};


pub struct EntryPointAnalyzer<A: Arch> {
    // This Analyzer must have a type parameter for it
    //  to implement Analyzer<A>.
    // however, it doesn't actually use this type itself.
    // so, we use a phantom data marker which has zero type,
    //  to ensure there is not an unused type parameter,
    //  which is a compile error.
    _phantom: PhantomData<A>,
}

impl<A: Arch> EntryPointAnalyzer<A> {
    pub fn new() -> EntryPointAnalyzer<A> {
        EntryPointAnalyzer {
            _phantom: PhantomData {},
        }
    }
}

impl<A: Arch + 'static> Analyzer<A> for EntryPointAnalyzer<A> {
    fn get_name(&self) -> String {
        "PE entry point analyzer".to_string()
    }

    fn analyze(&self, ws: &mut Workspace<A>) -> Result<(), Error> {
        let pe = match Object::parse(&ws.buf) {
            Ok(Object::PE(pe)) => pe,
            _ => panic!("can't analyze unexpected format"),
        };

        let entry = match A::RVA::from_usize(pe.entry) {
            Some(entry) => entry,
            None => return Err(AnalysisError::NotSupported.into()),
        };

        debug!("entry point: {:#x}", entry);

        ws.make_symbol(entry, "entry")?;
        ws.make_function(entry)?;
        ws.analyze()?;

        Ok(())
    }
}
