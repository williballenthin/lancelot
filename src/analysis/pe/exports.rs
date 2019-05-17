use num::{FromPrimitive};
use std::marker::PhantomData;

use log::{debug};
use goblin::{Object};
use failure::{Error};

use super::super::super::arch::Arch;
use super::super::super::workspace::Workspace;
use super::super::{Analyzer, AnalysisError};


pub struct ExportsAnalyzer<A: Arch> {
    // This Analyzer must have a type parameter for it
    //  to implement Analyzer<A>.
    // however, it doesn't actually use this type itself.
    // so, we use a phantom data marker which has zero type,
    //  to ensure there is not an unused type parameter,
    //  which is a compile error.
    _phantom: PhantomData<A>,
}

impl<A: Arch> ExportsAnalyzer<A> {
    pub fn new() -> ExportsAnalyzer<A> {
        ExportsAnalyzer {
            _phantom: PhantomData {},
        }
    }
}

impl<A: Arch + 'static> Analyzer<A> for ExportsAnalyzer<A> {
    fn get_name(&self) -> String {
        "PE exports analyzer".to_string()
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

        let exports: Vec<usize> = pe.exports.iter()
            // re-exports are simply strings that point to a `DLL.export_name` ASCII string.
            // therefore, they're not functions/code.
            .filter(|exp| exp.reexport.is_none())
            .map(|exp| exp.rva).collect();

        let symbols: Vec<(usize, String)> = pe.exports.iter()
            .filter(|exp| exp.name.is_some())
            .map(|exp| (exp.rva, exp.name.unwrap().to_string()))
            .collect();

        for (rva, name) in symbols.iter() {
            let rva = match A::RVA::from_usize(*rva) {
                Some(rva) => rva,
                // we panic here because some work is done, but not all.
                // alternatively, we could warn.
                // but i'd like to bail early and figure out why this can happen.
                None => panic!("failed to convert RVA")
            };

            debug!("export: {:#x}: {}", rva, name);

            ws.make_symbol(rva, name)?;
            ws.analyze()?;
        }

        for rva in exports.iter() {
            let rva = match A::RVA::from_usize(*rva) {
                Some(rva) => rva,
                None => panic!("failed to convert RVA")
            };

            ws.make_function(rva)?;
            ws.analyze()?;
        }

        Ok(())
    }
}
