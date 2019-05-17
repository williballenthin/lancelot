use num::{FromPrimitive};
use std::marker::PhantomData;

use log::{debug};
use goblin::{Object};
use failure::{Error};

use super::super::super::arch::Arch;
use super::super::super::workspace::Workspace;
use super::super::{Analyzer, AnalysisError};


pub struct ImportsAnalyzer<A: Arch> {
    // This Analyzer must have a type parameter for it
    //  to implement Analyzer<A>.
    // however, it doesn't actually use this type itself.
    // so, we use a phantom data marker which has zero type,
    //  to ensure there is not an unused type parameter,
    //  which is a compile error.
    _phantom: PhantomData<A>,
}

impl<A: Arch> ImportsAnalyzer<A> {
    pub fn new() -> ImportsAnalyzer<A> {
        ImportsAnalyzer {
            _phantom: PhantomData {},
        }
    }
}

impl<A: Arch + 'static> Analyzer<A> for ImportsAnalyzer<A> {
    fn get_name(&self) -> String {
        "PE imports analyzer".to_string()
    }

    /// ```
    /// use lancelot::rsrc::*;
    /// use lancelot::arch::*;
    /// use lancelot::analysis::Analyzer;
    /// use lancelot::workspace::Workspace;
    /// use lancelot::analysis::pe::ImportsAnalyzer;
    ///
    /// let mut ws = Workspace::<Arch64>::from_bytes("k32.dll", &get_buf(Rsrc::K32))
    ///    .disable_analysis()
    ///    .load().unwrap();
    /// let anal = ImportsAnalyzer::<Arch64>::new();
    /// anal.analyze(&mut ws).unwrap();
    /// // TODO: this currently fails.
    /// assert_eq!(ws.get_symbol(0x78160).unwrap(), "PrivCopyFileExW");
    /// ```
    fn analyze(&self, ws: &mut Workspace<A>) -> Result<(), Error> {
        let pe = match Object::parse(&ws.buf) {
            Ok(Object::PE(pe)) => pe,
            _ => panic!("can't analyze unexpected format"),
        };

        let entry = match A::RVA::from_usize(pe.entry) {
            Some(entry) => entry,
            None => return Err(AnalysisError::NotSupported.into()),
        };

        let symbols: Vec<(usize, String)> = pe.imports.iter()
            .map(|imp| {
                // TODO: what if import is by ordinal?

                /*
                 * TODO: compute FirstThunk address.
                 * its not clear what `imp.rva` or `imp.offset` point to.
                 * unfortunately, its not the FirstThunk entry.
                 * however, i'm not sure if this is a bug expected.
                 *
                 * see: https://github.com/m4b/goblin/issues/161

                println!("import: {}!{} offset: {:#x} rva: {:#x}",
                         imp.dll, &imp.name,
                         imp.offset, imp.rva,
                );
                let name = format!("{}!{}", imp.dll, &imp.name);
                */
                (imp.rva, name)
            })
            .collect();

        for (rva, name) in symbols.iter() {
            let rva = match A::RVA::from_usize(*rva) {
                Some(rva) => rva,
                // we panic here because some work is done, but not all.
                // alternatively, we could warn.
                // but i'd like to bail early and figure out why this can happen.
                None => panic!("failed to convert RVA")
            };

            /*
             * TODO: see note above
            debug!("import: {:#x}: {}", rva, name);
            ws.make_symbol(rva, name)?;
            ws.analyze()?;
            */
        }

        Ok(())
    }
}
