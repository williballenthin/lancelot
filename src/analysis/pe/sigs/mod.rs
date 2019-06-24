/// scan for known byte signatures that identify constructs such as functions.
///
/// uses the Ghidra signature definitions from here:
///  - https://github.com/NationalSecurityAgency/ghidra/tree/79d8f164f8bb8b15cfb60c5d4faeb8e1c25d15ca/Ghidra/Processors/x86/data/patterns

use num::{FromPrimitive};
use std::marker::PhantomData;
use std::collections::HashSet;

use log::{debug};
use failure::{Error};
use rust_embed::{RustEmbed};

use super::super::super::arch::Arch;
use super::super::super::workspace::Workspace;
use super::super::{Analyzer};

#[derive(RustEmbed)]
#[folder = "src/analysis/pe/sigs/patterns"]
struct Patterns;

pub struct ByteSigAnalyzer<A: Arch> {
    // This Analyzer must have a type parameter for it
    //  to implement Analyzer<A>.
    // however, it doesn't actually use this type itself.
    // so, we use a phantom data marker which has zero type,
    //  to ensure there is not an unused type parameter,
    //  which is a compile error.
    _phantom: PhantomData<A>,
}

impl<A: Arch> ByteSigAnalyzer<A> {
    pub fn new() -> ByteSigAnalyzer<A> {
        let constraints = Patterns::get("patternconstraints.xml").unwrap();

        ByteSigAnalyzer {
            _phantom: PhantomData {},
        }
    }
}

impl<A: Arch + 'static> Analyzer<A> for ByteSigAnalyzer<A> {
    fn get_name(&self) -> String {
        "byte signature analyzer".to_string()
    }

    /// ```
    /// use lancelot::rsrc::*;
    /// use lancelot::arch::*;
    /// use lancelot::analysis::Analyzer;
    /// use lancelot::workspace::Workspace;
    /// use lancelot::analysis::pe::ByteSigAnalyzer;
    ///
    /// let mut ws = Workspace::<Arch64>::from_bytes("k32.dll", &get_buf(Rsrc::K32))
    ///    .disable_analysis()
    ///    .load().unwrap();
    ///
    /// ByteSigAnalyzer::<Arch64>::new().analyze(&mut ws).unwrap();
    /// ```
    fn analyze(&self, ws: &mut Workspace<A>) -> Result<(), Error> {
        let existing_functions: HashSet<&A::RVA> = ws.get_functions().collect();
        let mut orphans: Vec<A::RVA> = vec![];

        for (i, section) in ws.module.sections.iter().enumerate() {
            orphans.extend(ws.analysis.flow.meta[i].iter()
                .enumerate()
                .filter(|(_, meta)| meta.is_insn())
                .filter(|(_, meta)| !meta.has_xrefs_to())
                .filter(|(_, meta)| !meta.does_other_fallthrough_to())
                .map(|(j, _)| section.addr + A::RVA::from_usize(j).unwrap())
                .filter(|rva| !existing_functions.contains(rva)))
        }

        for rva in orphans.iter() {
            debug!("orphan function: {:#x}", rva);
            ws.make_function(*rva)?;
            ws.analyze()?;
        }

        Ok(())
    }
}
