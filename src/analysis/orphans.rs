/// search for instructions with no predecessors (code xrefs to or fallthrough to).
/// assume these are the start of functions.
/// example: RUNTIME_FUNCTION always references code, but not always the start of a function.
/// catch that case here.
///
/// this should be the final analyzer pass.

use num::{FromPrimitive};
use std::marker::PhantomData;
use std::collections::HashSet;

use log::{debug};
use failure::{Error};

use super::super::arch::Arch;
use super::super::workspace::Workspace;
use super::{Analyzer};


pub struct OrphanFunctionAnalyzer<A: Arch> {
    // This Analyzer must have a type parameter for it
    //  to implement Analyzer<A>.
    // however, it doesn't actually use this type itself.
    // so, we use a phantom data marker which has zero type,
    //  to ensure there is not an unused type parameter,
    //  which is a compile error.
    _phantom: PhantomData<A>,
}

impl<A: Arch> OrphanFunctionAnalyzer<A> {
    pub fn new() -> OrphanFunctionAnalyzer<A> {
        OrphanFunctionAnalyzer {
            _phantom: PhantomData {},
        }
    }
}

impl<A: Arch + 'static> Analyzer<A> for OrphanFunctionAnalyzer<A> {
    fn get_name(&self) -> String {
        "orphan function analyzer".to_string()
    }

    /// ```
    /// use lancelot::rsrc::*;
    /// use lancelot::arch::*;
    /// use lancelot::analysis::Analyzer;
    /// use lancelot::workspace::Workspace;
    /// use lancelot::analysis::pe::RuntimeFunctionAnalyzer;
    /// use lancelot::analysis::OrphanFunctionAnalyzer;
    ///
    /// let mut ws = Workspace::<Arch64>::from_bytes("k32.dll", &get_buf(Rsrc::K32))
    ///    .disable_analysis()
    ///    .load().unwrap();
    ///
    /// RuntimeFunctionAnalyzer::<Arch64>::new().analyze(&mut ws).unwrap();
    /// OrphanFunctionAnalyzer::<Arch64>::new().analyze(&mut ws).unwrap();
    ///
    /// // this function is the impl of the export `GetApplicationRestartSettingsWorker`.
    /// // the exported symbol simply JMP to this function.
    /// // there is a RUNTIME_FUNCTION for this func, but not for the export.
    /// assert!(ws.get_meta(0x645A4).unwrap().is_insn());
    /// assert!(ws.get_functions().find(|&&rva| rva == 0x645A4).is_some());
    ///
    /// //  .text:0000000180001010     mov     r11, rsp
    /// //  .text:0000000180001013     sub     rsp, 48h
    /// //  .text:0000000180001017     mov     rax, [rsp+48h+ContextPointers]
    /// assert!(ws.get_functions().find(|&&rva| rva == 0x1010).is_some());
    /// assert!(ws.get_functions().find(|&&rva| rva == 0x1013).is_none());
    ///
    /// // this is a function referenced only as a function argument.
    /// assert!(ws.get_functions().find(|&&rva| rva == 0x1aa0).is_some());
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
