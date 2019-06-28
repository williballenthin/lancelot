/// search for instructions with no predecessors (code xrefs to or fallthrough to).
/// assume these are the start of functions.
/// example: RUNTIME_FUNCTION always references code, but not always the start of a function.
/// catch that case here.
///
/// this should be the final analyzer pass.
use std::collections::HashSet;

use log::{debug};
use failure::{Error};

use super::super::arch::{RVA};
use super::super::workspace::Workspace;
use super::{Analyzer};


pub struct OrphanFunctionAnalyzer {}

impl OrphanFunctionAnalyzer {
    pub fn new() -> OrphanFunctionAnalyzer {
        OrphanFunctionAnalyzer {}
    }
}

impl Analyzer for OrphanFunctionAnalyzer {
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
    /// let mut ws = Workspace::from_bytes("k32.dll", &get_buf(Rsrc::K32))
    ///    .disable_analysis()
    ///    .load().unwrap();
    ///
    /// RuntimeFunctionAnalyzer::new().analyze(&mut ws).unwrap();
    /// OrphanFunctionAnalyzer::new().analyze(&mut ws).unwrap();
    ///
    /// // this function is the impl of the export `GetApplicationRestartSettingsWorker`.
    /// // the exported symbol simply JMP to this function.
    /// // there is a RUNTIME_FUNCTION for this func, but not for the export.
    /// assert!(ws.get_meta(RVA(0x645A4)).unwrap().is_insn());
    /// assert!(ws.get_functions().find(|&&rva| rva == RVA(0x645A4)).is_some());
    ///
    /// //  .text:0000000180001010     mov     r11, rsp
    /// //  .text:0000000180001013     sub     rsp, 48h
    /// //  .text:0000000180001017     mov     rax, [rsp+48h+ContextPointers]
    /// assert!(ws.get_functions().find(|&&rva| rva == RVA(0x1010)).is_some());
    /// assert!(ws.get_functions().find(|&&rva| rva == RVA(0x1013)).is_none());
    ///
    /// // this is a function referenced only as a function argument.
    /// assert!(ws.get_functions().find(|&&rva| rva == RVA(0x1aa0)).is_some());
    /// ```
    fn analyze(&self, ws: &mut Workspace) -> Result<(), Error> {
        let existing_functions: HashSet<&RVA> = ws.get_functions().collect();
        let mut orphans: Vec<RVA> = vec![];

        for (i, section) in ws.module.sections.iter().enumerate() {
            orphans.extend(ws.analysis.flow.meta[i].iter()
                .enumerate()
                .filter(|(_, meta)| meta.is_insn())
                .filter(|(_, meta)| !meta.has_xrefs_to())
                .filter(|(_, meta)| !meta.does_other_fallthrough_to())
                .map(|(j, _)| section.addr + RVA::from(j))
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
