use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Not,
};

use anyhow::Result;
use bitflags::bitflags;

use crate::{
    analysis::{
        cfg::{flow::Flow, InstructionIndex, CFG},
        pe::{Import, ImportedSymbol},
    },
    loader::pe::PE,
    VA,
};

pub mod formatter;

bitflags! {
    pub struct FunctionFlags: u8 {
        const NORET = 0b0000_0001;
        const THUNK = 0b0000_0010;
    }
}

pub struct FunctionAnalysis {
    pub flags: FunctionFlags,
}

#[derive(Default)]
pub struct NameIndex {
    pub names_by_address:  BTreeMap<VA, String>,
    pub addresses_by_name: BTreeMap<String, VA>,
}

impl NameIndex {
    pub fn insert(&mut self, va: VA, name: String) {
        self.names_by_address.insert(va, name.clone());
        self.addresses_by_name.insert(name, va);
    }

    pub fn contains_address(&self, va: VA) -> bool {
        return self.names_by_address.get(&va).is_some();
    }

    pub fn contains_name(&self, name: &str) -> bool {
        return self.addresses_by_name.get(name).is_some();
    }
}

pub struct WorkspaceAnalysis {
    // derived from:
    //   - file format analysis passes
    //   - cfg flow analysis (call insns)
    //   - manual actions
    pub functions: BTreeMap<VA, FunctionAnalysis>,

    // derived from:
    //   - file format analysis pass: pe::get_improts()
    pub imports: BTreeMap<VA, Import>,

    // derived from:
    //  - user names
    //  - export names
    //  - imported symbols
    //  - flirt sigs
    pub names: NameIndex,
}

pub struct PEWorkspace {
    pub pe:       PE,
    pub cfg:      CFG,
    pub analysis: WorkspaceAnalysis,
}

impl PEWorkspace {
    pub fn from_pe(pe: PE) -> Result<PEWorkspace> {
        let mut insns: InstructionIndex = Default::default();

        let mut function_starts: BTreeSet<VA> = Default::default();
        function_starts.extend(crate::analysis::pe::entrypoints::find_pe_entrypoint(&pe)?);
        function_starts.extend(crate::analysis::pe::exports::find_pe_exports(&pe)?);
        function_starts.extend(crate::analysis::pe::safeseh::find_pe_safeseh_handlers(&pe)?);
        function_starts.extend(crate::analysis::pe::runtime_functions::find_pe_runtime_functions(&pe)?);
        function_starts.extend(crate::analysis::pe::control_flow_guard::find_pe_cfguard_functions(&pe)?);

        // heuristics:
        // function_starts.extend(crate::analysis::pe::call_targets::
        // find_pe_call_targets(pe)?); function_starts.extend(crate::analysis::
        // pe::patterns::find_function_prologues(pe)?); function_starts.
        // extend(crate::analysis::pe::pointers::
        // find_pe_nonrelocated_executable_pointers(pe)?; TODO: only do the
        // above searches in unrecovered regions.

        for &function in function_starts.iter() {
            insns.build_index(&pe.module, function)?;
        }
        let mut cfg = CFG::from_instructions(&pe.module, insns)?;

        let noret = crate::analysis::pe::noret_imports::cfg_prune_noret_imports(&pe, &mut cfg)?;

        let mut function_starts = function_starts
            .into_iter()
            .filter(|va| cfg.insns.insns_by_address.contains_key(va))
            .collect::<BTreeSet<VA>>();
        let call_targets = cfg
            .basic_blocks
            .blocks_by_address
            .keys()
            .cloned()
            .filter(|bb| {
                cfg.flows.flows_by_dst[bb]
                    .iter()
                    .any(|flow| matches!(flow, Flow::Call(_)))
            })
            .collect::<BTreeSet<VA>>();
        function_starts.extend(call_targets);

        let imports = crate::analysis::pe::get_imports(&pe)?;

        let mut names: NameIndex = Default::default();
        for import in imports.values() {
            let name = match &import.symbol {
                ImportedSymbol::Name(name) => format!("{}!{}", import.dll, name),
                ImportedSymbol::Ordinal(ordinal) => format!("{}!#{}", import.dll, ordinal),
            };

            names.insert(import.address, name);
        }

        let thunks = crate::analysis::cfg::thunk::find_thunks(&cfg, function_starts.iter());

        let mut functions: BTreeMap<VA, FunctionAnalysis> = Default::default();
        for va in function_starts {
            let mut flags = FunctionFlags::empty();

            if noret.contains(&va) {
                flags.set(FunctionFlags::NORET, true);
            }

            if thunks.contains(&va) {
                flags.set(FunctionFlags::THUNK, true);
            }

            functions.insert(va, FunctionAnalysis { flags });
        }

        for &function in functions.keys() {
            if names.contains_address(function).not() {
                names.insert(function, format!("sub_{:x}", function));
            }
        }

        Ok(PEWorkspace {
            pe,
            cfg,
            analysis: WorkspaceAnalysis {
                functions,
                imports,
                names,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rsrc::*;
    use anyhow::Result;

    #[test]
    fn nop() -> Result<()> {
        let buf = get_buf(Rsrc::NOP);
        let pe = crate::loader::pe::PE::from_bytes(&buf)?;

        let ws = PEWorkspace::from_pe(pe)?;

        // entry point
        assert!(ws.analysis.functions.contains_key(&0x401081));

        // main
        assert!(ws.analysis.functions.contains_key(&0x401000));

        assert!(ws.analysis.imports.contains_key(&0x40600C));
        assert!(ws
            .analysis
            .names
            .contains_name(&String::from("kernel32.dll!ExitProcess")));
        assert!(ws.analysis.names.contains_address(0x40600C));

        // 0x401C4E: void __cdecl __noreturn __crtExitProcess(UINT uExitCode)
        assert!(ws.analysis.functions[&0x401C4E].flags.intersects(FunctionFlags::NORET));

        // ```
        //     .text:00405F42  ; void __stdcall RtlUnwind(PVOID TargetFrame, PVOID TargetIp, PEXCEPTION_RECORD ExceptionRecord, PVOID ReturnValue)
        //     .text:00405F42  RtlUnwind       proc near               ; CODE XREF: __global_unwind2+13↑p
        //     .text:00405F42
        //     .text:00405F42  TargetFrame     = dword ptr  4
        //     .text:00405F42  TargetIp        = dword ptr  8
        //     .text:00405F42  ExceptionRecord = dword ptr  0Ch
        //     .text:00405F42  ReturnValue     = dword ptr  10h
        //     .text:00405F42
        //     .text:00405F42 000 FF 25 7C 60 40 00  jmp     ds:__imp_RtlUnwind
        //     .text:00405F42  RtlUnwind       endp
        // ```
        assert!(ws.analysis.functions[&0x405F42].flags.intersects(FunctionFlags::THUNK));

        use crate::analysis::dis::zydis;
        let formatter = zydis::Formatter::new(zydis::FormatterStyle::INTEL).unwrap();

        let mut buffer = [0u8; 200];
        let insn = crate::test::read_insn(&ws.pe.module, 0x401000);

        let tokens = formatter.tokenize_instruction(&insn, &mut buffer, Some(0x401000), None)?;

        for (token, s) in tokens {
            println!("{}\t{}", s, token);
        }

        assert!(false);

        Ok(())
    }
}
