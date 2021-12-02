use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;
use log::debug;

use crate::{
    analysis::{cfg, dis},
    aspace::AddressSpace,
    module::Module,
    RVA, VA,
};

#[derive(Default)]
pub struct CallGraph {
    // call instruction indexes...
    /// map from function start to the addresses that call here.
    /// lookup via `call_instruction_functions` to figure out the functions that
    /// call here.
    pub calls_to:   BTreeMap<VA, Vec<VA>>,
    /// map from an instruction to the addresses that it calls (usually one).
    pub calls_from: BTreeMap<VA, Vec<VA>>,

    // instruction membership indexes...
    /// map from function start to the instructions in its CFG that call
    /// elsewhere. lookup via `calls_to` to figoure out the functions that
    /// this function calls.
    pub function_call_instructions: BTreeMap<VA, Vec<VA>>,
    /// map from instruction to starts of functions whose CFGs contain the
    /// instruction (usually one).
    pub call_instruction_functions: BTreeMap<VA, Vec<VA>>,
}

pub fn get_call_import_xref(imports: &BTreeSet<VA>, va: VA, insn: &zydis::DecodedInstruction) -> Option<VA> {
    assert!(matches!(insn.mnemonic, zydis::enums::Mnemonic::CALL));

    // calls always have a first operand
    let op = crate::analysis::dis::get_first_operand(insn).unwrap();

    if !matches!(op.ty, zydis::OperandType::MEMORY) {
        // doesn't look like `call [...]`
        return None;
    }

    if let Ok(Some(ptr)) = crate::analysis::dis::get_memory_operand_ptr(va, insn, op) {
        if imports.contains(&ptr) {
            Some(ptr)
        } else {
            None
        }
    } else {
        None
    }
}

// provide `imports` if you've done analysis of the module to find
// the pointers used in the import table.
// when provided, will extract the call edges to the import pointers.
// otherwise, the call to/from import edges won't be indexed.
pub fn build_call_graph(module: &Module, cfgs: &BTreeMap<VA, cfg::CFG>, imports: &BTreeSet<VA>) -> Result<CallGraph> {
    debug!("call graph");

    let mut cg: CallGraph = Default::default();
    let decoder = dis::get_disassembler(module)?;

    for &import in imports.iter() {
        cg.calls_to.entry(import).or_default();
    }

    for (&function, cfg) in cfgs.iter() {
        debug!("call graph: {:#x}", function);

        // ensure there are at least (empty) entries for all the keys in `functions`
        cg.function_call_instructions.entry(function).or_default();
        cg.calls_to.entry(function).or_default();

        for basic_block in cfg.basic_blocks.values() {
            let buf = module
                .address_space
                .read_bytes(basic_block.address, basic_block.length as usize)?;

            for (offset, insn) in dis::linear_disassemble(&decoder, &buf) {
                if let Ok(Some(insn)) = insn {
                    if matches!(insn.mnemonic, zydis::enums::Mnemonic::CALL) {
                        let va = basic_block.address + offset as RVA;
                        cg.function_call_instructions.entry(function).or_default().push(va);
                        cg.call_instruction_functions.entry(va).or_default().push(function);

                        if let Some(import) = get_call_import_xref(imports, va, &insn) {
                            cg.calls_from.entry(va).or_default().push(import);
                            cg.calls_to.entry(import).or_default().push(va);
                        } else {
                            for flow in cfg::get_call_insn_flow(module, va, &insn)?.iter() {
                                if let cfg::Flow::Call(target) = *flow {
                                    cg.calls_from.entry(va).or_default().push(target);
                                    cg.calls_to.entry(target).or_default().push(va);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(cg)
}

#[cfg(test)]
mod tests {
    use crate::{
        analysis::{call_graph, cfg::CFG, pe},
        rsrc::*,
        VA,
    };
    use anyhow::Result;
    use std::collections::{BTreeMap, BTreeSet};

    #[test]
    fn k32() -> Result<()> {
        let buf = get_buf(Rsrc::K32);
        let pe = crate::loader::pe::PE::from_bytes(&buf)?;
        let imports: BTreeSet<VA> = crate::analysis::pe::get_imports(&pe)?.keys().cloned().collect();

        let mut cfgs: BTreeMap<VA, CFG> = Default::default();
        for &function in pe::find_function_starts(&pe)?.iter() {
            if let Ok(cfg) = crate::analysis::cfg::build_cfg(&pe.module, function) {
                cfgs.insert(function, cfg);
            }
        }

        let cg = call_graph::build_call_graph(&pe.module, &cfgs, &imports)?;

        assert_eq!(cg.calls_to[&0x180001068].len(), 2);
        assert!(cg.calls_to[&0x180001068].iter().find(|&&v| v == 0x18000F775).is_some());
        assert!(cg.calls_to[&0x180001068].iter().find(|&&v| v == 0x180060504).is_some());
        assert!(cg.calls_from[&0x180060504]
            .iter()
            .find(|&&v| v == 0x180001068)
            .is_some());
        assert!(cg.call_instruction_functions[&0x180060504]
            .iter()
            .find(|&&v| v == 0x1800602C0)
            .is_some());
        assert!(cg.function_call_instructions[&0x1800602C0]
            .iter()
            .find(|&&v| v == 0x180060504)
            .is_some());

        // ```
        // .text:00000001800134D0 sub_1800134D0 proc near
        // .text:...
        // .text:00000001800134D4 call    cs:KernelBaseGetGlobalData
        // ```
        //
        // this should result in a call flow to IAT entry 0x1800773F0
        #[allow(non_snake_case)]
        let KernelBaseGetGlobalData = 0x1800773F0;
        assert!(cg.function_call_instructions[&0x1800134D0]
            .iter()
            .find(|&&v| v == 0x1800134D4)
            .is_some());
        assert!(cg.calls_from[&0x1800134D4]
            .iter()
            .find(|&&v| v == KernelBaseGetGlobalData)
            .is_some());
        assert!(cg.calls_to[&KernelBaseGetGlobalData]
            .iter()
            .find(|&&v| v == 0x1800134D4)
            .is_some());

        Ok(())
    }

    #[test]
    fn mimi() -> Result<()> {
        let buf = get_buf(Rsrc::MIMI);
        let pe = crate::loader::pe::PE::from_bytes(&buf)?;
        let imports: BTreeSet<VA> = crate::analysis::pe::get_imports(&pe)?.keys().cloned().collect();

        let mut cfgs: BTreeMap<VA, CFG> = Default::default();
        for &function in pe::find_function_starts(&pe)?.iter() {
            if let Ok(cfg) = crate::analysis::cfg::build_cfg(&pe.module, function) {
                cfgs.insert(function, cfg);
            }
        }

        let cg = call_graph::build_call_graph(&pe.module, &cfgs, &imports)?;

        assert!(cg.function_call_instructions.get(&0x45CC62).is_some());
        assert!(cg.function_call_instructions.get(&0x45D028).is_some());
        assert!(cg.function_call_instructions.get(&0x45D16A).is_some());

        assert_eq!(cg.calls_to[&0x40B1F1].len(), 3);

        assert!(cg.calls_to[&0x40B1F1].iter().find(|&&v| v == 0x45CC9D).is_some());
        assert!(cg.calls_to[&0x40B1F1].iter().find(|&&v| v == 0x45D080).is_some());
        assert!(cg.calls_to[&0x40B1F1].iter().find(|&&v| v == 0x45D1B7).is_some());

        Ok(())
    }
}
