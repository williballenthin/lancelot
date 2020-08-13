use std::collections::BTreeMap;

use anyhow::Result;
use log::debug;
use smallvec::SmallVec;

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
    pub calls_from: BTreeMap<VA, SmallVec<[VA; 1]>>,

    // instruction membership indexes...
    /// map from function start to the instructions in its CFG that call
    /// elsewhere. lookup via `calls_to` to figoure out the functions that
    /// this function calls.
    pub function_call_instructions: BTreeMap<VA, Vec<VA>>,
    /// map from instruction to starts of functions whose CFGs contain the
    /// instruction (usually one).
    pub call_instruction_functions: BTreeMap<VA, SmallVec<[VA; 1]>>,
}

pub fn build_call_graph(module: &Module, cfgs: &BTreeMap<VA, cfg::CFG>) -> Result<CallGraph> {
    debug!("call graph");

    let mut cg: CallGraph = Default::default();
    let decoder = dis::get_disassembler(module)?;

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
                        for flow in cfg::get_call_insn_flow(module, va, &insn)?.iter() {
                            if let cfg::Flow::Call(target) = *flow {
                                cg.calls_from.entry(va).or_default().push(target);
                                cg.calls_to.entry(target).or_default().push(va);
                                cg.function_call_instructions.entry(function).or_default().push(va);
                                cg.call_instruction_functions.entry(va).or_default().push(function);
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
    use std::collections::BTreeMap;

    #[test]
    fn k32() -> Result<()> {
        let buf = get_buf(Rsrc::K32);
        let pe = crate::loader::pe::PE::from_bytes(&buf)?;

        let mut cfgs: BTreeMap<VA, CFG> = Default::default();
        for &function in pe::find_function_starts(&pe)?.iter() {
            if let Ok(cfg) = crate::analysis::cfg::build_cfg(&pe.module, function) {
                cfgs.insert(function, cfg);
            }
        }

        let cg = call_graph::build_call_graph(&pe.module, &cfgs)?;

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

        Ok(())
    }
}
