use std::collections::BTreeMap;

use anyhow::Result;
use log::debug;

use crate::{
    analysis::dis,
    aspace::AddressSpace,
    module::{Module, Permissions},
    VA,
};
use lancelot_flirt::*;

/// make a best guess as to the reference target, found at `ref_offset` from
/// `va`.
fn get_ref(module: &Module, decoder: &zydis::Decoder, va: VA, ref_offset: u64) -> Option<VA> {
    for i in (1..=4u64).rev() {
        let candidate_insn_va = va + ref_offset - i;
        let mut insn_buf = [0u8; 16];

        if module.address_space.read_into(candidate_insn_va, &mut insn_buf).is_ok() {
            if let Ok(Some(insn)) = decoder.decode(&insn_buf) {
                let explicit_operands = insn
                    .operands
                    .iter()
                    .filter(|op| matches!(op.visibility, zydis::OperandVisibility::EXPLICIT));
                for (j, op) in explicit_operands.take(2).enumerate() {
                    match op.ty {
                        zydis::OperandType::MEMORY => {
                            if (op.mem.base == zydis::Register::NONE || op.mem.base == zydis::Register::RIP)
                                && op.mem.index == zydis::Register::NONE
                                && op.mem.scale == 0
                                && op.mem.disp.has_displacement
                                && insn.raw.disp_offset == i as u8
                            {
                                if let Ok(target) = insn.calc_absolute_address(candidate_insn_va, op) {
                                    if module.probe_va(target, Permissions::RX) {
                                        return Some(target);
                                    }
                                }
                            }
                            continue;
                        }
                        zydis::OperandType::IMMEDIATE => {
                            if insn.raw.imm[j].offset == i as u8 {
                                if let Ok(target) = insn.calc_absolute_address(candidate_insn_va, op) {
                                    if module.probe_va(target, Permissions::RX) {
                                        return Some(target);
                                    }
                                }
                            }
                            continue;
                        }
                        zydis::OperandType::POINTER => continue,
                        zydis::OperandType::REGISTER => continue,
                        zydis::OperandType::UNUSED => continue,
                    }
                }
            }
        }
    }

    None
}

pub fn match_flirt(module: &Module, sigs: &FlirtSignatureSet, va: VA) -> Result<Vec<FlirtSignature>> {
    fn match_flirt_inner(
        module: &Module,
        sigs: &FlirtSignatureSet,
        decoder: &zydis::Decoder,
        va: VA,
        cache: &mut BTreeMap<VA, Vec<FlirtSignature>>,
    ) -> Result<Vec<FlirtSignature>> {
        let sec = module
            .sections
            .iter()
            .find(|sec| sec.virtual_range.start <= va && va < sec.virtual_range.end)
            .unwrap();

        let size = sec.virtual_range.end - va;
        let buf = module.address_space.read_bytes(va, size as usize)?;

        debug!("flirt: matching: {:#x}", va);

        Ok(sigs
            .r#match(&buf)
            .iter()
            .filter(|sig| {
                let mut does_match_references = true;

                debug!("flirt: {:#x}: candidate: {:?}", va, sig);

                'names: for name in sig.names.iter() {
                    if let Symbol::Reference(Name {
                        offset,
                        name: wanted_name,
                    }) = name
                    {
                        // i dont know what this means.
                        assert!(*offset >= 0, "negative offset");

                        if let Some(target) = get_ref(module, &decoder, va, *offset as u64) {
                            // TODO: special case "."

                            // can't use entry because of mutable cache used to create cache entry.
                            #[allow(clippy::map_entry)]
                            if !cache.contains_key(&target) {
                                let target_sigs = match_flirt_inner(module, sigs, decoder, target, cache)
                                    .unwrap_or_else(|_| Default::default());
                                cache.insert(target, target_sigs);
                            }

                            let target_sigs = cache.get(&target).unwrap();

                            let mut does_name_match = false;
                            'sigs: for target_sig in target_sigs.iter() {
                                debug!("flirt: {:#x}: found reference: {:?} @ {:#x}", va, target_sig, offset);
                                for name in target_sig.names.iter() {
                                    match name {
                                        Symbol::Reference(_) => continue,
                                        Symbol::Local(Name {
                                            name: target_name,
                                            offset,
                                        }) => {
                                            if *offset == 0 && target_name == wanted_name {
                                                does_name_match = true;
                                                break 'sigs;
                                            }
                                        }
                                        Symbol::Public(Name {
                                            name: target_name,
                                            offset,
                                        }) => {
                                            if *offset == 0 && target_name == wanted_name {
                                                does_name_match = true;
                                                break 'sigs;
                                            }
                                        }
                                    }
                                }
                            }

                            if !does_name_match {
                                does_match_references = false;
                                break 'names;
                            }
                        } else {
                            does_match_references = false;
                            break;
                        }
                    }
                }

                does_match_references
            })
            .cloned()
            .cloned()
            .collect::<Vec<_>>())
    }

    let decoder = dis::get_disassembler(module)?;
    let mut cache = Default::default();
    match_flirt_inner(module, sigs, &decoder, va, &mut cache)
}
