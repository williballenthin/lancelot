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

const EMPTY_CONTEXT: zydis::ffi::RegisterContext = zydis::ffi::RegisterContext { values: [0u64; 257] };

/// make a best guess for the reference target, found at `ref_offset` from `va`.
///
/// flirt uses references `(offset, name)` to describe that a function contains
/// a pointer to some known name (usually also matched by flirt).
/// the offset is relative to the start of the function, and may point in the
/// middle of an instruction!
/// (this is probably an artifact of extracting via relocations in lib files.)
///
/// its a problem because we don't know where the instruction,
/// so its hard to inspect operands for pointers.
/// we could either disassemble the entire function and find instruction ranges,
/// or scan backwards looking for potential instructions.
/// we do the latter here, as it works well in practice.
///
/// from the given address `ref_offset`, we disassemble backwards, up to -4
/// bytes. at each location, we inspect the operands. if it could be a pointer,
/// then we use metadata provided by zydis for the offset of the operand data.
/// (this is a great feature of zydis!)
/// the offset of the operand pointer data should match the number of bytes
/// we've disassembled backwards, that is, the pointer is found at the
/// reference address.
///
/// in practice, many references look like `call FOO` which is `E8 ?? ?? ?? ??`
/// and we recover the reference on the first try.
fn guess_reference_target(
    module: &Module,
    decoder: &zydis::Decoder,
    va: VA,
    ref_offset: u64,
    perms: Permissions,
) -> Option<VA> {
    // scan from -1 to -4 bytes backwards from the reference
    for i in (1..=4u64).rev() {
        let candidate_insn_va = va + ref_offset - i;
        let mut insn_buf = [0u8; 16];

        if module.address_space.read_into(candidate_insn_va, &mut insn_buf).is_ok() {
            if let Ok(Some(insn)) = decoder.decode(&insn_buf) {
                // we assume the pointer will be found in the first two explicit operands,
                // which works well for x86.
                for (j, op) in dis::get_operands(&insn).take(2).enumerate() {
                    match op.ty {
                        zydis::OperandType::MEMORY => {
                            if (op.mem.base == zydis::Register::NONE || op.mem.base == zydis::Register::RIP)
                                && op.mem.disp.has_displacement
                                && insn.raw.disp_offset == i as u8
                            {
                                if let Ok(target) = insn.calc_absolute_address_ex(candidate_insn_va, op, &EMPTY_CONTEXT)
                                {
                                    if module.probe_va(target, perms) {
                                        return Some(target);
                                    }
                                }
                            }
                            continue;
                        }
                        zydis::OperandType::IMMEDIATE => {
                            if insn.raw.imm[j].offset == i as u8 {
                                if let Ok(target) = insn.calc_absolute_address(candidate_insn_va, op) {
                                    if module.probe_va(target, perms) {
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

/// match the given flirt signatures at the given address.
/// returns a list of the signatures that match.
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

                        if wanted_name == "." {
                            // special case: name "." matches any data?
                            // not exactly sure if this should only match special data `ctype`?
                            // see: https://github.com/williballenthin/lancelot/issues/112#issuecomment-802379966
                            if guess_reference_target(module, decoder, va, *offset as u64, Permissions::R).is_some() {
                                continue;
                            } else {
                                does_match_references = false;
                                break;
                            }
                        }

                        // guess the reference target, then match flirt signatures there,
                        // and see if the wanted name matches a name recovered by flirt.
                        //
                        // we use the cache to record whether a negative match was encountered.
                        // this drastically when we have many nested references (like CALL wrappers).
                        // see: https://github.com/fireeye/capa/issues/448
                        if let Some(target) =
                            guess_reference_target(module, decoder, va, *offset as u64, Permissions::X)
                        {
                            // this is just:
                            //   target_sigs = cached(match_flirt_inner(...target...))
                            //
                            // can't use entry API because of mutable cache used to create cache entry.
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
                                        })
                                        | Symbol::Public(Name {
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
