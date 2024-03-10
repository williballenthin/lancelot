//! This is a heuristic that inspects operands to existing instructions
//! for references to likely code.
use std::{collections::BTreeSet, vec};

use anyhow::Result;
use byteorder::ByteOrder;
use log::debug;

use crate::{
    analysis::{
        cfg::{self, read_insn_with_cache, CachingPageReader},
        dis, heuristics,
    },
    aspace::AddressSpace,
    module::{Module, Permissions},
    VA,
};

pub fn find_executable_pointers(module: &Module) -> Result<Vec<VA>> {
    // list of candidates: (address of pointer, address pointed to)
    let mut candidates: Vec<(VA, VA)> = vec![];

    let min_addr = module.address_space.base_address;
    let max_addr = module
        .sections
        .iter()
        .map(|section| section.virtual_range.end)
        .max()
        .unwrap();

    // look for hardcoded pointers into the executable section of the module.
    // note: this often finds jump tables, too. more filtering is below.
    // note: also finds many exception handlers. see filtering below.
    for section in module.sections.iter() {
        let vstart: VA = section.virtual_range.start;
        let vsize = (section.virtual_range.end - section.virtual_range.start) as usize;
        let sec_buf = module.address_space.read_bytes(vstart, vsize)?;

        debug!(
            "code references: scanning section {:#x}-{:#x}",
            section.virtual_range.start, section.virtual_range.end
        );

        if let crate::arch::Arch::X64 = module.arch {
            candidates.extend(
                sec_buf
                    // using windows for unaligned pointers,
                    // rather than chunks for aligned pointers.
                    .windows(std::mem::size_of::<u64>())
                    .map(|b| byteorder::LittleEndian::read_u64(b) as VA)
                    .enumerate()
                    // naive range filter that is very fast
                    .filter(|&(_, va)| va >= min_addr && va < max_addr)
                    .filter(|&(_, va)| module.probe_va(va, Permissions::X))
                    .map(|(i, va)| (vstart + (i as u64), va)),
            )
        } else {
            candidates.extend(
                sec_buf
                    // using windows for unaligned pointers
                    // rather than chunks for aligned pointers.
                    .windows(std::mem::size_of::<u32>())
                    .map(|b| byteorder::LittleEndian::read_u32(b) as VA)
                    .enumerate()
                    // naive range filter that is very fast
                    .filter(|&(_, va)| va >= min_addr && va < max_addr)
                    .filter(|&(_, va)| module.probe_va(va, Permissions::X))
                    .map(|(i, va)| (vstart + (i as u64), va)),
            )
        }
    }

    Ok(candidates
        .into_iter()
        .map(|(src, dst)| {
            debug!(
                "code references: candidate pointer: {:#x} points to valid content at {:#x}",
                src, dst
            );
            dst
        })
        .collect::<BTreeSet<VA>>()
        .into_iter()
        .collect())
}

pub fn find_new_code_references(module: &Module, insns: &cfg::InstructionIndex) -> Result<Vec<VA>> {
    let decoder = dis::get_disassembler(module)?;
    // we prefer to read via a page cache,
    // assuming that when we read instructions ordered by address,
    // fetches will often be localized within one page.
    let mut reader: CachingPageReader = Default::default();

    let mut new_code: BTreeSet<VA> = Default::default();
    for &va in insns.insns_by_address.keys() {
        if let Ok(Some(insn)) = read_insn_with_cache(&mut reader, &module.address_space, va, &decoder) {
            for op in dis::get_operands(&insn) {
                if let Ok(Some(xref)) = dis::get_operand_xref(module, va, &insn, op) {
                    let target = match xref {
                        dis::Target::Direct(target) => target,
                        dis::Target::Indirect(target) => target,
                    };

                    if insns.insns_by_address.contains_key(&target) {
                        // this is already code.
                        continue;
                    }

                    if heuristics::is_probably_code(module, &decoder, target) {
                        // finally, we think we have some new code.
                        log::debug!("code references: found new likely code at {:#x}", target);
                        new_code.insert(target);
                    }
                }
            }
        }
    }

    // TODO: do additional passes on the newly found code

    Ok(new_code.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use crate::{
        analysis::cfg::{code_references::*, InstructionIndex},
        rsrc::*,
    };

    #[test]
    fn push_function_pointer() -> Result<()> {
        // recognize a function pointer being pushed onto the stack
        // such as a call to CreateThread
        //
        // in this case, we have function sub_4010E0
        // that is referenced at 0x41FA0C:
        //
        // ```
        // mov     edi, [ebp+arg_0]
        // push    offset sub_40116C
        // push    offset sub_4010E0  ; @ 0x41FA0C
        // push    10h
        // push    4
        // lea     eax, [edi+8]
        // push    eax
        // call    ??_L@YGXPAXIHP6EX0@Z1@Z ;
        // ```
        let buf = get_buf(Rsrc::DED0);
        let pe = crate::loader::pe::PE::from_bytes(&buf)?;

        let ptrs = find_executable_pointers(&pe.module)?;
        assert!(ptrs.contains(&0x4010E0));

        let existing = crate::analysis::pe::find_function_starts(&pe)?;
        assert!(!existing.contains(&0x4010E0));

        let mut insns: InstructionIndex = Default::default();
        for &function in existing.iter() {
            insns.build_index(&pe.module, function)?;
        }

        let found = find_new_code_references(&pe.module, &insns)?;
        assert!(found.contains(&0x4010E0));

        Ok(())
    }
}
