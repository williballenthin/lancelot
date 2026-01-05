use log::debug;
use std::collections::BTreeSet;

use anyhow::Result;

use crate::{analysis::dis, aspace::AddressSpace, loader::elf::ELF, module::Permissions, VA};
pub fn find_elf_jump_targets(elf: &ELF) -> Result<BTreeSet<VA>> {
    let mut ret: BTreeSet<VA> = Default::default();
    let decoder = dis::get_disassembler(&elf.module)?;

    let mut jump_count = 0usize;
    
    for section in elf
        .module
        .sections
        .iter()
        .filter(|section| section.permissions.intersects(Permissions::X))
    {
        let name = &section.name;
        let vstart: VA = section.virtual_range.start;
        let vsize = (section.virtual_range.end - section.virtual_range.start) as usize;
        
        let sec_buf = match elf.module.address_space.read_bytes(vstart, vsize) {
            Ok(buf) => buf,
            Err(_) => continue,
        };
        
        for (insn_offset, insn) in dis::linear_disassemble(&decoder, &sec_buf) {
            let Ok(Some(insn)) = insn else {
                continue;
            };

            if insn.meta.category != zydis::InstructionCategory::UNCOND_BR {
                continue;
            }

            if insn.mnemonic != zydis::Mnemonic::JMP {
                continue;
            }

            let insn_va: VA = vstart + insn_offset as u64;
            let Some(op0) = dis::get_first_operand(&insn) else {
                continue;
            };
            
            let dst = match op0.ty {
                zydis::OperandType::IMMEDIATE => dis::get_immediate_operand_xref(&elf.module, insn_va, &insn, op0)?,
                zydis::OperandType::MEMORY => dis::get_memory_operand_xref(&elf.module, insn_va, &insn, op0)?,
                zydis::OperandType::POINTER => dis::get_pointer_operand_xref(op0)?,
                _ => None,
            };

            if let Some(target) = dst {
                if elf.module.probe_va(target, Permissions::X) {
                    ret.insert(target);
                }
            }

            jump_count += 1;
        }

        let count = ret.len();
        debug!("elf jump targets: {name}, jump count: {jump_count}, targets: {count}");
    }

    Ok(ret)
}
