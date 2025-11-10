use log::debug;
use std::collections::BTreeSet;

use anyhow::Result;

use crate::{analysis::dis, aspace::AddressSpace, loader::elf::ELF, module::Permissions, util, VA};

pub fn find_elf_call_targets(elf: &ELF) -> Result<BTreeSet<VA>> {
    let mut ret = BTreeSet::default();
    let decoder = dis::get_disassembler(&elf.module)?;

    let mut call_count = 0usize;
    
    for section in elf.module.sections.iter() {

        let name = &section.name;
        let vstart: VA = section.virtual_range.start;
        let vsize = (section.virtual_range.end - section.virtual_range.start) as usize;
        
        let sec_buf = match elf.module.address_space.read_bytes(vstart, vsize) {
            Ok(buf) => buf,
            Err(_) => continue,
        };
        
        for (insn_offset, insn) in dis::linear_disassemble(&decoder, &sec_buf) {
            if let Ok(Some(insn)) = insn {
                if insn.meta.category != zydis::InstructionCategory::CALL {
                    continue;
                }

                let insn_va: VA = vstart + insn_offset as u64;
                let op0 = &insn.operands[0];

                match op0.ty {
                    zydis::OperandType::IMMEDIATE => {
                        if op0.imm.is_relative {
                            let imm = if op0.imm.is_signed {
                                util::u64_i64(op0.imm.value)
                            } else {
                                op0.imm.value as i64
                            };

                            // skip call $+5 pattern
                            if imm == 0 {
                                debug!("call targets: {insn_va:#x}: call $+5 skipped");
                                continue;
                            }

                            let target = ((insn_va + insn.length as u64) as i64 + imm) as u64;
                            if elf.module.probe_va(target, Permissions::X) {
                                ret.insert(target);
                            }
                        }
                    }
                    _ => continue,
                }

                call_count += 1;
            }
        }

        let count = ret.len();
        debug!("elf call targets: {name}, call count: {call_count}, targets: {count}");
    }

    Ok(ret)
}

