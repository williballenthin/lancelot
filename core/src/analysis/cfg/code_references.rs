//! This is a heuristic that inspects operands to existing instructions
//! for references to likely code.
use std::{collections::BTreeSet, ops::Not, vec};

use anyhow::Result;
use byteorder::ByteOrder;
use log::debug;

use crate::{
    analysis::{
        cfg::{self, read_insn_with_cache, CachingPageReader},
        dis,
        dis::zydis::{DecodedInstruction, Decoder},
        pe::Function,
    },
    aspace::AddressSpace,
    module::{Module, Permissions},
    VA,
};

pub fn find_pe_nonrelocated_executable_pointers(module: &Module) -> Result<Vec<VA>> {
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
            "pointers: scanning section {:#x}-{:#x}",
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
                "pointers: candidate pointer: {:#x} points to valid content at {:#x}",
                src, dst
            );
            dst
        })
        .collect::<BTreeSet<VA>>()
        .into_iter()
        .collect())
}

#[derive(Clone, Copy, Debug)]
enum MnemonicDescriptor {
    /// value is not present, such as beyond the bounds of the section or basic
    /// block.
    _NONE   = 1,
    PUSH    = 2,
    POP     = 3,
    MOV     = 4,
    LEA     = 5,
    CALL    = 6,
    RET     = 7,
    COMPARE = 8,
    JMP     = 9,
    CJMP    = 10,
    /// add, sub, xor, mul, div, etc.
    ARITH   = 11,
    OTHER   = 12,
}

#[derive(Debug)]
struct CodeFeatures {
    // when disassembling the first basic block,
    // do we encounter an invalid instruction?
    has_invalid_instruction: bool,

    // when disassembling the first basic block,
    // do we encounter the instruction representated by
    // 00 00: add    BYTE PTR [eax],al?
    has_zero_instruction: bool,

    // when disassembling the first basic block,
    // do we encounter an instruction in the "OTHER" category?
    has_uncommon_instruction: bool,
}

fn extract_mnemonic_feature(insn: &DecodedInstruction) -> MnemonicDescriptor {
    match insn.mnemonic {
        zydis::Mnemonic::PUSH => MnemonicDescriptor::PUSH,
        zydis::Mnemonic::POP => MnemonicDescriptor::POP,

        zydis::Mnemonic::MOV => MnemonicDescriptor::MOV,
        zydis::Mnemonic::LEA => MnemonicDescriptor::LEA,

        zydis::Mnemonic::CALL => MnemonicDescriptor::CALL,
        zydis::Mnemonic::RET | zydis::Mnemonic::IRET | zydis::Mnemonic::IRETD | zydis::Mnemonic::IRETQ => {
            MnemonicDescriptor::RET
        }

        zydis::Mnemonic::CMP => MnemonicDescriptor::COMPARE,
        zydis::Mnemonic::TEST => MnemonicDescriptor::COMPARE,

        zydis::Mnemonic::JMP => MnemonicDescriptor::JMP,

        zydis::Mnemonic::JB
        | zydis::Mnemonic::JBE
        | zydis::Mnemonic::JCXZ
        | zydis::Mnemonic::JECXZ
        | zydis::Mnemonic::JKNZD
        | zydis::Mnemonic::JKZD
        | zydis::Mnemonic::JL
        | zydis::Mnemonic::JLE
        | zydis::Mnemonic::JNB
        | zydis::Mnemonic::JNBE
        | zydis::Mnemonic::JNL
        | zydis::Mnemonic::JNLE
        | zydis::Mnemonic::JNO
        | zydis::Mnemonic::JNP
        | zydis::Mnemonic::JNS
        | zydis::Mnemonic::JNZ
        | zydis::Mnemonic::JO
        | zydis::Mnemonic::JP
        | zydis::Mnemonic::JRCXZ
        | zydis::Mnemonic::JS
        | zydis::Mnemonic::JZ => MnemonicDescriptor::CJMP,

        zydis::Mnemonic::CMOVB
        | zydis::Mnemonic::CMOVBE
        | zydis::Mnemonic::CMOVL
        | zydis::Mnemonic::CMOVLE
        | zydis::Mnemonic::CMOVNB
        | zydis::Mnemonic::CMOVNBE
        | zydis::Mnemonic::CMOVNL
        | zydis::Mnemonic::CMOVNLE
        | zydis::Mnemonic::CMOVNO
        | zydis::Mnemonic::CMOVNP
        | zydis::Mnemonic::CMOVNS
        | zydis::Mnemonic::CMOVNZ
        | zydis::Mnemonic::CMOVO
        | zydis::Mnemonic::CMOVP
        | zydis::Mnemonic::CMOVS
        | zydis::Mnemonic::CMOVZ => MnemonicDescriptor::CJMP,

        zydis::Mnemonic::ADD
        | zydis::Mnemonic::SUB
        | zydis::Mnemonic::XOR
        | zydis::Mnemonic::MUL
        | zydis::Mnemonic::DIV
        | zydis::Mnemonic::IMUL
        | zydis::Mnemonic::IDIV
        | zydis::Mnemonic::INC
        | zydis::Mnemonic::DEC
        | zydis::Mnemonic::NEG
        | zydis::Mnemonic::NOT
        | zydis::Mnemonic::AND
        | zydis::Mnemonic::OR
        | zydis::Mnemonic::SHL
        | zydis::Mnemonic::SHR
        | zydis::Mnemonic::SAR
        | zydis::Mnemonic::ROL
        | zydis::Mnemonic::ROR
        | zydis::Mnemonic::RCL
        | zydis::Mnemonic::RCR => MnemonicDescriptor::ARITH,

        _ => MnemonicDescriptor::OTHER,
    }
}

fn extract_code_features(decoder: &Decoder, buf: &[u8]) -> CodeFeatures {
    assert!(buf.len() >= 256);

    let mut has_invalid_instruction = false;
    let mut has_zero_instruction = false;
    let mut has_uncommon_instruction = false;
    for (offset, insn) in dis::linear_disassemble(decoder, buf) {
        if let (Some(0x0), Some(0x0)) = (buf.get(offset), buf.get(offset + 1)) {
            has_zero_instruction = true;
        }

        if let Ok(Some(insn)) = insn {
            let mnem = extract_mnemonic_feature(&insn);

            if matches!(mnem, MnemonicDescriptor::OTHER) {
                has_uncommon_instruction = true;
            }

            if matches!(
                mnem,
                MnemonicDescriptor::JMP | MnemonicDescriptor::CJMP | MnemonicDescriptor::RET
            ) {
                // end of basic block
                break;
            };
        } else {
            if offset < 256 - 0x10 {
                has_invalid_instruction = true;
            } else {
                // once we get close to the end of the data buffer,
                // its reasonable that we might fail to decode a truncated
                // instruction.
            }

            break;
        }
    }

    CodeFeatures {
        has_invalid_instruction,
        has_zero_instruction,
        has_uncommon_instruction,
    }
}

pub fn is_pointer(module: &Module, va: VA) -> bool {
    match module.read_va_at_va(va) {
        Ok(dst) => module.probe_va(dst, Permissions::R),
        Err(_) => false,
    }
}

// the given address contains a pointer, as does the previous or next address.
pub fn is_pointer_table(module: &Module, va: VA) -> bool {
    let psize = module.arch.pointer_size();
    is_pointer(module, va) && (is_pointer(module, va + psize as u64) || is_pointer(module, va - psize as u64))
}

pub fn is_probably_code(module: &Module, decoder: &Decoder, va: VA) -> bool {
    if module.probe_va(va, Permissions::X).not() {
        // this is not code because its not executable.
        return false;
    }

    // we could ensure the target is not being written to,
    // by inspecting the mnemonic and operand index,
    // although with W^X, we don't expect it to be both executable and writable.

    if is_pointer_table(module, va) {
        // this is a pointer table, not code.
        return false;
    }

    if let Ok(buf) = module.address_space.read_bytes(va, 256) {
        let features = extract_code_features(decoder, &buf);

        if features.has_invalid_instruction {
            return false;
        }

        if features.has_zero_instruction {
            return false;
        }

        if features.has_uncommon_instruction {
            return false;
        }

        true
    } else {
        // is there something else we could do here?
        // i think the scenario is: the region is right at the end of the section/file,
        // so there aren't 256 bytes to read.
        false
    }
}

pub fn find_new_code_references(module: &Module, existing_functions: Vec<Function>) -> Result<Vec<VA>> {
    let decoder = dis::get_disassembler(module)?;
    // we prefer to read via a page cache,
    // assuming that when we read instructions ordered by address,
    // fetches will often be localized within one page.
    let mut reader: CachingPageReader = Default::default();

    let function_addresses: BTreeSet<VA> = existing_functions
        .iter()
        .flat_map(|f| match f {
            Function::Local(va) => Some(va),
            Function::Thunk(_) => None,
            Function::Import(_) => None,
        })
        .cloned()
        .collect();

    let mut insns: cfg::InstructionIndex = Default::default();
    for function_address in function_addresses.iter() {
        let _ = insns.build_index(module, *function_address);
        // don't care if this fails, just continue.
    }

    let mut new_code: BTreeSet<VA> = Default::default();
    for &va in insns.insns_by_address.keys() {
        if let Ok(Some(insn)) = read_insn_with_cache(&mut reader, &module.address_space, va, &decoder) {
            for op in insn
                .operands
                .iter()
                .filter(|op| op.visibility == dis::zydis::OperandVisibility::EXPLICIT)
                .take(3)
            {
                if let Ok(Some(xref)) = dis::get_operand_xref(module, va, &insn, op) {
                    let target = match xref {
                        dis::Target::Direct(target) => target,
                        dis::Target::Indirect(target) => target,
                    };

                    if insns.insns_by_address.contains_key(&target) {
                        // this is already code.
                        continue;
                    }

                    if module.probe_va(target, Permissions::X).not() {
                        // this is not code because its not executable.
                        continue;
                    }

                    if is_probably_code(module, &decoder, target) {
                        // finally, we think we have some new code.
                        log::debug!("code references: found new code at {:#x}", target);
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
        analysis::{cfg::code_references::*, pe::Function},
        rsrc::*,
    };
    use anyhow::Result;

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
        crate::test::init_logging();

        let buf = get_buf(Rsrc::DED0);
        let pe = crate::loader::pe::PE::from_bytes(&buf)?;

        let ptrs = find_pe_nonrelocated_executable_pointers(&pe.module)?;
        assert!(ptrs.contains(&0x4010E0));

        let existing = crate::analysis::pe::find_functions(&pe)?;
        assert!(!existing.contains(&Function::Local(0x4010E0)));

        let found = find_new_code_references(&pe.module, existing)?;
        assert!(found.contains(&0x4010E0));

        Ok(())
    }
}
