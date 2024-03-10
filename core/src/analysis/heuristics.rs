use std::ops::Not;

use crate::{
    analysis::{
        dis,
        dis::zydis::{DecodedInstruction, Decoder},
    },
    aspace::AddressSpace,
    module::{Module, Permissions},
    VA,
};

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

    if module.is_in_image(va).not() {
        // this is not code, because its not found in the module image.
        // such as the RWX section that UPX unpacks into.
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
