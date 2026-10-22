use std::{
    collections::{BTreeSet, VecDeque},
    ops::Not,
};

use crate::{
    analysis::{
        cfg::{
            flow::{self, Flow},
            read_insn_with_cache, CachingPageReader,
        },
        dis,
        dis::{zydis::Decoder, DecodedInstruction, Target},
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

/// Is this an instruction that compilers don't emit in user-mode code,
/// but that shows up often when decoding data as code?
/// For example, the ASCII letters `l` through `o` decode as `insb`, `insd`, `outsb`, and `outsd`,
/// and `b` and `c` decode as `bound` and `arpl`.
fn is_unlikely_instruction(insn: &DecodedInstruction) -> bool {
    use zydis::{Mnemonic::*, Register};

    match insn.mnemonic {
        AAA | AAS | AAD | AAM | DAA | DAS | SALC | ARPL | BOUND | INTO | LES | LDS | INSB | INSW | INSD | OUTSB
        | OUTSW | OUTSD => true,
        // pop into a segment register
        POP => matches!(
            insn.operands().first().map(|op| &op.kind),
            Some(dis::DecodedOperandKind::Reg(Register::ES | Register::SS | Register::DS))
        ),
        _ => false,
    }
}

/// Is there a pointer table at the given address, possibly after some alignment padding?
fn is_padded_pointer_table(module: &Module, va: VA) -> bool {
    let mut va = va;
    while let Ok(0x90 | 0xCC) = module.address_space.read_u8(va) {
        va += 1;
    }
    is_pointer_table(module, va)
}

/// Is this a call or (conditional) jump? That is, a control flow instruction with a target operand.
fn is_branch(insn: &DecodedInstruction) -> bool {
    dis::is_control_flow_instruction(insn)
        && !matches!(
            insn.mnemonic,
            zydis::Mnemonic::RET | zydis::Mnemonic::IRET | zydis::Mnemonic::IRETD | zydis::Mnemonic::IRETQ
        )
}

/// The number of instructions to decode when checking the flow from a candidate function start.
const FLOW_CHECK_INSTRUCTION_COUNT: usize = 256;

/// Does the code reachable from the given address within its function
/// (fallthroughs and jumps, but not calls) decode cleanly,
/// up to FLOW_CHECK_INSTRUCTION_COUNT instructions?
///
/// Data decoded as code soon reaches an invalid instruction,
/// an instruction that compilers don't emit,
/// or a branch to somewhere that isn't code.
/// The first basic block alone often looks fine, so we look further.
fn has_clean_flow(module: &Module, decoder: &Decoder, va: VA) -> bool {
    let mut reader: CachingPageReader = Default::default();
    let mut seen: BTreeSet<VA> = Default::default();
    let mut queue: VecDeque<VA> = Default::default();
    queue.push_back(va);

    while let Some(va) = queue.pop_front() {
        if !seen.insert(va) {
            continue;
        }

        if seen.len() > FLOW_CHECK_INSTRUCTION_COUNT {
            return true;
        }

        let Ok(Some(insn)) = read_insn_with_cache(&mut reader, &module.address_space, va, decoder) else {
            return false;
        };

        if is_unlikely_instruction(&insn) {
            return false;
        }

        if is_branch(&insn) {
            if let Some(op) = dis::get_first_operand(&insn) {
                match dis::get_operand_xref(module, va, &insn, op) {
                    Ok(Some(Target::Direct(target))) if !flow::is_valid_target(module, target) => return false,
                    // a relative branch outside of the module.
                    Ok(None) if matches!(op.kind, dis::DecodedOperandKind::Imm(_)) => return false,
                    _ => {}
                }
            }
        }

        let Ok(flows) = flow::get_insn_flow(module, va, &insn) else {
            return false;
        };
        for flow in flows.iter() {
            match flow {
                Flow::Fallthrough(target)
                    if insn.mnemonic == zydis::Mnemonic::CALL && is_padded_pointer_table(module, *target) =>
                {
                    // the call doesn't return, and a jump table follows it.
                    // we don't know about noret functions yet.
                }
                Flow::Fallthrough(target) => queue.push_front(*target),
                Flow::ConditionalJump(target) => queue.push_back(*target),
                Flow::UnconditionalJump(Target::Direct(target)) => queue.push_back(*target),
                // calls are checked when the callee is considered,
                // and we can't follow indirect flows.
                Flow::Call(_) | Flow::UnconditionalJump(Target::Indirect(_)) => {}
            }
        }
    }

    true
}

fn is_text(c: u8) -> bool {
    (0x20..0x7F).contains(&c) || matches!(c, b'\t' | b'\n' | b'\r')
}

/// Does the buffer start with a UTF-16LE string of at least 4 characters?
/// Like `45 00 52 00 52 00 4F 00` ("ERRO"), which decodes as `inc ebp; add [edx+0x0], dl; ...`.
fn is_utf16_string(buf: &[u8]) -> bool {
    buf.len() >= 8 && buf[..8].chunks(2).all(|c| is_text(c[0]) && c[1] == 0)
}

/// Does the buffer start with an ASCII string:
/// at least 8 printable characters and a NULL, or at least 16 printable characters?
///
/// shorter runs are common in code, such as `6A 2C 68 ...` (`push 0x2C; push offset ...`).
fn is_ascii_string(buf: &[u8]) -> bool {
    let n = buf.iter().take_while(|&&c| (0x20..0x7F).contains(&c)).count();
    n >= 16 || (n >= 8 && buf.get(n) == Some(&0))
}

/// Does the buffer start with two RVAs into the module,
/// such as the import name table or an export table?
fn is_rva_table(module: &Module, buf: &[u8]) -> bool {
    let image_size = module
        .sections
        .iter()
        .map(|section| section.virtual_range.end)
        .max()
        .unwrap_or(0)
        - module.address_space.base_address;

    buf.len() >= 8
        && buf[..8].chunks(4).all(|c| {
            let rva = u32::from_le_bytes([c[0], c[1], c[2], c[3]]) as u64;
            (0x1000..image_size).contains(&rva)
        })
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
        if is_utf16_string(&buf) || is_ascii_string(&buf) || is_rva_table(module, &buf) {
            // this is a string or a table, not code.
            // they often decode as a valid first basic block.
            return false;
        }

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

        // data mapped executable happens in packed programs and memory dumps,
        // which map their sections writable and executable.
        // compilers don't emit writable code, so skip the slower check there.
        if module.probe_va(va, Permissions::W) && !has_clean_flow(module, decoder, va) {
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
