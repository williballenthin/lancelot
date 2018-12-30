// TODO: data xrefs

use super::*;
use zydis;
use byteorder::{ByteOrder, LittleEndian};
use std::mem;

fn analyze_operand_xrefs(
    // used to determine valid addresses
    layout: &ModuleLayout,
    // used to detect RIP-relative addressing
    pc: zydis::enums::register::Register,
    // used to compute relative addresses
    rva: Rva,
    // used to compute relative addresses
    insn: &zydis::ffi::DecodedInstruction,
    // the operand to inspect
    op: &zydis::ffi::DecodedOperand,
) -> Result<Option<Rva>, Error> {
    match op.ty {
        zydis::enums::OperandType::Unused => Err(Error::NotImplemented("xref from unused register")),
        zydis::enums::OperandType::Register => {
            // like: CALL rbx
            // TODO: for now, don't index unresolved indirect branches
            Ok(None)
        }
        zydis::enums::OperandType::Memory => {
            // like: .text:0000000180001041 FF 15 D1 78 07 00      call    cs:__imp_RtlVirtualUnwind_0
            //           0x0000000000001041:                       call    [0x0000000000079980]
            if pc == op.mem.base && op.mem.disp.has_displacement && op.mem.scale == 0 {
                // RIP-relative
                // this is the default encoding on x64.
                // tools like IDA automatically compute and display the target.
                // CALL [RIP + 0x401000]
                if let zydis::enums::register::Register::NONE = op.mem.index {
                    let target =
                        (rva as i64 
                        // TODO: cast from rva (u64) to i64 is lossy.
                        + op.mem.disp.displacement 
                        + i64::from(insn.length)) as Rva;

                    if layout.is_rva_valid(target) {
                        Ok(Some(target))
                    } else {
                        // TODO: record this anomaly somewhere.
                        warn!("problem: invalid xref target: memory not in sections");
                        Ok(None)
                    }
                } else {
                    // unsupported
                    // like: CALL [RIP + 4*RCX + 0x401000] ??
                    println!("CALL [RIP + 4*RCX + 0x401000] ??");
                    Err(Error::NotImplemented("xref from RIP-relative, non-zero index memory"))
                }
            } else if op.mem.base == zydis::enums::register::Register::NONE {
                // like: CALL [0x401000] ??
                println!("TODO: other OperandType::Memory branch");
                Err(Error::NotImplemented("xref from non-RIP-relative memory"))
            } else {
                // like: CALL [rbx]
                // like: CALL [rbx + 0x10]
                // TODO: for now, don't index unresolved indirect branches
                Ok(None)
            }
        }
        zydis::enums::OperandType::Pointer => {
            println!("TODO: operand: pointer");
            Err(Error::NotImplemented("xref from pointer"))
        }
        zydis::enums::OperandType::Immediate => {
            if !op.imm.is_relative {
                println!("TODO: absolute immediate operand");
                Err(Error::NotImplemented("xref from absolute immediate"))
            } else {
                let imm = if op.imm.is_signed {
                    u64_i64(op.imm.value)
                } else {
                    op.imm.value as i64
                };

                // TODO: cast from rva (u64) to i64 is lossy.
                let dst = (rva as i64 + imm + i64::from(insn.length)) as Rva;
                if layout.is_rva_valid(dst) {
                    Ok(Some(dst))
                } else {
                    // TODO: record this anomaly somewhere.
                    debug!("problem: invalid xref target: relative immediate not in sections");
                    Ok(None)
                }
            }
        }
    }
}

pub fn analyze_insn_xrefs(
    layout: &ModuleLayout,
    pc: zydis::enums::register::Register,
    rva: Rva,
    insn: &zydis::ffi::DecodedInstruction,
) -> Result<Vec<Xref>, Error> {
    match insn.mnemonic {
        // see InstructionCategory
        // syscall, sysexit, sysret
        // vmcall, vmmcall
        zydis::enums::mnemonic::Mnemonic::CALL => {
            // a CALL always has an operand, so assume this is ok.
            let op = Workspace::get_first_operand(insn).unwrap();

            let fallthrough = Xref {
                src: rva,
                dst: rva + u64::from(insn.length),
                typ: XrefType::Fallthrough,
            };

            match analyze_operand_xrefs(layout, pc, rva, insn, op)? {
                // TODO: fallthrough is not guaranteed if the function is noret
                Some(dst) => Ok(vec![Xref { src: rva, dst: dst, typ: XrefType::Call }, fallthrough]),
                None => Ok(vec![fallthrough]),
            }
        }
        zydis::enums::mnemonic::Mnemonic::RET
        | zydis::enums::mnemonic::Mnemonic::IRET
        | zydis::enums::mnemonic::Mnemonic::IRETD
        | zydis::enums::mnemonic::Mnemonic::IRETQ => Ok(vec![]),
        zydis::enums::mnemonic::Mnemonic::JMP => {
            // a JMP always has an operand, so assume this is ok.
            let op = Workspace::get_first_operand(insn).unwrap();

            match analyze_operand_xrefs(layout, pc, rva, insn, op)? {
                Some(dst) => Ok(vec![Xref { src: rva, dst: dst, typ: XrefType::UnconditionalJump }]),
                None => Ok(vec![]),
            }
        }
        zydis::enums::mnemonic::Mnemonic::JB
        | zydis::enums::mnemonic::Mnemonic::JBE
        | zydis::enums::mnemonic::Mnemonic::JCXZ
        | zydis::enums::mnemonic::Mnemonic::JECXZ
        | zydis::enums::mnemonic::Mnemonic::JKNZD
        | zydis::enums::mnemonic::Mnemonic::JKZD
        | zydis::enums::mnemonic::Mnemonic::JL
        | zydis::enums::mnemonic::Mnemonic::JLE
        | zydis::enums::mnemonic::Mnemonic::JNB
        | zydis::enums::mnemonic::Mnemonic::JNBE
        | zydis::enums::mnemonic::Mnemonic::JNL
        | zydis::enums::mnemonic::Mnemonic::JNLE
        | zydis::enums::mnemonic::Mnemonic::JNO
        | zydis::enums::mnemonic::Mnemonic::JNP
        | zydis::enums::mnemonic::Mnemonic::JNS
        | zydis::enums::mnemonic::Mnemonic::JNZ
        | zydis::enums::mnemonic::Mnemonic::JO
        | zydis::enums::mnemonic::Mnemonic::JP
        | zydis::enums::mnemonic::Mnemonic::JRCXZ
        | zydis::enums::mnemonic::Mnemonic::JS
        | zydis::enums::mnemonic::Mnemonic::JZ => {
            // a J* always has an operand, so assume this is ok.
            let op = Workspace::get_first_operand(insn).unwrap();

            let fallthrough = Xref {
                src: rva,
                dst: rva + u64::from(insn.length),
                typ: XrefType::Fallthrough,
            };

            match analyze_operand_xrefs(layout, pc, rva, insn, op)? {
                Some(dst) => Ok(vec![
                    Xref { src: rva, dst: dst, typ: XrefType::ConditionalJump, },
                    fallthrough,
                ]),
                None => Ok(vec![fallthrough]),
            }
        }
        zydis::enums::mnemonic::Mnemonic::CMOVB
        | zydis::enums::mnemonic::Mnemonic::CMOVBE
        | zydis::enums::mnemonic::Mnemonic::CMOVL
        | zydis::enums::mnemonic::Mnemonic::CMOVLE
        | zydis::enums::mnemonic::Mnemonic::CMOVNB
        | zydis::enums::mnemonic::Mnemonic::CMOVNBE
        | zydis::enums::mnemonic::Mnemonic::CMOVNL
        | zydis::enums::mnemonic::Mnemonic::CMOVNLE
        | zydis::enums::mnemonic::Mnemonic::CMOVNO
        | zydis::enums::mnemonic::Mnemonic::CMOVNP
        | zydis::enums::mnemonic::Mnemonic::CMOVNS
        | zydis::enums::mnemonic::Mnemonic::CMOVNZ
        | zydis::enums::mnemonic::Mnemonic::CMOVO
        | zydis::enums::mnemonic::Mnemonic::CMOVP
        | zydis::enums::mnemonic::Mnemonic::CMOVS
        | zydis::enums::mnemonic::Mnemonic::CMOVZ => Ok(vec![
            Xref {
                src: rva,
                dst: rva + u64::from(insn.length),
                typ: XrefType::Fallthrough
            },
            Xref {
                src: rva,
                dst: rva + u64::from(insn.length),
                typ: XrefType::ConditionalMove
            },
        ]),
        _ => Ok(vec![Xref {
            src: rva,
            dst: rva + u64::from(insn.length),
            typ: XrefType::Fallthrough,
        }]),
    }
}

pub fn find_insns(ws: &Workspace, predicate: fn(&Instruction) -> bool) -> Result<Vec<Rva>, Error> {
    let mut ret: Vec<Rva> = vec![];

    for section in ws.sections.iter() {
        ret.extend(
            section.insns
            .iter()
            .filter(|insn| predicate(insn))
            .map(|insn| match insn {
                Instruction::Valid {addr, ..} => addr,
                Instruction::Invalid {addr, ..} => addr,
            }));
    };

    Ok(ret)
}

pub fn find_roots(ws: &Workspace) -> Result<Vec<Rva>, Error> {
    find_insns(ws, |insn| match insn {
        Instruction::Valid{xrefs, ..} => xrefs.to.is_empty(),
        _ => false,
    })
}

pub fn find_call_targets(ws: &Workspace) -> Result<Vec<Rva>, Error> {
    find_insns(ws, |insn| match insn {
        Instruction::Valid{xrefs, ..} => xrefs.to.iter().any(|xref| match xref.typ {
            XrefType::Call => true,
            _ => false,
        }),
        _ => false,
    })
}

pub fn find_branch_targets(ws: &Workspace) -> Result<Vec<Rva>, Error> {
    find_insns(ws, |insn| match insn {
        Instruction::Valid{xrefs, ..} => xrefs.to.iter().any(|xref| match xref.typ {
            XrefType::UnconditionalJump => true,
            XrefType::ConditionalJump => true,
            _ => false,
        }),
        _ => false,
    })
}

fn get_section_by_name<'a>(ws: &'a Workspace, name: &[u8]) -> Result<Option<&'a Section>, Error> {
    match ws.get_obj()? {
        Object::PE(pe) => {
            match pe.sections.iter()
                .enumerate()
                .map(|(index, section)| (index, section.name))
                .find(|(_, sec_name)| sec_name == name) {
                    Some((index, _)) => Ok(Some(&ws.sections[index])),
                    None => Ok(None),
            }
        },
        _ => Err(Error::NotImplemented("analyzer for non-PE module"))
    }
}

// pub fn find_runtime_functions
//  on pe64, entries in .pdata are struct RUNTIME_FUNCTION
//
//  00000000 FunctionStart   dd ?                    ; offset rva
//  00000004 FunctionEnd     dd ?                    ; offset rva pastend
//  00000008 UnwindInfo      dd ?                    ; offset rva
//
// ref: https://stackoverflow.com/a/9794688/87207
//
// for k32, the first three entries should be:
//  - 1010
//  - 1060
//  - 1140
pub fn find_runtime_functions(ws: &Workspace) -> Result<Vec<Rva>, Error> {
    match ws.get_obj()? {
        Object::PE(pe) => {
            let mut ret: Vec<Rva> = vec![];

            if let Some(sec) = get_section_by_name(ws, b".pdata\x00\x00")? {
                let layout = ws.get_section_layout();
                for runtime_function in sec.buf.chunks_exact(mem::size_of::<u32>() * 3) {
                    let rva = LittleEndian::read_u32(&runtime_function) as Rva;
                    if rva == 0 {
                        // must be end of (valid) .pdata section
                        break;
                    } else if layout.is_rva_valid(rva) {
                        ret.push(rva);
                    } else {
                        warn!("malformed .pdata section: entry points outside of image");
                        return Ok(vec![]);
                    }
                }
            }

            Ok(ret)
        },
        _ => Err(Error::NotImplemented("analyzer for non-PE module"))
    }
}


// pub fn find_fixups

// pub fn find_ptrs
//  relies on the image being loaded at the base address
//  also relies on loc vs insn to be figured out.

// for k32, there should be 1630
pub fn find_entrypoints(ws: &Workspace) -> Result<Vec<Rva>, Error> {
    match ws.get_obj()? {
        Object::PE(pe) => {
            let mut ret: Vec<Rva> = vec![];

            let optional_header = pe.header.optional_header.expect("optional header is not optional");
            ret.push(optional_header.standard_fields.address_of_entry_point);

            ret.extend(
                pe.exports.iter().map(|export| export.rva as Rva)
            );

            Ok(ret)
        },
        _ => Err(Error::NotImplemented("analyzer for non-PE module"))
    }
}

// pub fn find_sigs

// pub fn find_impossible_paths
// like:
//   MOV
//   MOV
//   INVALID
