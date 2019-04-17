// TODO: data xrefs

use super::*;
use zydis;
use byteorder::{ByteOrder, LittleEndian};
use std::mem;
use std::collections::HashSet;
use std::collections::VecDeque;
use bit_vec::BitVec;

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
            } else if op.mem.base == zydis::enums::register::Register::NONE &&
                      op.mem.disp.has_displacement &&
                      op.mem.scale == 0 {
                // like: .text:00401078 FF 15 40 80 40 00    call   DWORD PTR ds:0x408040
                // "mem": {
                //    "ty": "Register",
                //    "segment": "DS",
                //    "base": "NONE",
                //    "index": "NONE",
                //    "scale": 0,
                //    "disp": {
                //        "has_displacement": true,
                //        "displacement": 4227136
                //    }
                // },

                let target = op.mem.disp.displacement as Va;
                if layout.is_va_valid(target) {
                    if let Ok(target) = layout.va2rva(target) {
                        debug!("found RVA 0x{:x} from VA 0x{:x} using base address 0x{:x}",
                            target, op.mem.disp.displacement, layout.base_address);
                        Ok(Some(target))
                    } else {
                        Ok(None)
                    }
                } else {
                    warn!("problem: VA 0x{:x} not mapped using base address 0x{:x}", target, layout.base_address);
                    Ok(None)
                 }
            } else {
                // like: CALL [rbx]
                // like: CALL [rbx + 0x10]
                // TODO: for now, don't index unresolved indirect branches
                Ok(None)
            }
        }
        zydis::enums::OperandType::Pointer => {
            // like: EA 33 D2 B9 60 80 40  jmp  far ptr 4080h:60B9D233h 
            // "ptr": {
            //    "segment": 16512,
            //    "offset": 1622790707
            // },
            if op.ptr.segment == 0x0 {
                // i guess we can treat this like a memory reference???
                let target = op.ptr.offset as Va;
                if layout.is_va_valid(target) {
                    if let Ok(target) = layout.va2rva(target) {
                        debug!("found RVA 0x{:x} from VA 0x{:x} using base address 0x{:x}",
                            target, op.mem.disp.displacement, layout.base_address);
                        Ok(Some(target))
                    } else {
                        Ok(None)
                    }
                } else {
                    warn!("problem: 0x{:x}: VA 0x{:x} not mapped using base address 0x{:x}",
                            rva, target, layout.base_address);
                    Ok(None)
                }
            } else {
                // this is probably more likely, and not relevant on modern OSes.
                warn!("problem: 0x{:x}: pointer using non-zero segment: 0x{:x}", rva, op.ptr.segment);
                Ok(None)
            }
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

        // empirically, doing this in parallel (par_extend/par_bridge) is not worth it.
        // the predicates are likely too simple,
        // so the majority of time is spent synchronizing.
        ret.extend(
            ws
            .iter_insns()
            .filter(|insn| predicate(insn))
            .map(|insn| match insn {
                Instruction::Valid {loc, ..} => loc.addr,
                Instruction::Invalid {loc, ..} => loc.addr,
            })
        );

    Ok(ret)
}

/// ```
/// use lancelot::*;
/// use lancelot::rsrc::*;
/// use lancelot::analysis::*;
/// let ws = get_workspace(Rsrc::NOP);
/// let roots = find_roots(&ws).unwrap();
/// assert_eq!(roots.len(), 7324);
/// ```
pub fn find_roots(ws: &Workspace) -> Result<Vec<Rva>, Error> {
    find_insns(ws, |insn| match insn {
        Instruction::Valid{loc, ..} => loc.xrefs.to.is_empty(),
        _ => false,
    })
}

/// ```
/// use lancelot::*;
/// use lancelot::rsrc::*;
/// use lancelot::analysis::*;
/// let ws = get_workspace(Rsrc::NOP);
/// let call_targets = find_call_targets(&ws).unwrap();
/// assert_eq!(call_targets.len(), 154);
/// ```
pub fn find_call_targets(ws: &Workspace) -> Result<Vec<Rva>, Error> {
    find_insns(ws, |insn| match insn {
        Instruction::Valid{loc, ..} => loc.xrefs.to.iter().any(|xref| match xref.typ {
            XrefType::Call => true,
            _ => false,
        }),
        _ => false,
    })
}

/// ```
/// use lancelot::*;
/// use lancelot::rsrc::*;
/// use lancelot::analysis::*;
/// let ws = get_workspace(Rsrc::NOP);
/// let branch_targets = find_branch_targets(&ws).unwrap();
/// assert_eq!(branch_targets.len(), 1903);
/// ```
pub fn find_branch_targets(ws: &Workspace) -> Result<Vec<Rva>, Error> {
    find_insns(ws, |insn| match insn {
        Instruction::Valid{loc, ..} => loc.xrefs.to.iter().any(|xref| match xref.typ {
            XrefType::UnconditionalJump => true,
            XrefType::ConditionalJump => true,
            _ => false,
        }),
        _ => false,
    })
}

/// ```
/// use lancelot::*;
/// use lancelot::rsrc::*;
/// use lancelot::analysis::*;
/// let ws = get_workspace(Rsrc::NOP);
/// let sec = get_section_by_name(&ws, ".text").unwrap();
/// assert_eq!(sec.buf.len(), 0x5000);
/// ```
pub fn get_section_by_name<'a>(ws: &'a Workspace, name: &str) -> Option<&'a Section> {
    ws.sections.iter().find(|section| section.name == name)
}

/// Find functions registered as a runtime function via the .pdata section.
///  on pe64, entries in .pdata are `struct RUNTIME_FUNCTION`.
///
/// ```text
///  00000000 FunctionStart   dd ?                    ; offset rva
///  00000004 FunctionEnd     dd ?                    ; offset rva pastend
///  00000008 UnwindInfo      dd ?                    ; offset rva
/// ```
///
/// ref: https://stackoverflow.com/a/9794688/87207
///
/// ```
/// use lancelot::*;
/// use lancelot::rsrc::*;
/// use lancelot::analysis::*;
/// let ws = get_workspace(Rsrc::K32);
/// let f = find_runtime_functions(&ws).unwrap();
/// assert_eq!(1800, f.len());
/// assert_eq!(f[0..3], [0x1010, 0x1068, 0x1310]);
/// ```
pub fn find_runtime_functions(ws: &Workspace) -> Result<Vec<Rva>, Error> {
    match ws.get_obj()? {
        Object::PE(_) => {
            let mut ret: Vec<Rva> = vec![];

            if let Some(sec) = get_section_by_name(ws, ".pdata") {
                let layout = ws.get_layout()?;
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

/// ```
/// use lancelot::*;
/// use lancelot::rsrc::*;
/// use lancelot::analysis::*;
/// let ws = get_workspace(Rsrc::TINY);
/// assert_eq!(0, find_entrypoints(&ws).unwrap().len());
/// 
/// let ws = get_workspace(Rsrc::K32);
/// assert_eq!(1622, find_entrypoints(&ws).unwrap().len());
/// ```
/// 
pub fn find_entrypoints(ws: &Workspace) -> Result<Vec<Rva>, Error> {
    match ws.get_obj()? {
        Object::PE(pe) => {
            let mut ret: Vec<Rva> = vec![];
            if let Some(opt) = pe.header.optional_header {
                ret.push(opt.standard_fields.address_of_entry_point);
                ret.extend(
                    pe.exports.iter().map(|export| export.rva as Rva)
                );
            } else {
                info!("no optional header")
            }

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

pub fn iter_func_loc(ws: &Workspace, fva: Rva) -> FunctionLocationIterator {
    let mut q = VecDeque::new();
    q.push_back(fva);

    FunctionLocationIterator {
        workspace: ws,
        seen: HashSet::new(),
        q: q,
    }
}

pub struct FunctionLocationIterator<'a> {
    workspace: &'a Workspace,
    seen: HashSet<Rva>,
    q: VecDeque<Rva>,
}

pub fn is_flow(xref: &Xref) -> bool {
    match xref.typ {
        XrefType::Fallthrough => true,
        XrefType::UnconditionalJump => true,
        XrefType::ConditionalJump => true,
        XrefType::ConditionalMove => true,

        XrefType::Call => false,
        // _ => false,
    }
}

impl<'a> Iterator for FunctionLocationIterator<'a> {
    type Item = &'a Location;

    fn next(&mut self) -> Option<&'a Location> {
        while let Some(rva) = self.q.pop_front() {
            if self.seen.contains(&rva) {
                continue
            } else {
                self.seen.insert(rva);

                // warning: assume that the loc is valid
                let loc = self.workspace.get_loc(rva).unwrap();

                self.q.extend(loc.xrefs.from.iter()
                    .filter(|xref| is_flow(xref))
                    .map(|xref| xref.dst));

                // note: early return here if there's an available item
                return Some(loc);
            }
        }
        None
    }
}

pub fn is_call(xref: &Xref) -> bool {
    match xref.typ {
        XrefType::Call => true,
        _ => false,
    }
}

pub fn get_call_target(loc: &Location) -> Rva {
    loc.xrefs.from
        .iter()
        .find(|xref| is_call(xref))
        .unwrap()
        .dst
}

/// Compute the start addresses of all functions that are called from the given functions.
pub fn recursive_descents(ws: &Workspace, fvas: &[Rva]) -> Result<Vec<Rva>, Error> {

    let mut q: VecDeque<Rva> = VecDeque::new();
    let mut seen: HashSet<Rva> = HashSet::new();

    q.extend(fvas);

    while let Some(fva) = q.pop_front() {
        if seen.contains(&fva) {
            continue;
        }

        seen.insert(fva);

        for rva in iter_func_loc(ws, fva)
                    .filter_map(|loc| {
                        if let Some(xref) = loc.xrefs.from.iter().find(|xref| is_call(xref)) {
                            Some(xref.dst)
                        } else {
                            None
                        }
                    }) {
            q.push_back(rva);
        }
    }

    Ok(seen.iter().cloned().collect())
}


pub fn find_functions(ws: &Workspace) -> Result<Vec<Rva>, Error> {
    let mut candidates = Vec::new();
    candidates.extend(find_entrypoints(ws)?);
    candidates.extend(find_runtime_functions(ws)?);

    recursive_descents(ws, &candidates)
}


pub fn compute_coverage(ws: &Workspace, fvas: &[Rva]) -> Result<(), Error> {
    let maxrva = ws.sections.iter()
                            .map(|section| section.addr+(section.buf.len() as u64))
                            .max()
                            .unwrap();
    println!("capacity: 0x{:x}", maxrva as usize);
    let mut active = BitVec::from_elem(maxrva as usize, false);

    for fva in fvas.iter() {
        for loc in iter_func_loc(ws, *fva) {
            if let Instruction::Valid{insn, ..} = ws.get_insn(loc.addr)? {
                for iva in loc.addr..loc.addr+(insn.length as u64) {
                    active.set(iva as usize, true);
                }
            }
        }
    }

    println!("coverage: {:}/{:}", active.iter().filter(|x| *x).count(), active.len());

    Ok(())
}
