use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::fmt::Display;

use serde_json;
use failure::{Error, Fail, bail};
use log::{trace, debug, warn};
use zydis;

use super::arch::{RVA, VA};
use super::pagemap;
use super::pagemap::{PageMap};
use super::flowmeta;
use super::flowmeta::FlowMeta;
use super::loader::{LoadedModule, Permissions};
use super::workspace::Workspace;
use super::xref::{Xref, XrefType};
use super::util;

pub mod orphans;
pub use orphans::OrphanFunctionAnalyzer;

pub mod pe;

#[derive(Debug, Fail)]
pub enum AnalysisError {
    #[fail(display = "Not implemented")]
    NotImplemented,
    #[fail(display = "Not supported")]
    NotSupported,
    #[fail(display = "foo")]
    InvalidInstruction,
}

#[derive(Debug, Clone)]
pub enum AnalysisCommand {
    MakeInsn(RVA),
    MakeXref(Xref),
    MakeSymbol {
        rva: RVA,
        name: String
    },
    MakeFunction(RVA),
}

impl Display for AnalysisCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            AnalysisCommand::MakeInsn(rva) => write!(f, "MakeInsn({})", rva),
            AnalysisCommand::MakeXref(x) => write!(f, "MakeXref({:?})", x),
            AnalysisCommand::MakeSymbol{rva, name} => write!(f, "MakeSymbol({}, {})", rva, name),
            AnalysisCommand::MakeFunction(rva) => write!(f, "MakeFunction({})", rva),
        }
    }
}

/// Static cast the given 64-bit unsigned integer to a 64-bit signed integer.
/// This is probably only useful when some other code provides you a u64
///  that is meant to be an i64 (aka. uncommon).
///
/// In C: `*(int64_t *)&i`
///
/// # Examples
///
/// ```
/// use lancelot::analysis::*;
/// assert_eq!(0, u64_i64(0));
/// assert_eq!(1, u64_i64(0x1));
/// assert_eq!(-1, u64_i64(0xFFFF_FFFF_FFFF_FFFF));
/// ```
pub fn u64_i64(i: u64) -> i64 {
    if i & 1 << 63 > 0 {
        // TODO: there's probably some elegant rust-way to do this.
        // in the meantime, manually compute twos-complement.
        let bits = i & 0x7FFF_FFFF_FFFF_FFFF;
        let bits = !bits;
        let bits = bits + 1;
        let bits = bits & 0x7FFF_FFFF_FFFF_FFFF;
        -(bits as i64)
    } else {
        i as i64
    }
}

pub fn get_first_operand(insn: &zydis::DecodedInstruction) -> Option<&zydis::DecodedOperand> {
    insn.operands
        .iter()
        .find(|op| op.visibility == zydis::OperandVisibility::EXPLICIT)
}

fn print_op(op: &zydis::DecodedOperand) {
    let s = serde_json::to_string(op).unwrap();
    println!("op: {}", s);
}

pub struct XrefAnalysis {
    // TODO: use FNV because the keys are small.
    // TODO: use SmallVec(1) for `.from` values,
    // TODO: use SmallVec(X) for `.to` values,

    // dst rva -> src rva
    pub to: HashMap<RVA, HashSet<Xref>>,
    // src rva -> dst rva
    pub from: HashMap<RVA, HashSet<Xref>>,
}

pub struct FlowAnalysis {
    meta: PageMap<FlowMeta>,
    pub xrefs: XrefAnalysis,
}

pub struct Analysis {
    queue: VecDeque<AnalysisCommand>,

    // TODO: FNV
    pub functions: HashSet<RVA>,

    // TODO: FNV
    pub symbols: HashMap<RVA, String>,

    pub flow: FlowAnalysis,
    // datameta
    // symbols
    // functions
}

impl Analysis {
    pub fn new(module: &LoadedModule) -> Analysis {
        let max_address: i64 = module.max_address().into();
        let max_address = util::align(max_address as usize, 0x1000);
        let mut meta = PageMap::with_capacity(RVA::from(max_address));

        for section in module.sections.iter().filter(|section| section.is_executable()) {
            let v = pagemap::page_align(RVA::from(section.size));
            meta.map_empty(section.addr, v.into()).expect("failed to map section flowmeta");
        }

        Analysis {
            queue: VecDeque::new(),
            functions: HashSet::new(),
            symbols: HashMap::new(),
            flow: FlowAnalysis {
                meta: meta,
                xrefs: XrefAnalysis {
                    to: HashMap::new(),
                    from: HashMap::new(),
                },
            },
        }
    }
}

// here we've logically split off the analysis portion of workspace.
// this should keep file sizes smaller, and hopefully easier to understand.
impl Workspace {
    /// ```
    /// use lancelot::test;
    /// use lancelot::arch::RVA;
    ///
    /// // NOP
    /// // JMP $+0;
    /// let mut ws = test::get_shellcode32_workspace(b"\x90\xEB\xFE");
    /// ws.make_insn(RVA(0x0));
    /// ws.analyze();
    ///
    /// assert!( ws.get_meta(RVA(0x0)).unwrap().is_insn());
    /// assert!( ws.get_meta(RVA(0x1)).unwrap().is_insn());
    /// assert!(!ws.get_meta(RVA(0x2)).unwrap().is_insn());
    /// ```
    pub fn make_insn(&mut self, rva: RVA) -> Result<(), Error> {
        self.analysis
            .queue
            .push_back(AnalysisCommand::MakeInsn(rva));
        Ok(())
    }

    /// ```
    /// use lancelot::test;
    /// use lancelot::arch::RVA;
    ///
    /// // JMP $+0;
    /// let mut ws = test::get_shellcode32_workspace(b"\xEB\xFE");
    /// assert!(ws.get_symbol(RVA(0x0)).is_none());
    /// ws.make_symbol(RVA(0x0), "entry");
    /// ws.analyze();
    /// assert_eq!(ws.get_symbol(RVA(0x0)).unwrap(), "entry");
    /// ```
    pub fn make_symbol(&mut self, rva: RVA, name: &str) -> Result<(), Error> {
        self.analysis
            .queue
            .push_back(AnalysisCommand::MakeSymbol{rva: rva, name: name.to_string()});
        Ok(())
    }

    pub fn get_functions(&self ) -> impl Iterator<Item=&RVA> {
        self.analysis.functions.iter()
    }

    /// ```
    /// use lancelot::test;
    /// use lancelot::arch::RVA;
    ///
    /// // JMP $+0;
    /// let mut ws = test::get_shellcode32_workspace(b"\xEB\xFE");
    /// assert!(ws.get_functions().collect::<Vec<_>>().is_empty());
    /// ws.make_function(RVA(0x0));
    /// ws.analyze();
    ///
    /// assert!(ws.get_meta(RVA(0x0)).unwrap().is_insn());
    /// assert_eq!(ws.get_functions().collect::<Vec<_>>().len(), 1);
    /// ```
    pub fn make_function(&mut self, rva: RVA) -> Result<(), Error> {
        self.analysis
            .queue
            .push_back(AnalysisCommand::MakeFunction(rva));
        Ok(())
    }

    pub fn get_symbol(&self,  rva: RVA) -> Option<&String> {
        self.analysis.symbols.get(&rva)
    }

    pub fn get_meta(&self, rva: RVA) -> Option<FlowMeta> {
        self.analysis.flow.meta.get(rva)
    }

    fn get_meta_mut(&mut self, rva: RVA) -> Option<&mut FlowMeta> {
        self.analysis.flow.meta.get_mut(rva)
    }

    pub fn get_metas(&self, rva: RVA, length: usize) -> Result<Vec<FlowMeta>, Error> {
        self.analysis.flow.meta.slice(rva, rva+length)
    }

    /// Does the given instruction have a fallthrough flow?
    ///
    /// ```
    /// use lancelot::test;
    /// use lancelot::arch::*;
    /// use lancelot::workspace::*;
    ///
    /// // JMP $+0;
    /// let insn = test::get_shellcode32_workspace(b"\xEB\xFE").read_insn(RVA(0x0)).unwrap();
    /// assert_eq!(Workspace::does_insn_fallthrough(&insn), false);
    ///
    /// // PUSH 0x11
    /// let insn = test::get_shellcode32_workspace(b"\x6A\x11").read_insn(RVA(0x0)).unwrap();
    /// assert_eq!(Workspace::does_insn_fallthrough(&insn), true);
    /// ```
    pub fn does_insn_fallthrough(insn: &zydis::DecodedInstruction) -> bool {
        match insn.mnemonic {
            zydis::Mnemonic::JMP => false,
            zydis::Mnemonic::RET => false,
            zydis::Mnemonic::IRET => false,
            zydis::Mnemonic::IRETD => false,
            zydis::Mnemonic::IRETQ => false,
            // TODO: call may not fallthrough if function is noret.
            // will need another pass to clean this up.
            zydis::Mnemonic::CALL => true,
            _ => true,
        }
    }

    pub fn get_insn_length(&self, rva: RVA) -> Result<u8, Error> {
        match self.get_meta(rva) {
            None => Err(flowmeta::Error::NotAnInstruction.into()),
            Some(meta) => {
                match meta.is_insn() {
                    false => Err(flowmeta::Error::NotAnInstruction.into()),
                    true => match meta.get_insn_length() {
                        Ok(length) => Ok(length),
                        Err(flowmeta::Error::LongInstruction) => {
                            match self.read_insn(rva) {
                                Ok(insn) => Ok(insn.length),
                                Err(e) => Err(e),
                            }
                        },
                        Err(e) => Err(e.into()),
                    }
                }
            }
        }
    }

    pub fn get_xrefs_from(&self, rva: RVA) -> Result<Vec<Xref>, Error> {
        let mut xrefs = match self.analysis.flow.xrefs.from.get(&rva) {
            Some(xrefs) => xrefs.iter().cloned().collect(),
            None => vec![],
        };

        // if there is a fallthrough, compute the xref.
        if let Some(meta) = self.get_meta(rva) {
            if meta.is_insn() && meta.does_fallthrough() {
                if let Ok(length) = self.get_insn_length(rva) {
                    xrefs.push(Xref {
                        src: rva,
                        dst: RVA::from(rva + length),
                        typ: XrefType::Fallthrough,
                    });
                }
            }
        }

        Ok(xrefs)
    }

    pub fn get_xrefs_to(&self, rva: RVA) -> Result<Vec<Xref>, Error> {
        let mut xrefs = match self.analysis.flow.xrefs.to.get(&rva) {
            Some(xrefs) => xrefs.iter().cloned().collect(),
            None => vec![],
        };

        if let Some(meta) = self.get_meta(rva) {
            if meta.is_insn() && meta.does_other_fallthrough_to() {
                // have to scan backwards for instructions that fallthrough to here.

                let r: usize = rva.into();
                for i in r-0x10..r-1 {
                    if let Some(imeta) = self.get_meta(RVA::from(i)) {
                        if !imeta.is_insn() {
                            continue
                        }

                        if !imeta.does_fallthrough() {
                            continue
                        }

                        let length = match imeta.get_insn_length() {
                            Err(_) => continue,
                            Ok(length) => length as usize,
                        };

                        if RVA::from(i + length) == rva {
                            xrefs.push(Xref {
                                src: RVA::from(i),
                                dst: rva,
                                typ: XrefType::Fallthrough,
                            });
                        }
                    }
                }
            }
        }

        Ok(xrefs)
    }

    /// ## test simple memory ptr operand
    ///
    /// ```
    /// use lancelot::test;
    /// use lancelot::analysis;
    /// use lancelot::arch::RVA;
    ///
    /// // 0:  ff 25 06 00 00 00   +->  jmp    DWORD PTR ds:0x6
    /// // 6:  00 00 00 00         +--  dw     0x0
    /// let mut ws = test::get_shellcode32_workspace(b"\xFF\x25\x06\x00\x00\x00\x00\x00\x00\x00");
    /// let insn = ws.read_insn(RVA(0x0)).unwrap();
    /// let op = analysis::get_first_operand(&insn).unwrap();
    /// let xref = ws.get_memory_operand_xref(RVA(0x0), &insn, &op).unwrap();
    ///
    /// assert_eq!(xref.is_some(), true);
    /// assert_eq!(xref.unwrap(), RVA(0x0));
    /// ```
    ///
    /// ## test RIP-relative
    ///
    /// ```
    /// use lancelot::test;
    /// use lancelot::analysis;
    /// use lancelot::arch::RVA;
    ///
    /// // FF 15 00 00 00 00         CALL $+5
    /// // 00 00 00 00 00 00 00 00   dq 0x0
    /// let mut ws = test::get_shellcode64_workspace(b"\xFF\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
    /// let insn = ws.read_insn(RVA(0x0)).unwrap();
    /// let op = analysis::get_first_operand(&insn).unwrap();
    /// let xref = ws.get_memory_operand_xref(RVA(0x0), &insn, &op).unwrap();
    ///
    /// assert_eq!(xref.is_some(), true);
    /// assert_eq!(xref.unwrap(), RVA(0x0));
    /// ```
    pub fn get_memory_operand_xref(
        &self,
        rva: RVA,
        insn: &zydis::DecodedInstruction,
        op: &zydis::DecodedOperand,
    ) -> Result<Option<RVA>, Error> {
        if op.mem.base == zydis::Register::NONE
            && op.mem.index == zydis::Register::NONE
            && op.mem.scale == 0
            && op.mem.disp.has_displacement
        {
            // the operand is a deref of a memory address.
            // for example: JMP [0x0]
            // this means: read the ptr from 0x0, and then jump to it.
            //
            // we'll have to make some assumptions here:
            //  - the ptr doesn't change (can detect via mem segment perms)
            //  - the ptr is fixed up (TODO)
            //
            // see doctest: [test simple memory ptr operand]()

            if op.mem.disp.displacement < 0 {
                return Ok(None)
            }
            let ptr = VA::from(op.mem.disp.displacement as u64);

            let ptr = match self.rva(ptr) {
                Some(ptr) => ptr,
                None => return Ok(None),
            };

            let dst = match self.read_va(ptr) {
                Ok(dst) => dst,
                Err(_) => return Ok(None),
            };

            let dst = match self.rva(dst) {
                Some(dst) => dst,
                None => return Ok(None),
            };

            if !self.probe(dst, 1, Permissions::X) {
                return Ok(None);
            };

            // this is the happy path!
            return Ok(Some(dst));
        } else if op.mem.base == zydis::Register::RIP
            // only valid on x64
            && op.mem.index == zydis::Register::NONE
            && op.mem.scale == 0
            && op.mem.disp.has_displacement {

                // this is RIP-relative addressing.
                // it works like a relative immediate,
                // that is: dst = *(rva + displacement + instruction len)

                let disp = RVA::from(op.mem.disp.displacement);
                let len = insn.length;

                let ptr = rva + disp + len;

                let dst = match self.read_va(ptr) {
                    Ok(dst) => dst,
                    Err(_) => return Ok(None),
                };

                let dst = match self.rva(dst) {
                    Some(dst) => dst,
                    None => return Ok(None),
                };

                if !self.probe(dst, 1, Permissions::X) {
                    return Ok(None);
                };

                // this is the happy path!
                return Ok(Some(dst));
        } else if op.mem.base != zydis::Register::NONE {
            // this is something like `CALL [eax+4]`
            // can't resolve without emulation
            // TODO: add test
            return Ok(None)
        } else if op.mem.scale == 0x4 {
            // this is something like `JMP [0x1000+eax*4]` (32-bit)
            return Ok(None)
        } else {
            println!("{:#x}: get mem op xref", rva);
            print_op(op);
            panic!("not supported");
        }
    }

    fn get_pointer_operand_xref(
        &self,
        rva: RVA,
        _insn: &zydis::DecodedInstruction,
        op: &zydis::DecodedOperand,
    ) -> Result<Option<RVA>, Error> {
        // TODO
        println!("get ptr op xref {}", rva);
        print_op(op);
        panic!("not supported");
        //Ok(None)
    }

    /// ## test relative immediate operand
    ///
    /// ```
    /// use lancelot::test;
    /// use lancelot::analysis;
    /// use lancelot::arch::RVA;
    ///
    /// // this is a jump from addr 0x0 to itself:
    /// // JMP $+0;
    /// let mut ws = test::get_shellcode32_workspace(b"\xEB\xFE");
    /// let insn = ws.read_insn(RVA(0x0)).unwrap();
    /// let op = analysis::get_first_operand(&insn).unwrap();
    /// let xref = ws.get_immediate_operand_xref(RVA(0x0), &insn, &op).unwrap();
    ///
    /// assert_eq!(xref.is_some(), true);
    /// assert_eq!(xref.unwrap(), RVA(0x0));
    ///
    ///
    /// // this is a jump from addr 0x0 to -1, which is unmapped
    /// // JMP $-1;
    /// let mut ws = test::get_shellcode32_workspace(b"\xEB\xFD");
    /// let insn = ws.read_insn(RVA(0x0)).unwrap();
    /// let op = analysis::get_first_operand(&insn).unwrap();
    /// let xref = ws.get_immediate_operand_xref(RVA(0x0), &insn, &op).unwrap();
    ///
    /// assert_eq!(xref.is_some(), false);
    /// ```
    pub fn get_immediate_operand_xref(
        &self,
        rva: RVA,
        insn: &zydis::DecodedInstruction,
        op: &zydis::DecodedOperand,
    ) -> Result<Option<RVA>, Error> {
        // TODO
        if op.imm.is_relative {
            // the operand is an immediate constant relative to $PC.
            // destination = $pc + immediate + insn.len
            //
            // see doctest: [test relative immediate operand]()

            let imm = if op.imm.is_signed {
                RVA::from(u64_i64(op.imm.value))
            } else {
                // TODO: note, we lose the top bit here.
                // however, its going into an RVA, which is i64, and can't have it anyways.
                RVA::from(op.imm.value as i64)
            };

            let dst = rva + imm + insn.length;

            if self.probe(dst, 1, Permissions::X) {
                Ok(Some(dst))
            } else {
                // invalid address
                Ok(None)
            }
        } else {
            // the operand is an immediate absolute address.
            println!("get imm op xref");
            println!("not implemented: immediate absolute address");
            print_op(op);
            panic!("not implemented");
        }
    }

    fn get_operand_xref(
        &self,
        rva: RVA,
        insn: &zydis::DecodedInstruction,
        op: &zydis::DecodedOperand,
    ) -> Result<Option<RVA>, Error> {
        match op.ty {
            // TODO: need a way to add xrefs for the pointer for something like `CALL [0x0]`
            // like: .text:0000000180001041 FF 15 D1 78 07 00      call    cs:__imp_RtlVirtualUnwind_0
            //           0x0000000000001041:                       call    [0x0000000000079980]
            zydis::OperandType::MEMORY => self.get_memory_operand_xref(rva, insn, op),
            // like: EA 33 D2 B9 60 80 40  jmp  far ptr 4080h:60B9D233h
            // "ptr": {
            //    "segment": 16512,
            //    "offset": 1622790707
            // },
            zydis::OperandType::POINTER => self.get_pointer_operand_xref(rva, insn, op),
            zydis::OperandType::IMMEDIATE => self.get_immediate_operand_xref(rva, insn, op),
            // like: CALL rax
            // which cannot be resolved without emulation.
            zydis::OperandType::REGISTER => Ok(None),
            zydis::OperandType::UNUSED => Ok(None),
        }
    }

    /// ```
    /// use lancelot::test;
    /// use lancelot::arch::RVA;
    ///
    /// // E8 00 00 00 00  CALL $+5
    /// // 90              NOP
    /// let mut ws = test::get_shellcode32_workspace(b"\xE8\x00\x00\x00\x00\x90");
    /// let insn = ws.read_insn(RVA(0x0)).unwrap();
    /// let xrefs = ws.get_call_insn_flow(RVA(0x0), &insn).unwrap();
    /// assert_eq!(xrefs[0].dst, RVA(0x5));
    /// ```
    pub fn get_call_insn_flow(
        &self,
        rva: RVA,
        insn: &zydis::DecodedInstruction,
    ) -> Result<Vec<Xref>, Error> {
        // if this is not a CALL, then its a programming error. panic!
        // all CALLs should have an operand.
        let op = get_first_operand(insn).expect("CALL has no operand");

        match self.get_operand_xref(rva, insn, op)? {
            Some(dst) => Ok(vec![Xref {
                src: rva,
                dst: dst,
                typ: XrefType::Call,
            }]),
            None => Ok(vec![]),
        }
    }

    fn read_pointer_table(&self, rva: RVA) -> Result<Vec<RVA>, Error> {
        let mut ret = vec![];

        let mut rva = rva;
        loop {
            let ptr_va = match self.read_va(rva) {
                Ok(va) => va,
                Err(_) => break,
            };

            let ptr_rva = match self.rva(ptr_va) {
                Some(va) => va,
                None => break,
            };

            if ! self.probe(ptr_rva, 1, Permissions::R) {
                break
            }

            ret.push(ptr_rva);
            rva = rva + self.loader.get_arch().get_pointer_size();
        }

        if ret.len() < 4 {
            bail!("not a pointer table");
        }

        Ok(ret)
    }

    /// ```
    /// use lancelot::test;
    /// use lancelot::arch::RVA;
    ///
    /// // E9 00 00 00 00  JMP $+5
    /// // 90              NOP
    /// let mut ws = test::get_shellcode32_workspace(b"\xE9\x00\x00\x00\x00\x90");
    /// let insn = ws.read_insn(RVA(0x0)).unwrap();
    /// let xrefs = ws.get_jmp_insn_flow(RVA(0x0), &insn).unwrap();
    /// assert_eq!(xrefs[0].dst, RVA(0x5));
    /// ```
    ///
    /// ```
    /// use lancelot::rsrc::*;
    /// use lancelot::arch::*;
    /// use lancelot::workspace::Workspace;
    ///
    /// let mut ws = Workspace::from_bytes("mimi.exe", &get_buf(Rsrc::MIMI))
    ///    .disable_analysis()
    ///    .load().unwrap();
    ///
    /// // at 0x47153B is a function with some switch statements.
    /// // at 0x4715AB is one such indirect jump:
    /// //
    /// //     .text:004715A8 FF 24 8D 9B 1B 47 00                    jmp     ds:jpt_4715A8[ecx*4] ; switch jump
    /// //
    /// // and the table:
    /// //
    /// //     .text:00471B9B AF 15 47 00 F7 15 47 00+jpt_4715A8      dd offset loc_4715AF    ; DATA XREF: sub_47153B+6D↑r
    /// //     .text:00471B9B 3E 16 47 00 61 16 47 00+                dd offset loc_4715F7    ; jump table for switch statement
    /// //     .text:00471B9B 93 16 47 00 CB 16 47 00+                dd offset loc_47163E
    /// //     .text:00471B9B DB 16 47 00 36 17 47 00+                dd offset loc_471661
    /// //     .text:00471B9B 21 17 47 00 A0 17 47 00+                dd offset loc_471693
    /// //     .text:00471B9B 95 17 47 00 44 17 47 00                 dd offset loc_4716CB
    /// //     .text:00471B9B                                         dd offset loc_4716DB
    /// //     .text:00471B9B                                         dd offset loc_471736
    /// //     .text:00471B9B                                         dd offset loc_471721
    /// //     .text:00471B9B                                         dd offset loc_4717A0
    /// //     .text:00471B9B                                         dd offset def_4715A8
    /// //     .text:00471B9B                                         dd offset loc_471744
    /// //ws.make_function(0x7153B).unwrap();
    /// ws.make_insn(RVA(0x715A8)).unwrap();
    /// ws.analyze().unwrap();
    ///
    /// assert!(ws.get_meta(RVA(0x715AF)).unwrap().is_insn());
    /// assert!(ws.get_meta(RVA(0x715F7)).unwrap().is_insn());
    /// assert!(ws.get_meta(RVA(0x71744)).unwrap().is_insn());
    /// ```
    pub fn get_jmp_insn_flow(
        &self,
        rva: RVA,
        insn: &zydis::DecodedInstruction,
    ) -> Result<Vec<Xref>, Error> {
        // if this is not a JMP, then its a programming error. panic!
        // all JMPs should have an operand.
        let op = get_first_operand(insn).expect("JMP has no target");

        if op.ty == zydis::OperandType::MEMORY
            && op.mem.scale == 0x4
            && op.mem.base == zydis::Register::NONE
            && op.mem.disp.has_displacement {
            // this looks like a switch table, e.g. `JMP [0x1000+ecx*4]`
            // so, probe for a pointer table.
            // otherwise, this should probably be solved via emulation.

            // disp is a i64 here, but actually a u64 in practice
            // it is the VA of the table (and probably fixed up by a reloc).
            let disp = VA::from(op.mem.disp.displacement as u64);
            let table_rva = match self.rva(disp) {
                Some(table) => table,
                None => return Ok(vec![]),
            };

            let table = match self.read_pointer_table(table_rva) {
                Ok(table) => table,
                Err(_) => return Ok(vec![]),
            };

            Ok(table.iter()
                   .map(|&dst| Xref {
                       src: rva,
                       dst: dst,
                       typ: XrefType::UnconditionalJump,
                   })
                   .collect())
        } else {
            match self.get_operand_xref(rva, insn, op)? {
                Some(dst) => Ok(vec![Xref {
                    src: rva,
                    dst: dst,
                    typ: XrefType::UnconditionalJump,
                }]),
                None => Ok(vec![]),
            }
        }
    }

    /// ```
    /// use lancelot::test;
    /// use lancelot::arch::RVA;
    ///
    /// // C3  RETN
    /// let mut ws = test::get_shellcode32_workspace(b"\xC3");
    /// let insn = ws.read_insn(RVA(0x0)).unwrap();
    /// let xrefs = ws.get_ret_insn_flow(RVA(0x0), &insn).unwrap();
    /// assert_eq!(xrefs.len(), 0);
    /// ```
    pub fn get_ret_insn_flow(
        &self,
        _rva: RVA,
        _insn: &zydis::DecodedInstruction,
    ) -> Result<Vec<Xref>, Error> {
        Ok(vec![])
    }

    /// ```
    /// use lancelot::test;
    /// use lancelot::arch::RVA;
    ///
    /// // 75 01 JNZ $+1
    /// // CC    BREAK
    /// // 90    NOP
    /// let mut ws = test::get_shellcode32_workspace(b"\x75\x01\xCC\x90");
    /// let insn = ws.read_insn(RVA(0x0)).unwrap();
    /// let xrefs = ws.get_cjmp_insn_flow(RVA(0x0), &insn).unwrap();
    /// assert_eq!(xrefs[0].dst, RVA(0x3));
    /// ```
    pub fn get_cjmp_insn_flow(
        &self,
        rva: RVA,
        insn: &zydis::DecodedInstruction,
    ) -> Result<Vec<Xref>, Error> {
        // if this is not a CJMP, then its a programming error. panic!
        // all conditional jumps should have an operand.
        let op = get_first_operand(insn).expect("CJMP has no target");

        match self.get_operand_xref(rva, insn, op)? {
            Some(dst) => Ok(vec![Xref {
                src: rva,
                dst: dst,
                typ: XrefType::ConditionalJump,
            }]),
            None => Ok(vec![]),
        }
    }

    /// ```
    /// use lancelot::test;
    /// use lancelot::arch::RVA;
    ///
    /// // 0F 44 C3  CMOVZ EAX, EBX
    /// // 90        NOP
    /// let mut ws = test::get_shellcode32_workspace(b"\x0F\x44\xC3\x90");
    /// let insn = ws.read_insn(RVA(0x0)).unwrap();
    /// let xrefs = ws.get_cmov_insn_flow(RVA(0x0), &insn).unwrap();
    /// assert_eq!(xrefs[0].dst, RVA(0x3));
    /// ```
    pub fn get_cmov_insn_flow(
        &self,
        rva: RVA,
        insn: &zydis::DecodedInstruction,
    ) -> Result<Vec<Xref>, Error> {
        let dst = rva + insn.length;

        Ok(vec![Xref {
            src: rva,
            dst: dst,
            typ: XrefType::ConditionalMove,
        }])
    }

    fn get_insn_flow(
        &self,
        rva: RVA,
        insn: &zydis::DecodedInstruction,
    ) -> Result<Vec<Xref>, Error> {
        match insn.mnemonic {
            zydis::Mnemonic::CALL => self.get_call_insn_flow(rva, insn),

            zydis::Mnemonic::JMP => self.get_jmp_insn_flow(rva, insn),

            zydis::Mnemonic::RET | zydis::Mnemonic::IRET | zydis::Mnemonic::IRETD
            | zydis::Mnemonic::IRETQ => self.get_ret_insn_flow(rva, insn),

            zydis::Mnemonic::JB | zydis::Mnemonic::JBE | zydis::Mnemonic::JCXZ | zydis::Mnemonic::JECXZ
            | zydis::Mnemonic::JKNZD | zydis::Mnemonic::JKZD | zydis::Mnemonic::JL
            | zydis::Mnemonic::JLE | zydis::Mnemonic::JNB | zydis::Mnemonic::JNBE
            | zydis::Mnemonic::JNL | zydis::Mnemonic::JNLE | zydis::Mnemonic::JNO
            | zydis::Mnemonic::JNP | zydis::Mnemonic::JNS | zydis::Mnemonic::JNZ | zydis::Mnemonic::JO
            | zydis::Mnemonic::JP | zydis::Mnemonic::JRCXZ | zydis::Mnemonic::JS | zydis::Mnemonic::JZ => {
                self.get_cjmp_insn_flow(rva, insn)
            }

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
            | zydis::Mnemonic::CMOVZ => self.get_cmov_insn_flow(rva, insn),

            // TODO: syscall, sysexit, sysret, vmcall, vmmcall
            _ => Ok(vec![]),
        }
    }

    fn handle_make_insn(&mut self, rva: RVA) -> Result<Vec<AnalysisCommand>, Error> {
        let mut ret = vec![];

        // TODO: 0. probe address

        // 1. ensure instruction doesn't already exist
        //
        // if we get a result here, then there's not yet an instruction at the rva.
        // otherwise, we will have returned early, and there's no work to be done.
        //
        // now, we might worry about lots of extra allocations for the Vec if the insn already exists.
        //  but, its not a problem: Vec only allocates when there's a non-zero element in it!
        // so, its mostly ok to spam `make_insn`.
        let meta = match self.get_meta(rva) {
            None => {
                // this might happen if:
                //   - the instruction is in a non-executable section
                //   - the memory is not mapped
                warn!("invalid instruction: no flow meta: {:x}", rva);
                return Ok(vec![]);
            }
            Some(meta) => meta,
        };

        if meta.is_insn() {
            trace!("duplicate instruction: {}", rva);
            return Ok(vec![]);
        }

        let insn = match self.read_insn(rva) {
            Err(e) => {
                warn!("invalid instruction: {:}: {:x}", e, rva);
                return Ok(vec![]);
            }
            Ok(insn) => insn,
        };

        // 2. compute instruction len
        let length = insn.length;

        // 3. compute fallthrough
        let does_fallthrough = Workspace::does_insn_fallthrough(&insn);

        // 4. compute flow ref
        // TODO: maybe don't fail, but just return empty list?
        let flows = self.get_insn_flow(rva, &insn)?;
        ret.extend(flows.iter().map(|f| AnalysisCommand::MakeXref(*f)));
        ret.extend(flows.iter().map(|f| match f.typ {
            XrefType::Call => AnalysisCommand::MakeFunction(f.dst),
            _ => AnalysisCommand::MakeInsn(f.dst),
        }));

        if does_fallthrough {
            ret.push(AnalysisCommand::MakeInsn(rva + insn.length));
        }

        // 5. update flowmeta
        {
            let meta = self.get_meta_mut(rva).expect("flowmeta not in section");

            meta.set_insn_length(length);

            if does_fallthrough {
                meta.set_fallthrough();
            }
        }

        // 6. update flowmeta for instruction fallthrough to
        if does_fallthrough {
            let next_rva = rva + length;
            let meta = self.get_meta_mut(next_rva).expect("flowmeta not in section");
            meta.set_other_fallthrough_to();
        }

        Ok(ret)
    }

    /// ```
    /// use lancelot::test;
    /// use lancelot::arch::RVA;
    ///
    /// // JMP $+0;
    /// let mut ws = test::get_shellcode32_workspace(b"\xEB\xFE");
    /// let meta = ws.get_meta(RVA(0x0)).unwrap();
    /// assert_eq!(meta.has_xrefs_from(), false);
    /// assert_eq!(meta.has_xrefs_to(),   false);
    ///
    /// ws.make_insn(RVA(0x0)).unwrap();
    /// ws.analyze();
    ///
    /// let meta = ws.get_meta(RVA(0x0)).unwrap();
    /// assert_eq!(meta.has_xrefs_from(), true);
    /// assert_eq!(meta.has_xrefs_to(),   true);
    /// ```
    fn handle_make_xref(&mut self, xref: Xref) -> Result<Vec<AnalysisCommand>, Error> {
        // outline:
        //  1. validate arguments
        //  2. insert xref-from src, if not exists
        //  3. if did (2), insert xref-to dst

        // step 1. validate arguments
        if !self.probe(xref.src, 1, Permissions::X) {
            warn!("invalid xref src address: {:#x}", xref.src);
            return Ok(vec![]);
        }
        if !self.probe(xref.dst, 1, Permissions::X) {
            warn!("invalid xref dst address: {:#x}", xref.dst);
            return Ok(vec![]);
        }

        // since we already validated the xref,
        // meta unwraps should be safe here.

        // step 2a: update src flowmeta flag indicating xrefs-from
        {
            let srcmeta = self.get_meta_mut(xref.src).expect("flowmeta not in section");
            if !srcmeta.has_xrefs_from() {
                srcmeta.set_xrefs_from();
            }
        }

        // step 2b: update src xrefs-from with xref, it not exists
        let is_new = {
            let xrefs = self
                .analysis
                .flow
                .xrefs
                .from
                .entry(xref.src)
                .or_insert_with(HashSet::new);
            xrefs.insert(xref)
        };

        // step 3: only if new entry, then insert dst xrefs-to
        if is_new {
            {
                let dstmeta = self.get_meta_mut(xref.dst).expect("flowmeta not in section");
                if !dstmeta.has_xrefs_to() {
                    dstmeta.set_xrefs_to();
                }
            }

            {
                let xrefs = self
                    .analysis
                    .flow
                    .xrefs
                    .to
                    .entry(xref.dst)
                    .or_insert_with(HashSet::new);
                xrefs.insert(xref);
            }
        }

        Ok(vec![])
    }

    fn handle_make_symbol(&mut self, rva: RVA, name: &str) -> Result<Vec<AnalysisCommand>, Error> {
        if !self.probe(rva, 1, Permissions::R) {
            warn!("invalid symbol address: {:#x}", rva);
            return Ok(vec![]);
        }

        self.analysis.symbols.entry(rva).or_insert_with(|| {
            debug!("adding symbol: {} -> \"{}\"", rva, name);
            name.to_string()
        });

        Ok(vec![])
    }

    fn handle_make_function(&mut self, rva: RVA) -> Result<Vec<AnalysisCommand>, Error> {
        // TODO: probably ensure this is code, not just readable.
        if !self.probe(rva, 1, Permissions::X) {
            warn!("invalid function address: {:#x}", rva);
            return Ok(vec![]);
        }

        if self.analysis.functions.insert(rva) {
            debug!("adding function: {}", rva);
        };

        Ok(vec![AnalysisCommand::MakeInsn(rva)])
    }

    /// ```
    /// use lancelot::test;
    /// use lancelot::arch::RVA;
    ///
    /// // JMP $+0;
    /// let mut ws = test::get_shellcode32_workspace(b"\xEB\xFE");
    /// ws.make_insn(RVA(0x0)).unwrap();
    /// ws.analyze();
    /// let meta = ws.get_meta(RVA(0x0)).unwrap();
    /// assert_eq!(meta.get_insn_length().unwrap(), 2);
    /// assert_eq!(meta.does_fallthrough(), false);
    /// ```
    pub fn analyze(&mut self) -> Result<(), Error> {
        while let Some(cmd) = self.analysis.queue.pop_front() {
            trace!("dispatching command: {:}", cmd);
            let cmds = match cmd {
                AnalysisCommand::MakeInsn(rva) => self.handle_make_insn(rva)?,
                AnalysisCommand::MakeXref(xref) => self.handle_make_xref(xref)?,
                AnalysisCommand::MakeSymbol{rva, name} => self.handle_make_symbol(rva, &name)?,
                AnalysisCommand::MakeFunction(rva) => self.handle_make_function(rva)?,
            };
            self.analysis.queue.extend(cmds);
        }

        Ok(())
    }
}


pub trait Analyzer {
    fn get_name(&self) -> String;
    fn analyze(&self, ws: &mut Workspace) -> Result<(), Error>;
}


