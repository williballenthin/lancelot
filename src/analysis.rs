use num::{FromPrimitive, ToPrimitive};
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::fmt::Display;
use std::fmt::Debug;
use std::hash::Hash;

use failure::{Error, Fail};
use log::{debug, info, warn};
use zydis::gen::*;

use super::arch;
use super::arch::Arch;
use super::flowmeta::FlowMeta;
use super::loader::{LoadedModule, Section};
use super::workspace::Workspace;
use super::xref::{Xref, XrefType};

#[derive(Debug, Fail)]
pub enum AnalysisError {
    #[fail(display = "Not implemented")]
    NotImplemented,
    #[fail(display = "foo")]
    InvalidInstruction,
}

#[derive(Debug, Clone)]
pub enum AnalysisCommand<A: Arch> {
    MakeInsn(A::RVA),
    MakeXref(Xref<A>),
    MakeSymbol {
        rva: A::RVA,
        name: String
    },
    MakeFunction(A::RVA),
}

impl<A: Arch + Debug> Display for AnalysisCommand<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            AnalysisCommand::MakeInsn(rva) => write!(f, "MakeInsn({:#x})", rva),
            AnalysisCommand::MakeXref(x) => write!(f, "MakeXref({:?})", x),
            AnalysisCommand::MakeSymbol{rva, name} => write!(f, "MakeSymbol({:?}, {})", rva, name),
            AnalysisCommand::MakeFunction(rva) => write!(f, "MakeFunction({:?})", rva),
        }
    }
}

pub fn get_first_operand(insn: &ZydisDecodedInstruction) -> Option<&ZydisDecodedOperand> {
    insn.operands
        .iter()
        .find(|op| op.visibility == ZYDIS_OPERAND_VISIBILITY_EXPLICIT as u8)
}

fn print_op(op: &ZydisDecodedOperand) {
    println!("op:");
    println!("  id: {}", op.id);
    println!("  type: {}", op.type_);
    println!("  visibility: {}", op.visibility);
    println!("  action: {}", op.action);
    println!("  encoding: {}", op.encoding);
    println!("  size: {}", op.size);
    match i32::from(op.type_) {
        ZYDIS_OPERAND_TYPE_MEMORY => {
            println!("  mem.addr gen only: {}", op.mem.isAddressGenOnly);
            println!("  mem.segment: {}", op.mem.segment);
            println!("  mem.base: {}", op.mem.base);
            println!("  mem.index: {}", op.mem.index);
            println!("  mem.scale: {}", op.mem.scale);
            println!(
                "  mem.disp.hasDisplacement: {}",
                op.mem.disp.hasDisplacement
            );
            if op.mem.disp.hasDisplacement != 0 {
                println!("  mem.disp.value: 0x{:x}", op.mem.disp.value);
            }
        }
        ZYDIS_OPERAND_TYPE_POINTER => {
            println!("  ptr.segment: 0x{:x}", op.ptr.segment);
            println!("  ptr.offset: 0x{:x}", op.ptr.offset);
        }
        ZYDIS_OPERAND_TYPE_IMMEDIATE => {
            println!("  imm.signed: {}", op.imm.isSigned);
            println!("  imm.relative: {}", op.imm.isRelative);
            if op.imm.isSigned != 0 {
                println!("  imm.value: (signed) {:#x}", *unsafe {
                    op.imm.value.s.as_ref()
                });
            } else {
                println!("  imm.value: (unsigned) {:#x}", *unsafe {
                    op.imm.value.u.as_ref()
                });
            }
        }
        ZYDIS_OPERAND_TYPE_REGISTER => {
            println!("  reg: {}", op.reg.value);
        }
        _ => {}
    }
}

pub struct XrefAnalysis<A: Arch> {
    // TODO: use FNV because the keys are small.
    // TODO: use SmallVec(1) for `.from` values,
    // TODO: use SmallVec(X) for `.to` values,

    // dst rva -> src rva
    to: HashMap<A::RVA, HashSet<Xref<A>>>,
    // src rva -> dst rva
    from: HashMap<A::RVA, HashSet<Xref<A>>>,
}

pub struct FlowAnalysis<A: Arch> {
    // one entry for each section in the module.
    // if executable, then one FlowMeta for each address in the section.
    // that is, Vec<FlowMeta>.len() == Section.buf.len()
    // TODO: order these entries so that the most common sections are first (`.code`?)
    meta: Vec<Vec<FlowMeta>>,
    xrefs: XrefAnalysis<A>,
}

pub struct Analysis<A: Arch> {
    queue: VecDeque<AnalysisCommand<A>>,

    // TODO: FNV
    functions: HashSet<A::RVA>,

    // TODO: FNV
    symbols: HashMap<A::RVA, String>,

    flow: FlowAnalysis<A>,
    // datameta
    // symbols
    // functions
}

impl<A: Arch> Analysis<A> {
    pub fn new(module: &LoadedModule<A>) -> Analysis<A> {
        let flow_meta: Vec<Vec<FlowMeta>> = module
            .sections
            .iter()
            .map(|section| -> Vec<FlowMeta> {
                if section.is_executable() {
                    vec![FlowMeta::zero(); section.buf.len()]
                } else {
                    vec![]
                }
            })
            .collect();

        Analysis {
            queue: VecDeque::new(),
            functions: HashSet::new(),
            symbols: HashMap::new(),
            flow: FlowAnalysis {
                meta: flow_meta,
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
impl<A: Arch + 'static + Debug + Eq + Hash> Workspace<A> {
    /// ```
    /// use lancelot::test;
    ///
    /// // NOP
    /// // JMP $+0;
    /// let mut ws = test::get_shellcode32_workspace(b"\x90\xEB\xFE");
    /// ws.make_insn(0x0);
    /// ws.analyze();
    ///
    /// assert!( ws.get_meta(0x0).unwrap().is_insn());
    /// assert!( ws.get_meta(0x1).unwrap().is_insn());
    /// assert!(!ws.get_meta(0x2).unwrap().is_insn());
    /// ```
    pub fn make_insn(&mut self, rva: A::RVA) -> Result<(), Error> {
        self.analysis
            .queue
            .push_back(AnalysisCommand::MakeInsn(rva));
        Ok(())
    }

    /// ```
    /// use lancelot::test;
    ///
    /// // JMP $+0;
    /// let mut ws = test::get_shellcode32_workspace(b"\xEB\xFE");
    /// assert!(ws.get_symbol(0x0).is_none());
    /// ws.make_symbol(0x0, "entry");
    /// ws.analyze();
    /// assert_eq!(ws.get_symbol(0x0).unwrap(), "entry");
    /// ```
    pub fn make_symbol(&mut self, rva: A::RVA, name: &str) -> Result<(), Error> {
        self.analysis
            .queue
            .push_back(AnalysisCommand::MakeSymbol{rva: rva, name: name.to_string()});
        Ok(())
    }

    pub fn get_functions(&self ) -> impl Iterator<Item=&A::RVA> {
        self.analysis.functions.iter()
    }

    /// ```
    /// use lancelot::test;
    ///
    /// // JMP $+0;
    /// let mut ws = test::get_shellcode32_workspace(b"\xEB\xFE");
    /// assert!(ws.get_functions().collect::<Vec<_>>().is_empty());
    /// ws.make_function(0x0);
    /// ws.analyze();
    ///
    /// assert!(ws.get_meta(0x0).unwrap().is_insn());
    /// assert_eq!(ws.get_functions().collect::<Vec<_>>().len(), 1);
    /// ```
    pub fn make_function(&mut self, rva: A::RVA) -> Result<(), Error> {
        self.analysis
            .queue
            .push_back(AnalysisCommand::MakeFunction(rva));
        Ok(())
    }

    pub fn get_symbol(&self,  rva: A::RVA) -> Option<&String> {
        self.analysis.symbols.get(&rva)
    }

    /// fetch the (section, offset) indices for the given RVA.
    fn get_coords(&self, rva: A::RVA) -> Option<(usize, usize)> {
        self.module
            .sections
            .iter()
            .enumerate()
            .filter(|(_, section)| section.contains(rva))
            .nth(0)
            .and_then(
                |(i, section): (usize, &Section<A>)| -> Option<(usize, usize)> {
                    // rva is guaranteed to be within this section,
                    // so we can do an unchecked subtract here.
                    let offset = rva - section.addr;
                    A::RVA::to_usize(&offset).and_then(|offset| Some((i, offset)))
                },
            )
    }

    pub fn get_meta(&self, rva: A::RVA) -> Option<FlowMeta> {
        self.get_coords(rva)
            .and_then(|(section, offset)| Some(self.analysis.flow.meta[section][offset]))
    }

    /// Does the given instruction have a fallthrough flow?
    ///
    /// ```
    /// use lancelot::test;
    /// use lancelot::arch::*;
    /// use lancelot::workspace::*;
    ///
    /// // JMP $+0;
    /// let insn = test::get_shellcode32_workspace(b"\xEB\xFE").read_insn(0x0).unwrap();
    /// assert_eq!(Workspace::<Arch32>::does_insn_fallthrough(&insn), false);
    ///
    /// // PUSH 0x11
    /// let insn = test::get_shellcode32_workspace(b"\x6A\x11").read_insn(0x0).unwrap();
    /// assert_eq!(Workspace::<Arch32>::does_insn_fallthrough(&insn), true);
    /// ```
    pub fn does_insn_fallthrough(insn: &ZydisDecodedInstruction) -> bool {
        match i32::from(insn.mnemonic) {
            ZYDIS_MNEMONIC_JMP => false,
            ZYDIS_MNEMONIC_RET => false,
            ZYDIS_MNEMONIC_IRET => false,
            ZYDIS_MNEMONIC_IRETD => false,
            ZYDIS_MNEMONIC_IRETQ => false,
            // TODO: call may not fallthrough if function is noret.
            // will need another pass to clean this up.
            ZYDIS_MNEMONIC_CALL => true,
            _ => true,
        }
    }

    /// ## test simple memory ptr operand
    ///
    /// ```
    /// use lancelot::test;
    /// use lancelot::analysis;
    ///
    /// // 0:  ff 25 06 00 00 00   +->  jmp    DWORD PTR ds:0x6
    /// // 6:  00 00 00 00         +--  dw     0x0
    /// let mut ws = test::get_shellcode32_workspace(b"\xFF\x25\x06\x00\x00\x00\x00\x00\x00\x00");
    /// let insn = ws.read_insn(0x0).unwrap();
    /// let op = analysis::get_first_operand(&insn).unwrap();
    /// let xref = ws.get_memory_operand_xref(0x0, &insn, &op).unwrap();
    ///
    /// assert_eq!(xref.is_some(), true);
    /// assert_eq!(xref.unwrap(), 0x0);
    /// ```
    ///
    /// ## test RIP-relative
    ///
    /// ```
    /// use lancelot::test;
    /// use lancelot::analysis;
    ///
    /// // FF 15 00 00 00 00         CALL $+5
    /// // 00 00 00 00 00 00 00 00   dq 0x0
    /// let mut ws = test::get_shellcode64_workspace(b"\xFF\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
    /// let insn = ws.read_insn(0x0).unwrap();
    /// let op = analysis::get_first_operand(&insn).unwrap();
    /// let xref = ws.get_memory_operand_xref(0x0, &insn, &op).unwrap();
    ///
    /// assert_eq!(xref.is_some(), true);
    /// assert_eq!(xref.unwrap(), 0x0);
    /// ```
    pub fn get_memory_operand_xref(
        &self,
        rva: A::RVA,
        insn: &ZydisDecodedInstruction,
        op: &ZydisDecodedOperand,
    ) -> Result<Option<A::RVA>, Error> {
        if op.mem.base == 0
            && op.mem.index == 0
            && op.mem.scale == 0
            && op.mem.disp.hasDisplacement == 1
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

            let ptr = match A::VA::from_i64(op.mem.disp.value) {
                Some(ptr) => ptr,
                None => return Ok(None),
            };

            let ptr = match arch::va_compute_rva::<A>(self.module.base_address, ptr) {
                Some(ptr) => ptr,
                None => return Ok(None),
            };

            let dst = match self.read_va(ptr) {
                Ok(dst) => dst,
                Err(_) => return Ok(None),
            };

            let dst = match arch::va_compute_rva::<A>(self.module.base_address, dst) {
                Some(dst) => dst,
                None => return Ok(None),
            };

            if !self.probe(dst, 1) {
                return Ok(None);
            };

            // this is the happy path!
            return Ok(Some(dst));
        } else if op.mem.base == ZYDIS_REGISTER_RIP as u8
            // only valid on x64
            && op.mem.index == 0
            && op.mem.scale == 0
            && op.mem.disp.hasDisplacement == 1 {

                // this is RIP-relative addressing.
                // it works like a relative immediate,
                // that is: dst = *(rva + displacement + instruction len)

                let disp = A::RVA::from_i64(op.mem.disp.value);
                let len = A::RVA::from_u8(insn.length);

                let (disp, len) = match (disp, len) {
                    (Some(disp), Some(len)) => (disp, len),
                    _ => return Ok(None),
                };

                // TODO: this should be checked add
                let ptr = rva + disp + len;

                let dst = match self.read_va(ptr) {
                    Ok(dst) => dst,
                    Err(_) => return Ok(None),
                };

                let dst = match arch::va_compute_rva::<A>(self.module.base_address, dst) {
                    Some(dst) => dst,
                    None => return Ok(None),
                };

                if !self.probe(dst, 1) {
                    return Ok(None);
                };

                // this is the happy path!
                return Ok(Some(dst));
        } else {
            println!("get mem op xref");
            print_op(op);
            panic!("not supported");
        }
    }

    fn get_pointer_operand_xref(
        &self,
        rva: A::RVA,
        insn: &ZydisDecodedInstruction,
        op: &ZydisDecodedOperand,
    ) -> Result<Option<A::RVA>, Error> {
        // TODO
        println!("get ptr op xref");
        print_op(op);
        panic!("not supported");
        Ok(None)
    }

    /// ## test relative immediate operand
    ///
    /// ```
    /// use lancelot::test;
    /// use lancelot::analysis;
    ///
    /// // this is a jump from addr 0x0 to itself:
    /// // JMP $+0;
    /// let mut ws = test::get_shellcode32_workspace(b"\xEB\xFE");
    /// let insn = ws.read_insn(0x0).unwrap();
    /// let op = analysis::get_first_operand(&insn).unwrap();
    /// let xref = ws.get_immediate_operand_xref(0x0, &insn, &op).unwrap();
    ///
    /// assert_eq!(xref.is_some(), true);
    /// assert_eq!(xref.unwrap(), 0x0);
    ///
    ///
    /// // this is a jump from addr 0x0 to -1, which is unmapped
    /// // JMP $-1;
    /// let mut ws = test::get_shellcode32_workspace(b"\xEB\xFD");
    /// let insn = ws.read_insn(0x0).unwrap();
    /// let op = analysis::get_first_operand(&insn).unwrap();
    /// let xref = ws.get_immediate_operand_xref(0x0, &insn, &op).unwrap();
    ///
    /// assert_eq!(xref.is_some(), false);
    /// ```
    pub fn get_immediate_operand_xref(
        &self,
        rva: A::RVA,
        insn: &ZydisDecodedInstruction,
        op: &ZydisDecodedOperand,
    ) -> Result<Option<A::RVA>, Error> {
        // TODO
        if op.imm.isRelative != 0 {
            // the operand is an immediate constant relative to $PC.
            // destination = $pc + immediate + insn.len
            //
            // see doctest: [test relative immediate operand]()

            // the use of `unsafe` here is an artifact of the zydis API.
            let imm = if op.imm.isSigned != 0 {
                A::RVA::from_i64(*unsafe { op.imm.value.s.as_ref() })
            } else {
                A::RVA::from_u64(*unsafe { op.imm.value.u.as_ref() })
            };

            let len = A::RVA::from_u8(insn.length);

            if let (Some(imm), Some(len)) = (imm, len) {
                // TODO: this should be checked add
                let dst = rva + imm + len;

                if self.probe(dst, 1) {
                    Ok(Some(dst))
                } else {
                    // invalid address
                    Ok(None)
                }
            } else {
                // `imm` (u64) could not fit within an RVA,
                // so it doesn't make sense for this to be an address.
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
        rva: A::RVA,
        insn: &ZydisDecodedInstruction,
        op: &ZydisDecodedOperand,
    ) -> Result<Option<A::RVA>, Error> {
        match i32::from(op.type_) {
            // TODO: need a way to add xrefs for the pointer for something like `CALL [0x0]`
            // like: .text:0000000180001041 FF 15 D1 78 07 00      call    cs:__imp_RtlVirtualUnwind_0
            //           0x0000000000001041:                       call    [0x0000000000079980]
            ZYDIS_OPERAND_TYPE_MEMORY => self.get_memory_operand_xref(rva, insn, op),
            // like: EA 33 D2 B9 60 80 40  jmp  far ptr 4080h:60B9D233h
            // "ptr": {
            //    "segment": 16512,
            //    "offset": 1622790707
            // },
            ZYDIS_OPERAND_TYPE_POINTER => self.get_pointer_operand_xref(rva, insn, op),
            ZYDIS_OPERAND_TYPE_IMMEDIATE => self.get_immediate_operand_xref(rva, insn, op),
            // like: CALL rax
            // which cannot be resolved without emulation.
            ZYDIS_OPERAND_TYPE_REGISTER => Ok(None),
            ZYDIS_OPERAND_TYPE_UNUSED => Ok(None),
            _ => Ok(None),
        }
    }

    /// ```
    /// use lancelot::test;
    ///
    /// // E8 00 00 00 00  CALL $+5
    /// // 90              NOP
    /// let mut ws = test::get_shellcode32_workspace(b"\xE8\x00\x00\x00\x00\x90");
    /// let insn = ws.read_insn(0x0).unwrap();
    /// let xrefs = ws.get_call_insn_flow(0x0, &insn).unwrap();
    /// assert_eq!(xrefs[0].dst, 0x5);
    /// ```
    pub fn get_call_insn_flow(
        &self,
        rva: A::RVA,
        insn: &ZydisDecodedInstruction,
    ) -> Result<Vec<Xref<A>>, Error> {
        // if this is not a CALL, then its a programming error. panic!
        // all CALLs should have an operand.
        let op = get_first_operand(insn).unwrap();

        match self.get_operand_xref(rva, insn, op)? {
            Some(dst) => Ok(vec![Xref {
                src: rva,
                dst: dst,
                typ: XrefType::Call,
            }]),
            None => Ok(vec![]),
        }
    }

    /// ```
    /// use lancelot::test;
    ///
    /// // E9 00 00 00 00  JMP $+5
    /// // 90              NOP
    /// let mut ws = test::get_shellcode32_workspace(b"\xE9\x00\x00\x00\x00\x90");
    /// let insn = ws.read_insn(0x0).unwrap();
    /// let xrefs = ws.get_jmp_insn_flow(0x0, &insn).unwrap();
    /// assert_eq!(xrefs[0].dst, 0x5);
    /// ```
    pub fn get_jmp_insn_flow(
        &self,
        rva: A::RVA,
        insn: &ZydisDecodedInstruction,
    ) -> Result<Vec<Xref<A>>, Error> {
        // if this is not a JMP, then its a programming error. panic!
        // all JMPs should have an operand.
        let op = get_first_operand(insn).unwrap();

        match self.get_operand_xref(rva, insn, op)? {
            Some(dst) => Ok(vec![Xref {
                src: rva,
                dst: dst,
                typ: XrefType::UnconditionalJump,
            }]),
            None => Ok(vec![]),
        }
    }

    /// ```
    /// use lancelot::test;
    ///
    /// // C3  RETN
    /// let mut ws = test::get_shellcode32_workspace(b"\xC3");
    /// let insn = ws.read_insn(0x0).unwrap();
    /// let xrefs = ws.get_ret_insn_flow(0x0, &insn).unwrap();
    /// assert_eq!(xrefs.len(), 0);
    /// ```
    pub fn get_ret_insn_flow(
        &self,
        rva: A::RVA,
        insn: &ZydisDecodedInstruction,
    ) -> Result<Vec<Xref<A>>, Error> {
        Ok(vec![])
    }

    /// ```
    /// use lancelot::test;
    ///
    /// // 75 01 JNZ $+1
    /// // CC    BREAK
    /// // 90    NOP
    /// let mut ws = test::get_shellcode32_workspace(b"\x75\x01\xCC\x90");
    /// let insn = ws.read_insn(0x0).unwrap();
    /// let xrefs = ws.get_cjmp_insn_flow(0x0, &insn).unwrap();
    /// assert_eq!(xrefs[0].dst, 0x3);
    /// ```
    pub fn get_cjmp_insn_flow(
        &self,
        rva: A::RVA,
        insn: &ZydisDecodedInstruction,
    ) -> Result<Vec<Xref<A>>, Error> {
        // if this is not a CJMP, then its a programming error. panic!
        // all conditional jumps should have an operand.
        let op = get_first_operand(insn).unwrap();

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
    ///
    /// // 0F 44 C3  CMOVZ EAX, EBX
    /// // 90        NOP
    /// let mut ws = test::get_shellcode32_workspace(b"\x0F\x44\xC3\x90");
    /// let insn = ws.read_insn(0x0).unwrap();
    /// let xrefs = ws.get_cmov_insn_flow(0x0, &insn).unwrap();
    /// assert_eq!(xrefs[0].dst, 0x3);
    /// ```
    pub fn get_cmov_insn_flow(
        &self,
        rva: A::RVA,
        insn: &ZydisDecodedInstruction,
    ) -> Result<Vec<Xref<A>>, Error> {
        let len = A::RVA::from_u8(insn.length).unwrap();
        let dst = rva + len;

        Ok(vec![Xref {
            src: rva,
            dst: dst,
            typ: XrefType::ConditionalMove,
        }])
    }

    fn get_insn_flow(
        &self,
        rva: A::RVA,
        insn: &ZydisDecodedInstruction,
    ) -> Result<Vec<Xref<A>>, Error> {
        match i32::from(insn.mnemonic) {
            ZYDIS_MNEMONIC_CALL => self.get_call_insn_flow(rva, insn),

            ZYDIS_MNEMONIC_JMP => self.get_jmp_insn_flow(rva, insn),

            ZYDIS_MNEMONIC_RET | ZYDIS_MNEMONIC_IRET | ZYDIS_MNEMONIC_IRETD
            | ZYDIS_MNEMONIC_IRETQ => self.get_ret_insn_flow(rva, insn),

            ZYDIS_MNEMONIC_JB | ZYDIS_MNEMONIC_JBE | ZYDIS_MNEMONIC_JCXZ | ZYDIS_MNEMONIC_JECXZ
            | ZYDIS_MNEMONIC_JKNZD | ZYDIS_MNEMONIC_JKZD | ZYDIS_MNEMONIC_JL
            | ZYDIS_MNEMONIC_JLE | ZYDIS_MNEMONIC_JNB | ZYDIS_MNEMONIC_JNBE
            | ZYDIS_MNEMONIC_JNL | ZYDIS_MNEMONIC_JNLE | ZYDIS_MNEMONIC_JNO
            | ZYDIS_MNEMONIC_JNP | ZYDIS_MNEMONIC_JNS | ZYDIS_MNEMONIC_JNZ | ZYDIS_MNEMONIC_JO
            | ZYDIS_MNEMONIC_JP | ZYDIS_MNEMONIC_JRCXZ | ZYDIS_MNEMONIC_JS | ZYDIS_MNEMONIC_JZ => {
                self.get_cjmp_insn_flow(rva, insn)
            }

            ZYDIS_MNEMONIC_CMOVB
            | ZYDIS_MNEMONIC_CMOVBE
            | ZYDIS_MNEMONIC_CMOVL
            | ZYDIS_MNEMONIC_CMOVLE
            | ZYDIS_MNEMONIC_CMOVNB
            | ZYDIS_MNEMONIC_CMOVNBE
            | ZYDIS_MNEMONIC_CMOVNL
            | ZYDIS_MNEMONIC_CMOVNLE
            | ZYDIS_MNEMONIC_CMOVNO
            | ZYDIS_MNEMONIC_CMOVNP
            | ZYDIS_MNEMONIC_CMOVNS
            | ZYDIS_MNEMONIC_CMOVNZ
            | ZYDIS_MNEMONIC_CMOVO
            | ZYDIS_MNEMONIC_CMOVP
            | ZYDIS_MNEMONIC_CMOVS
            | ZYDIS_MNEMONIC_CMOVZ => self.get_cmov_insn_flow(rva, insn),

            // TODO: syscall, sysexit, sysret, vmcall, vmmcall
            _ => Ok(vec![]),
        }
    }

    fn handle_make_insn(&mut self, rva: A::RVA) -> Result<Vec<AnalysisCommand<A>>, Error> {
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
            debug!("duplicate instruction: {:x}", rva);
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
        let does_fallthrough = Workspace::<A>::does_insn_fallthrough(&insn);

        // 4. compute flow ref
        // TODO: maybe don't fail, but just return empty list?
        let flows = self.get_insn_flow(rva, &insn)?;
        ret.extend(flows.iter().map(|f| AnalysisCommand::MakeXref(*f)));
        ret.extend(flows.iter().map(|f| match f.typ {
            XrefType::Call => AnalysisCommand::MakeFunction(f.dst),
            _ => AnalysisCommand::MakeInsn(f.dst),
        }));

        if does_fallthrough {
            // u8 can always go into an RVA (u32 or greater).
            let len = A::RVA::from_u8(insn.length).unwrap();
            ret.push(AnalysisCommand::MakeInsn(rva + len));
        }

        // 5. update flowmeta
        {
            let (section, offset) = self.get_coords(rva).unwrap();
            let meta = &mut self.analysis.flow.meta[section][offset];

            meta.set_insn_length(length);

            if does_fallthrough {
                meta.set_fallthrough();
            }
        }

        Ok(ret)
    }

    /// ```
    /// use lancelot::test;
    ///
    /// // JMP $+0;
    /// let mut ws = test::get_shellcode32_workspace(b"\xEB\xFE");
    /// let meta = ws.get_meta(0x0).unwrap();
    /// assert_eq!(meta.has_xrefs_from(), false);
    /// assert_eq!(meta.has_xrefs_to(),   false);
    ///
    /// ws.make_insn(0x0).unwrap();
    /// ws.analyze();
    ///
    /// let meta = ws.get_meta(0x0).unwrap();
    /// assert_eq!(meta.has_xrefs_from(), true);
    /// assert_eq!(meta.has_xrefs_to(),   true);
    /// ```
    fn handle_make_xref(&mut self, xref: Xref<A>) -> Result<Vec<AnalysisCommand<A>>, Error> {
        // outline:
        //  1. validate arguments
        //  2. insert xref-from src, if not exists
        //  3. if did (2), insert xref-to dst

        // step 1. validate arguments
        if !self.probe(xref.src, 1) {
            warn!("invalid xref src address: {:#x}", xref.src);
            return Ok(vec![]);
        }
        if !self.probe(xref.dst, 1) {
            warn!("invalid xref dst address: {:#x}", xref.dst);
            return Ok(vec![]);
        }

        // since we already validated the xref,
        // unwrap should be safe here.
        //
        // TODO: we are duplicating the validation here.
        let srcco = self.get_coords(xref.src).unwrap();
        let dstco = self.get_coords(xref.dst).unwrap();

        // step 2a: update src flowmeta flag indicating xrefs-from
        {
            let srcmeta = &mut self.analysis.flow.meta[srcco.0][srcco.1];
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
                let dstmeta = &mut self.analysis.flow.meta[dstco.0][dstco.1];
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

    fn handle_make_symbol(&mut self, rva: A::RVA, name: &str) -> Result<Vec<AnalysisCommand<A>>, Error> {
        if !self.probe(rva, 1) {
            warn!("invalid symbol address: {:#x}", rva);
            return Ok(vec![]);
        }

        self.analysis.symbols.entry(rva).or_insert_with(|| {
            debug!("adding symbol: {:#x} -> {}", rva, name);
            name.to_string()
        });

        Ok(vec![])
    }

    fn handle_make_function(&mut self, rva: A::RVA) -> Result<Vec<AnalysisCommand<A>>, Error> {
        // TODO: probably ensure this is code, not just readable.
        if !self.probe(rva, 1) {
            warn!("invalid function address: {:#x}", rva);
            return Ok(vec![]);
        }

        if self.analysis.functions.insert(rva) {
            debug!("adding function: {:#x}", rva);
        };

        Ok(vec![AnalysisCommand::MakeInsn(rva)])
    }

    /// ```
    /// use lancelot::test;
    ///
    /// // JMP $+0;
    /// let mut ws = test::get_shellcode32_workspace(b"\xEB\xFE");
    /// ws.make_insn(0x0).unwrap();
    /// ws.analyze();
    /// let meta = ws.get_meta(0x0).unwrap();
    /// assert_eq!(meta.get_insn_length().unwrap(), 2);
    /// assert_eq!(meta.does_fallthrough(), false);
    /// ```
    pub fn analyze(&mut self) -> Result<(), Error> {
        while let Some(cmd) = self.analysis.queue.pop_front() {
            debug!("dispatching command: {:}", cmd);
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
