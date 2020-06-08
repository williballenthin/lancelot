use std::collections::{BTreeMap, VecDeque};

use anyhow::Result;
use log::debug;
use smallvec::{smallvec, SmallVec};

use crate::{
    analysis::dis,
    aspace::AddressSpace,
    module::{Module, Permissions},
    util, VA,
};

/// The type and destination of a control flow.
#[derive(Debug, Clone, Copy)]
pub enum Flow {
    // mov eax, eax
    // push ebp
    Fallthrough(VA),

    // call [0x401000]
    Call(VA),

    // call [eax]
    //IndirectCall { src: Rva },

    // jmp 0x401000
    UnconditionalJump(VA),

    // jmp eax
    //UnconditionalIndirectJump { src: Rva, dst: Rva },

    // jnz 0x401000
    ConditionalJump(VA),

    // jnz eax
    //ConditionalIndirectJump { src: Rva },

    // cmov 0x1
    ConditionalMove(VA),
}

impl Flow {
    pub fn va(&self) -> VA {
        match *self {
            Flow::Fallthrough(va) => va,
            Flow::Call(va) => va,
            Flow::UnconditionalJump(va) => va,
            Flow::ConditionalJump(va) => va,
            Flow::ConditionalMove(va) => va,
        }
    }

    /// create a new Flow with the va swapped out for the given va.
    /// useful when you have a flow edge that you want to reverse
    /// (e.g. from successor to predecessor).
    pub fn swap(&self, va: VA) -> Flow {
        match *self {
            Flow::Fallthrough(_) => Flow::Fallthrough(va),
            Flow::Call(_) => Flow::Call(va),
            Flow::UnconditionalJump(_) => Flow::UnconditionalJump(va),
            Flow::ConditionalJump(_) => Flow::ConditionalJump(va),
            Flow::ConditionalMove(_) => Flow::ConditionalMove(va),
        }
    }
}

/// most instructions have 1-2 flows, so attempt to store the inline.
type Flows = SmallVec<[Flow; 2]>;

#[derive(Debug, Clone)]
pub struct BasicBlock {
    /// start VA of the basic block.
    pub addr: VA,

    /// length of the basic block in bytes.
    pub length: u64,

    /// VAs of start addresses of basic blocks that flow here.
    pub predecessors: Flows,

    /// VAs of start addresses of basic blocks that flow from here.
    pub successors: Flows,
}

pub struct CFG {
    // using FNV because the keys are small
    basic_blocks: BTreeMap<VA, BasicBlock>,
}

/// Does the given instruction have a fallthrough flow?
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

fn va_add_signed(va: VA, rva: i64) -> Option<VA> {
    if rva >= 0 {
        va.checked_add(rva as u64)
    } else {
        if i64::abs(rva) as u64 > va {
            // this would overflow, which:
            //  1. we don't expect, and
            //  2. we can't handle
            None
        } else {
            Some(va - i64::abs(rva) as u64)
        }
    }
}

fn print_op(_op: &zydis::DecodedOperand) {
    println!("op: TODO(print_op)");
    /*
    let s = serde_json::to_string(op).unwrap();
    println!("op: {}", s);
    */
}

/// zydis supports implicit operands,
/// which we don't currently use in our analysis.
/// so, fetch the first explicit operand to an instruction.
pub fn get_first_operand(insn: &zydis::DecodedInstruction) -> Option<&zydis::DecodedOperand> {
    insn.operands
        .iter()
        .find(|op| op.visibility == zydis::OperandVisibility::EXPLICIT)
}

/// ## test simple memory ptr operand
///
/// ```
/// use lancelot::test::*;
/// use lancelot::analysis::dis::get_disassembler;
/// use lancelot::analysis::cfg::{get_first_operand, get_memory_operand_xref};
///
/// // 0:  ff 25 06 00 00 00   +->  jmp    DWORD PTR ds:0x6
/// // 6:  00 00 00 00         +--  dw     0x0
/// let mut module = load_shellcode32(b"\xFF\x25\x06\x00\x00\x00\x00\x00\x00\x00");
/// let insn = read_insn(&module, 0x0);
/// let op = get_first_operand(&insn).unwrap();
/// let xref = get_memory_operand_xref(&module, 0x0, &insn, &op).unwrap();
///
/// assert_eq!(xref.is_some(), true);
/// assert_eq!(xref.unwrap(), 0x0);
/// ```
///
/// ## test RIP-relative
///
/// ```
/// use lancelot::test::*;
/// use lancelot::analysis::dis::get_disassembler;
/// use lancelot::analysis::cfg::{get_first_operand, get_memory_operand_xref};
///
/// // FF 15 00 00 00 00         CALL $+5
/// // 00 00 00 00 00 00 00 00   dq 0x0
/// let mut module = load_shellcode64(b"\xFF\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
/// let insn = read_insn(&module, 0x0);
/// let op = get_first_operand(&insn).unwrap();
/// let xref = get_memory_operand_xref(&module, 0x0, &insn, &op).unwrap();
///
/// assert_eq!(xref.is_some(), true);
/// assert_eq!(xref.unwrap(), 0x0);
/// ```
#[allow(clippy::if_same_then_else)]
pub fn get_memory_operand_xref(
    module: &Module,
    va: VA,
    insn: &zydis::DecodedInstruction,
    op: &zydis::DecodedOperand,
) -> Result<Option<VA>> {
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
            return Ok(None);
        }
        let ptr: VA = op.mem.disp.displacement as u64;

        let dst = match module.read_va_at_va(ptr) {
            Ok(dst) => dst,
            Err(_) => return Ok(None),
        };

        if !module.probe_va(dst, Permissions::X) {
            return Ok(None);
        };

        // this is the happy path!
        Ok(Some(dst))
    } else if op.mem.base == zydis::Register::RIP
        // only valid on x64
        && op.mem.index == zydis::Register::NONE
        && op.mem.scale == 0
        && op.mem.disp.has_displacement
    {
        // this is RIP-relative addressing.
        // it works like a relative immediate,
        // that is: dst = *(rva + displacement + instruction len)

        let ptr = match va_add_signed(va + insn.length as u64, op.mem.disp.displacement as i64) {
            None => return Ok(None),
            Some(ptr) => ptr,
        };

        let dst = match module.read_va_at_va(ptr) {
            Ok(dst) => dst,
            Err(_) => return Ok(None),
        };

        if !module.probe_va(dst, Permissions::X) {
            return Ok(None);
        };

        // this is the happy path!
        Ok(Some(dst))
    } else if op.mem.base != zydis::Register::NONE {
        // this is something like `CALL [eax+4]`
        // can't resolve without emulation
        // TODO: add test
        Ok(None)
    } else if op.mem.scale == 0x4 {
        // this is something like `JMP [0x1000+eax*4]` (32-bit)
        Ok(None)
    } else {
        println!("{:#x}: get mem op xref", va);
        print_op(op);
        panic!("not supported");
    }
}

/// ```
/// use lancelot::test::*;
/// use lancelot::analysis::dis::get_disassembler;
/// use lancelot::analysis::cfg::{get_first_operand, get_pointer_operand_xref};
///
/// // this is a far ptr jump from addr 0x0 to itmodule:
/// // JMP FAR PTR 0:00000000
/// // [ EA ] [ 00 00 00 00 ] [ 00 00 ]
/// // opcode   ptr            segment
/// let mut module = load_shellcode32(b"\xEA\x00\x00\x00\x00\x00\x00");
/// let insn = read_insn(&module, 0x0);
/// let op = get_first_operand(&insn).unwrap();
/// let xref = get_pointer_operand_xref(&op).unwrap();
///
/// assert_eq!(xref.is_some(), true, "has pointer operand xref");
/// assert_eq!(xref.unwrap(), 0x0, "correct pointer operand xref");
/// ```
pub fn get_pointer_operand_xref(op: &zydis::DecodedOperand) -> Result<Option<VA>> {
    // ref: https://c9x.me/x86/html/file_module_x86_id_147.html
    //
    // > Far Jumps in Real-Address or Virtual-8086 Mode.
    // > When executing a far jump in realaddress or virtual-8086 mode,
    // > the processor jumps to the code segment and offset specified with the
    // target operand. > Here the target operand specifies an absolute far
    // address either directly with a > pointer (ptr16:16 or ptr16:32) or
    // indirectly with a memory location (m16:16 or m16:32). > With the
    // pointer method, the segment and address of the called procedure is encoded
    // > in the instruction, using a 4-byte (16-bit operand size) or
    // > 6-byte (32-bit operand size) far address immediate.
    // TODO: do something intelligent with the segment.
    Ok(Some(op.ptr.offset as u64))
}

/// ## test relative immediate operand
///
/// ```
/// use lancelot::test::*;
/// use lancelot::analysis::dis::get_disassembler;
/// use lancelot::analysis::cfg::{get_first_operand, get_immediate_operand_xref};
///
/// // this is a jump from addr 0x0 to itmodule:
/// // JMP $+0;
/// let mut module = load_shellcode32(b"\xEB\xFE");
/// let insn = read_insn(&module, 0x0);
/// let op = get_first_operand(&insn).unwrap();
/// let xref = get_immediate_operand_xref(&module, 0x0, &insn, &op).unwrap();
///
/// assert_eq!(xref.is_some(), true, "has immediate operand");
/// assert_eq!(xref.unwrap(), 0x0, "correct immediate operand");
///
///
/// // this is a jump from addr 0x0 to -1, which is unmapped
/// // JMP $-1;
/// let mut module = load_shellcode32(b"\xEB\xFD");
/// let insn = read_insn(&module, 0x0);
/// let op = get_first_operand(&insn).unwrap();
/// let xref = get_immediate_operand_xref(&module, 0x0, &insn, &op).unwrap();
///
/// assert_eq!(xref.is_some(), false, "does not have immediate operand");
/// ```
pub fn get_immediate_operand_xref(
    module: &Module,
    va: VA,
    insn: &zydis::DecodedInstruction,
    op: &zydis::DecodedOperand,
) -> Result<Option<VA>> {
    if op.imm.is_relative {
        // the operand is an immediate constant relative to $PC.
        // destination = $pc + immediate + insn.len
        //
        // see doctest: [test relative immediate operand]()

        let imm = if op.imm.is_signed {
            util::u64_i64(op.imm.value)
        } else {
            op.imm.value as i64
        };

        let dst = match va_add_signed(va + insn.length as u64, imm) {
            None => return Ok(None),
            Some(dst) => dst,
        };

        if module.probe_va(dst, Permissions::X) {
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
    module: &Module,
    va: VA,
    insn: &zydis::DecodedInstruction,
    op: &zydis::DecodedOperand,
) -> Result<Option<VA>> {
    match op.ty {
        // like: .text:0000000180001041 FF 15 D1 78 07 00      call    cs:__imp_RtlVirtualUnwind_0
        //           0x0000000000001041:                       call    [0x0000000000079980]
        zydis::OperandType::MEMORY => get_memory_operand_xref(module, va, insn, op),

        // like: EA 33 D2 B9 60 80 40  jmp  far ptr 4080h:60B9D233h
        // "ptr": {
        //    "segment": 16512,
        //    "offset": 1622790707
        // },
        zydis::OperandType::POINTER => get_pointer_operand_xref(op),

        zydis::OperandType::IMMEDIATE => get_immediate_operand_xref(module, va, insn, op),

        // like: CALL rax
        // which cannot be resolved without emulation.
        zydis::OperandType::REGISTER => Ok(None),

        zydis::OperandType::UNUSED => Ok(None),
    }
}

/// ```
/// use lancelot::test::*;
/// use lancelot::analysis::dis::get_disassembler;
/// use lancelot::analysis::cfg::get_call_insn_flow;
///
/// // E8 00 00 00 00  CALL $+5
/// // 90              NOP
/// let mut module = load_shellcode32(b"\xE8\x00\x00\x00\x00\x90");
/// let insn = read_insn(&module, 0x0);
/// let flows = get_call_insn_flow(&module, 0x0, &insn).unwrap();
/// assert_eq!(flows[0].va(), 0x5);
/// ```
pub fn get_call_insn_flow(module: &Module, va: VA, insn: &zydis::DecodedInstruction) -> Result<Flows> {
    // if this is not a CALL, then its a programming error. panic!
    // all CALLs should have an operand.
    let op = get_first_operand(insn).expect("CALL has no operand");

    match get_operand_xref(module, va, insn, op)? {
        None => Ok(smallvec![]),
        Some(dst) => Ok(smallvec![Flow::Call(dst)]),
    }
}

/// ```
/// use lancelot::test::*;
/// use lancelot::analysis::dis::get_disassembler;
/// use lancelot::analysis::cfg::get_jmp_insn_flow;
///
/// // E9 00 00 00 00  JMP $+5
/// // 90              NOP
/// let mut module = load_shellcode32(b"\xE9\x00\x00\x00\x00\x90");
/// let insn = read_insn(&module, 0x0);
/// let flows = get_jmp_insn_flow(&module, 0x0, &insn).unwrap();
/// assert_eq!(flows[0].va(), 0x5);
/// ```
pub fn get_jmp_insn_flow(module: &Module, va: VA, insn: &zydis::DecodedInstruction) -> Result<Flows> {
    // if this is not a JMP, then its a programming error. panic!
    // all JMPs should have an operand.
    let op = get_first_operand(insn).expect("JMP has no target");

    if op.ty == zydis::OperandType::MEMORY
        && op.mem.scale == 0x4
        && op.mem.base == zydis::Register::NONE
        && op.mem.disp.has_displacement
    {
        // this looks like a switch table, e.g. `JMP [0x1000+ecx*4]`
        // it should probably be solved via emulation.
        // see analysis/pe/pointers.rs for some experiments looking at pointer tables.
        Ok(smallvec![])
    } else {
        match get_operand_xref(module, va, insn, op)? {
            None => Ok(smallvec![]),
            Some(dst) => Ok(smallvec![Flow::UnconditionalJump(dst)]),
        }
    }
}

/// ```
/// use lancelot::test::*;
/// use lancelot::analysis::dis::get_disassembler;
/// use lancelot::analysis::cfg::get_cjmp_insn_flow;
///
/// // 75 01 JNZ $+1
/// // CC    BREAK
/// // 90    NOP
/// let mut module = load_shellcode32(b"\x75\x01\xCC\x90");
/// let insn = read_insn(&module, 0x0);
/// let flows = get_cjmp_insn_flow(&module, 0x0, &insn).unwrap();
/// assert_eq!(flows[0].va(), 0x3);
/// ```
pub fn get_cjmp_insn_flow(module: &Module, va: VA, insn: &zydis::DecodedInstruction) -> Result<Flows> {
    // if this is not a CJMP, then its a programming error. panic!
    // all conditional jumps should have an operand.
    let op = get_first_operand(insn).expect("CJMP has no target");

    match get_operand_xref(module, va, insn, op)? {
        None => Ok(smallvec![]),
        Some(dst) => Ok(smallvec![Flow::ConditionalJump(dst)]),
    }
}

/// ```
/// use lancelot::test::*;
/// use lancelot::analysis::dis::get_disassembler;
/// use lancelot::analysis::cfg::get_cmov_insn_flow;
///
/// // 0F 44 C3  CMOVZ EAX, EBX
/// // 90        NOP
/// let mut module = load_shellcode32(b"\x0F\x44\xC3\x90");
/// let insn = read_insn(&module, 0x0);
/// let flows = get_cmov_insn_flow(0x0, &insn).unwrap();
/// assert_eq!(flows[0].va(), 0x3);
/// ```
pub fn get_cmov_insn_flow(va: VA, insn: &zydis::DecodedInstruction) -> Result<Flows> {
    Ok(smallvec![Flow::ConditionalMove(va + insn.length as u64)])
}

pub fn get_insn_flow(module: &Module, va: VA, insn: &zydis::DecodedInstruction) -> Result<Flows> {
    let mut flows = match insn.mnemonic {
        zydis::Mnemonic::CALL => get_call_insn_flow(module, va, insn)?,

        zydis::Mnemonic::JMP => get_jmp_insn_flow(module, va, insn)?,

        zydis::Mnemonic::RET | zydis::Mnemonic::IRET | zydis::Mnemonic::IRETD | zydis::Mnemonic::IRETQ => smallvec![],

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
        | zydis::Mnemonic::JZ => get_cjmp_insn_flow(module, va, insn)?,

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
        | zydis::Mnemonic::CMOVZ => get_cmov_insn_flow(va, insn)?,

        // TODO: syscall, sysexit, sysret, vmcall, vmmcall
        _ => smallvec![],
    };

    if does_insn_fallthrough(&insn) {
        flows.push(Flow::Fallthrough(va + insn.length as u64))
    }

    Ok(flows)
}

struct InstructionDescriptor {
    addr: VA,
    length: u64,
    successors: Flows,
}

impl InstructionDescriptor {
    fn does_fallthrough(&self) -> bool {
        self.successors.iter().any(|succ| match succ {
            Flow::Fallthrough(_) => true,
            _ => false,
        })
    }
}

fn fallthrough_flows<'a>(flows: &'a Flows) -> Box<dyn Iterator<Item = &'a Flow> + 'a> {
    Box::new(flows.iter().filter(|flow| match flow {
        Flow::Fallthrough(_) => true,
        _ => false,
    }))
}

fn non_fallthrough_flows<'a>(flows: &'a Flows) -> Box<dyn Iterator<Item = &'a Flow> + 'a> {
    Box::new(flows.iter().filter(|flow| match flow {
        Flow::Fallthrough(_) => false,
        _ => true,
    }))
}

fn read_insn_descriptors(module: &Module, va: VA) -> Result<BTreeMap<VA, InstructionDescriptor>> {
    let decoder = dis::get_disassembler(module)?;
    let mut insn_buf = [0u8; 16];

    let mut queue: VecDeque<VA> = Default::default();
    queue.push_back(va);

    let mut insns: BTreeMap<VA, InstructionDescriptor> = Default::default();

    loop {
        let va = match queue.pop_back() {
            None => break,
            Some(va) => va,
        };

        if insns.contains_key(&va) {
            continue;
        }

        // TODO: better error handling.
        // TODO: can optimize here by re-using buffers.
        module.address_space.read_into(va, &mut insn_buf)?;

        // TODO: better error handling.
        if let Ok(Some(insn)) = decoder.decode(&insn_buf) {
            let successors: Flows = get_insn_flow(module, va, &insn)?
                // remove CALL instructions for cfg reconstruction.
                .into_iter()
                .filter(|succ| match succ {
                    Flow::Call(_) => false,
                    _ => true,
                })
                .collect();

            for target in successors.iter() {
                queue.push_back(target.va());
            }

            let desc = InstructionDescriptor {
                addr: va,
                length: insn.length as u64,
                successors,
            };

            insns.insert(va, desc);
        }
    }

    Ok(insns)
}

// compute successors for an instruction (specified by VA).
/// this function should not fail.
fn compute_successors(insns: &BTreeMap<VA, InstructionDescriptor>) -> BTreeMap<VA, Flows> {
    let mut successors: BTreeMap<VA, Flows> = Default::default();

    for &va in insns.keys() {
        successors.insert(va, smallvec![]);
    }

    for (&va, desc) in insns.iter() {
        successors
            .entry(va)
            .and_modify(|l: &mut Flows| l.extend(desc.successors.clone()));
    }

    successors
}

// compute predecessors for an instruction (specified by VA).
/// this function should not fail.
fn compute_predecessors(insns: &BTreeMap<VA, InstructionDescriptor>) -> BTreeMap<VA, Flows> {
    let mut predecessors: BTreeMap<VA, Flows> = Default::default();

    for &va in insns.keys() {
        predecessors.insert(va, smallvec![]);
    }

    for (&va, desc) in insns.iter() {
        for succ in desc.successors.iter() {
            let flow = succ.swap(va);
            predecessors.entry(succ.va()).and_modify(|l: &mut Flows| l.push(flow));
        }
    }

    predecessors
}

/// this function should not fail.
fn compute_basic_blocks(
    insns: &BTreeMap<VA, InstructionDescriptor>,
    predecessors: &BTreeMap<VA, Flows>,
    successors: &BTreeMap<VA, Flows>,
) -> BTreeMap<VA, BasicBlock> {
    let starts: Vec<VA> = insns
        .keys()
        .filter(|&va| {
            let preds = &predecessors[va];

            // its a root, because nothing flows here.
            if preds.len() == 0 {
                return true;
            }

            // its a bb start, because there's a branch here.
            if non_fallthrough_flows(preds).next().is_some() {
                return true;
            }

            // its a bb start, because the instruction that fallthrough here
            // also branched somewhere else.
            for pred in fallthrough_flows(preds) {
                if non_fallthrough_flows(&successors[&pred.va()]).next().is_some() {
                    return true;
                }
            }

            return false;
        })
        .cloned()
        .collect();

    let mut basic_blocks: BTreeMap<VA, BasicBlock> = Default::default();
    let mut basic_blocks_by_last_insn: BTreeMap<VA, VA> = Default::default();
    for &start in starts.iter() {
        let mut va = start;
        let mut insn = &insns[&va];

        let mut bb = BasicBlock {
            addr: va,
            length: insn.length,
            predecessors: Default::default(),
            successors: Default::default(),
        };

        loop {
            let flows = &successors[&va];

            if fallthrough_flows(flows).next().is_none() {
                // end of bb.
                // for example: ret has no fallthrough, and is end of basic block.
                break;
            }

            if non_fallthrough_flows(flows).next().is_some() {
                // end of bb.
                // for example: jnz has a non-fallthrough flow from it.
                break;
            }

            let next_va = va + insn.length;
            if non_fallthrough_flows(&predecessors[&next_va]).next().is_some() {
                // end of bb.
                // the next instruction is not part of this bb.
                // for example, the target of a fallthrough AND a jump from elsewhere.
                break;
            }

            bb.length += insn.length;

            va = next_va;
            insn = &insns[&next_va];
        }
        // insn is the last instruction of the current basic block.
        // va is the address of the last instruction of the current basic block.

        bb.successors = successors[&va].clone();

        basic_blocks.insert(start, bb);
        basic_blocks_by_last_insn.insert(va, start);
    }

    for (va, bb) in basic_blocks.iter_mut() {
        bb.predecessors.extend(
            predecessors[va]
                .iter()
                .map(|pred| pred.swap(basic_blocks_by_last_insn[&pred.va()])),
        )
    }

    basic_blocks
}

pub fn build_cfg(module: &Module, va: VA) -> Result<CFG> {
    let insns = read_insn_descriptors(module, va)?;
    let successors = compute_successors(&insns);
    let predecessors = compute_predecessors(&insns);

    let mut vas: Vec<VA> = insns.keys().cloned().collect();
    vas.sort();
    for va in vas.iter() {
        debug!("{:#x}", va)
    }

    let bbs = compute_basic_blocks(&insns, &predecessors, &successors);
    for bb in bbs.values() {
        debug!("bb: {:#x}", bb.addr);
    }

    Ok(CFG {
        basic_blocks: Default::default(),
    })
}

#[cfg(test)]
mod tests {
    use crate::analysis::cfg::build_cfg;
    use crate::test::init_logging;
    use crate::{aspace::AddressSpace, rsrc::*};
    use anyhow::Result;

    #[test]
    fn k32() -> Result<()> {
        init_logging();

        let buf = get_buf(Rsrc::K32);
        let pe = crate::loader::pe::load_pe(&buf)?;

        // this function has:
        //   - api call at 0x1800527F8
        //   - cmovns at 0x180052841
        //   - conditional branches at 0x180052829
        let cfg = build_cfg(&pe.module, 0x1800527B0)?;

        Ok(())
    }
}
