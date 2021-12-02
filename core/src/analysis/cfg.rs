use std::collections::{BTreeMap, VecDeque};

use anyhow::Result;
use log::debug;
use smallvec::{smallvec, SmallVec};

use crate::{
    analysis::dis,
    aspace::AddressSpace,
    module::{Module, Permissions},
    VA,
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
    pub address: VA,

    /// length of the basic block in bytes.
    pub length: u64,

    /// VAs of start addresses of basic blocks that flow here.
    pub predecessors: Flows,

    /// VAs of start addresses of basic blocks that flow from here.
    pub successors: Flows,
}

pub struct CFG {
    // we use a btree so that we can conveniently iterate in order.
    // alternative choice would be an FNV hash map,
    // because the keys are small.
    pub basic_blocks: BTreeMap<VA, BasicBlock>,
}

fn is_executable(module: &Module, va: VA) -> bool {
    module.probe_va(va, Permissions::X)
}

pub fn get_call_insn_flow(module: &Module, va: VA, insn: &zydis::DecodedInstruction) -> Result<Flows> {
    // if this is not a CALL, then its a programming error. panic!
    // all CALLs should have an operand.
    let op = dis::get_first_operand(insn).expect("CALL has no operand");

    if let Ok(Some(dst)) = dis::get_operand_xref(module, va, insn, op) {
        if is_executable(module, dst) {
            return Ok(smallvec![Flow::Call(dst)]);
        }
    }
    Ok(smallvec![])
}

pub fn get_jmp_insn_flow(module: &Module, va: VA, insn: &zydis::DecodedInstruction) -> Result<Flows> {
    // if this is not a JMP, then its a programming error. panic!
    // all JMPs should have an operand.
    let op = dis::get_first_operand(insn).expect("JMP has no target");

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
        if let Ok(Some(dst)) = dis::get_operand_xref(module, va, insn, op) {
            if is_executable(module, dst) {
                return Ok(smallvec![Flow::UnconditionalJump(dst)]);
            }
        }
        Ok(smallvec![])
    }
}

pub fn get_cjmp_insn_flow(module: &Module, va: VA, insn: &zydis::DecodedInstruction) -> Result<Flows> {
    // if this is not a CJMP, then its a programming error. panic!
    // all conditional jumps should have an operand.
    let op = dis::get_first_operand(insn).expect("CJMP has no target");

    if let Ok(Some(dst)) = dis::get_operand_xref(module, va, insn, op) {
        if is_executable(module, dst) {
            return Ok(smallvec![Flow::ConditionalJump(dst)]);
        }
    }
    Ok(smallvec![])
}

pub fn get_cmov_insn_flow(va: VA, insn: &zydis::DecodedInstruction) -> Result<Flows> {
    let next = va + insn.length as u64;
    Ok(smallvec![Flow::ConditionalMove(next)])
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

    if dis::does_insn_fallthrough(insn) {
        flows.push(Flow::Fallthrough(va + insn.length as u64))
    }

    Ok(flows)
}

struct InstructionDescriptor {
    length:     u64,
    successors: Flows,
}

fn fallthrough_flows<'a>(flows: &'a Flows) -> Box<dyn Iterator<Item = &'a Flow> + 'a> {
    Box::new(flows.iter().filter(|flow| matches!(flow, Flow::Fallthrough(_))))
}

fn non_fallthrough_flows<'a>(flows: &'a Flows) -> Box<dyn Iterator<Item = &'a Flow> + 'a> {
    Box::new(flows.iter().filter(|flow| !matches!(flow, Flow::Fallthrough(_))))
}

fn empty<'a, T>(mut i: Box<dyn Iterator<Item = T> + 'a>) -> bool {
    i.next().is_none()
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

        // TODO: optimize here by re-using buffers.
        if module.address_space.read_into(va, &mut insn_buf).is_ok() {
            if let Ok(Some(insn)) = decoder.decode(&insn_buf) {
                let successors: Flows = get_insn_flow(module, va, &insn)?
                    // remove CALL instructions for cfg reconstruction.
                    .into_iter()
                    .filter(|succ| !matches!(succ, Flow::Call(_)))
                    .collect();

                for target in successors.iter() {
                    queue.push_back(target.va());
                }

                let desc = InstructionDescriptor {
                    length: insn.length as u64,
                    successors,
                };

                insns.insert(va, desc);
            }
        }
    }

    Ok(insns)
}

/// compute successors for an instruction (specified by VA).
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

/// compute predecessors for an instruction (specified by VA).
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
    // find all the basic block start addresses.
    //
    // scan through all instructions, looking for:
    //  1. instruction with nothing before it, or
    //  2. instruction with a non-fallthrough flow to it (e.g. jmp target), or
    //  3. the prior instruction also branched elsewhere
    let starts: Vec<VA> = insns
        .keys()
        .filter(|&va| {
            let preds = &predecessors[va];

            // its a root, because nothing flows here.
            if preds.is_empty() {
                return true;
            }

            // its a bb start, because there's a branch to here.
            if !empty(non_fallthrough_flows(preds)) {
                return true;
            }

            // its a bb start, because the instruction that fallthrough here
            // also branched somewhere else.
            for pred in fallthrough_flows(preds) {
                if !empty(non_fallthrough_flows(&successors[&pred.va()])) {
                    return true;
                }
            }

            false
        })
        .cloned()
        .collect();

    let mut basic_blocks: BTreeMap<VA, BasicBlock> = Default::default();
    let mut basic_blocks_by_last_insn: BTreeMap<VA, VA> = Default::default();

    // compute the basic block instances.
    //
    // for each basic block start,
    // scan forward to find the end of the block.
    //
    // set the bb successors.
    // leave the predecessors for a subsequent pass.
    // this is because we need the basic blocks indexed by final address.
    for &start in starts.iter() {
        let mut va = start;
        let mut insn = &insns[&va];

        let mut bb = BasicBlock {
            address:      va,
            length:       0,
            predecessors: Default::default(),
            successors:   Default::default(),
        };

        loop {
            let flows = &successors[&va];

            // there is no fallthrough here, so end of bb.
            // for example: ret has no fallthrough, and is end of basic block.
            if empty(fallthrough_flows(flows)) {
                break;
            }

            // there is a non-fallthrough flow, so end of bb.
            // for example: jnz has a non-fallthrough flow from it.
            if !empty(non_fallthrough_flows(flows)) {
                break;
            }

            // now we need to check the next instruction.
            // if its the start of a basic block,
            // then the current basic block must end.

            let next_va = va + insn.length;

            // there is not a subsequent instruction, so end of bb.
            // this might be considered an analysis error.
            // but, we don't have a better framework for this right now.
            // options include:
            //  1. pretend the current BB is ok, or
            //  2. fail the whole analysis
            // for right now, we're doing (1).
            if !predecessors.contains_key(&next_va) {
                log::warn!("cfg: {:#x}: no subsequent instruction at {:#x}", va, next_va);
                break;
            }

            // the next instruction has other flows to it, so its a new bb.
            // the next instruction is not part of this bb.
            // for example, the target of a fallthrough AND a jump from elsewhere.
            if !empty(non_fallthrough_flows(&predecessors[&next_va])) {
                break;
            }

            bb.length += insn.length;

            va = next_va;
            insn = &insns[&next_va];
        }
        // insn is the last instruction of the current basic block.
        // va is the address of the last instruction of the current basic block.

        bb.length += insn.length;
        bb.successors = successors.get(&va).unwrap_or(&smallvec![]).clone();

        basic_blocks.insert(start, bb);
        basic_blocks_by_last_insn.insert(va, start);
    }

    for (va, bb) in basic_blocks.iter_mut() {
        bb.predecessors.extend(
            predecessors
                .get(va)
                .unwrap_or(&smallvec![])
                .iter()
                .filter(|pred| basic_blocks_by_last_insn.contains_key(&pred.va()))
                .map(|pred| pred.swap(basic_blocks_by_last_insn[&pred.va()])),
        )
    }

    basic_blocks
}

pub fn build_cfg(module: &Module, va: VA) -> Result<CFG> {
    debug!("cfg: {:#x}", va);

    let insns = read_insn_descriptors(module, va)?;
    debug!("cfg: {:#x}: {} instructions", va, insns.len());

    let successors = compute_successors(&insns);
    let predecessors = compute_predecessors(&insns);

    let bbs = compute_basic_blocks(&insns, &predecessors, &successors);
    debug!("cfg: {:#x}: {} basic blocks", va, bbs.len());

    Ok(CFG { basic_blocks: bbs })
}

#[cfg(test)]
mod tests {
    use crate::{analysis::cfg::*, rsrc::*, test::*};
    use anyhow::Result;

    #[test]
    fn k32() -> Result<()> {
        let buf = get_buf(Rsrc::K32);
        let pe = crate::loader::pe::PE::from_bytes(&buf)?;

        // this function has:
        //   - api call at 0x1800527F8
        //   - cmovns at 0x180052841
        //   - conditional branches at 0x180052829
        let cfg = build_cfg(&pe.module, 0x1800527B0)?;
        assert_eq!(cfg.basic_blocks.len(), 4);

        Ok(())
    }

    #[test]
    fn test_get_call_insn_flow() {
        // E8 00 00 00 00  CALL $+5
        // 90              NOP
        let module = load_shellcode32(b"\xE8\x00\x00\x00\x00\x90");
        let insn = read_insn(&module, 0x0);
        let flows = get_call_insn_flow(&module, 0x0, &insn).unwrap();
        assert_eq!(flows[0].va(), 0x5);
    }

    #[test]
    fn test_get_jmp_insn_flow() {
        // E9 00 00 00 00  JMP $+5
        // 90              NOP
        let module = load_shellcode32(b"\xE9\x00\x00\x00\x00\x90");
        let insn = read_insn(&module, 0x0);
        let flows = get_jmp_insn_flow(&module, 0x0, &insn).unwrap();
        assert_eq!(flows[0].va(), 0x5);
    }

    #[test]
    fn test_get_cjmp_insn_flow() {
        // 75 01 JNZ $+1
        // CC    BREAK
        // 90    NOP
        let module = load_shellcode32(b"\x75\x01\xCC\x90");
        let insn = read_insn(&module, 0x0);
        let flows = get_cjmp_insn_flow(&module, 0x0, &insn).unwrap();
        assert_eq!(flows[0].va(), 0x3);
    }

    #[test]
    fn test_get_cmov_insn_flow() {
        // 0F 44 C3  CMOVZ EAX, EBX
        // 90        NOP
        let module = load_shellcode32(b"\x0F\x44\xC3\x90");
        let insn = read_insn(&module, 0x0);
        let flows = get_cmov_insn_flow(0x0, &insn).unwrap();
        assert_eq!(flows[0].va(), 0x3);
    }
}
