use std::collections::{BTreeMap, VecDeque};

use anyhow::Result;
use log::debug;
use smallvec::smallvec;

use crate::{
    analysis::{
        cfg::{
            flow,
            flow::{Flow, Flows},
            BasicBlock, CFG,
        },
        dis,
    },
    aspace::AddressSpace,
    module::Module,
    VA,
};

struct InstructionDescriptor {
    length:     u8,
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
                let successors: Flows = flow::get_insn_flow(module, va, &insn)?
                    // remove CALL instructions for cfg reconstruction.
                    .into_iter()
                    .filter(|succ| !matches!(succ, Flow::Call(_)))
                    .collect();

                for target in successors.iter() {
                    queue.push_back(target.va());
                }

                let desc = InstructionDescriptor {
                    length: insn.length,
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

            let next_va = va + (insn.length as u64);

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

            bb.length += insn.length as u64;

            va = next_va;
            insn = &insns[&next_va];
        }
        // insn is the last instruction of the current basic block.
        // va is the address of the last instruction of the current basic block.

        bb.length += insn.length as u64;
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
    use crate::{analysis::cfg::local::*, rsrc::*};
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
}
