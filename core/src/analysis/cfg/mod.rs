use std::collections::{BTreeMap, BTreeSet, VecDeque};

use anyhow::Result;

pub mod flow;

use crate::{
    analysis::{
        cfg::flow::{Flow, Flows},
        dis,
    },
    aspace::{AbsoluteAddressSpace, AddressSpace},
    module::Module,
    VA,
};

#[derive(Clone)]
pub struct InstructionDescriptor {
    pub length:     u8,
    pub successors: Flows,
}

#[derive(Default, Clone)]
pub struct InstructionIndex {
    pub insns_by_address: BTreeMap<VA, InstructionDescriptor>,
}

const PAGE_SIZE: usize = 0x1000;
const PAGE_MASK: u64 = 0xFFF;

struct CachingPageReader {
    page:         [u8; PAGE_SIZE],
    page_address: VA,
}

impl Default for CachingPageReader {
    fn default() -> Self {
        Self {
            page:         [0u8; PAGE_SIZE],
            // special, non-page aligned value indicates no pages have been read yet.
            // this will never match the page-aligned page_address computed from a requested address.
            page_address: 1,
        }
    }
}

impl CachingPageReader {
    fn read(&mut self, address_space: &AbsoluteAddressSpace, va: VA) -> Result<&[u8; PAGE_SIZE]> {
        // mask off the bottom 12 bits
        let page_address = va & 0xFFFF_FFFF_FFFF_F000;

        if page_address == self.page_address {
            return Ok(&self.page);
        }

        address_space.read_into(page_address, &mut self.page)?;
        self.page_address = page_address;

        Ok(&self.page)
    }
}

impl InstructionIndex {
    pub fn build_index(&mut self, module: &Module, va: VA) -> Result<()> {
        let decoder = dis::get_disassembler(module)?;
        // we prefer to read via a page cache,
        // assuming that instruction fetches are often localized within one page.
        let mut reader: CachingPageReader = Default::default();

        // pop from the front of the queue.
        // place localized work on the front, non-localized work at the back.
        // that is:
        //  - fallthrough at the very front,
        //  - local jumps after fallthroughs at the front, and
        //  - calls to the back.
        let mut queue: VecDeque<VA> = Default::default();
        queue.push_back(va);

        loop {
            let va = match queue.pop_front() {
                None => break,
                Some(va) => va,
            };

            if self.insns_by_address.contains_key(&va) {
                continue;
            }

            let maybe_insn = if va & 0xFFFF_FFFF_FFFF_F000 <= (PAGE_SIZE - 0x10) as u64 {
                // common case: instruction doesn't split two pages (max insn size: 0x10).
                //
                // so we read from the page cache, which we expect to be pretty fast.
                let page = match reader.read(&module.address_space, va) {
                    Ok(page) => page,
                    Err(e) => {
                        log::warn!("failed to read instruction: {:#x}: invalid page: {:#x?}", va, e);
                        continue;
                    }
                };
                let insn_buf = &page[(va & PAGE_MASK) as usize..];
                decoder.decode(insn_buf)
            } else {
                // uncommon case: potentially valid instruction that splits two pages.
                // so, we'll read 0x10 bytes across the two pages,
                // and try to decode again.
                //
                // we expect this to be a bit slower, because:
                //   1. we have read from two pages, and
                //   2. we have to reach into the address space, which isn't free.
                let mut insn_buf = [0u8; 0x10];
                if let Err(e) = module.address_space.read_into(va, &mut insn_buf) {
                    log::warn!("failed to read instruction: {:#x}: invalid address: {:#x?}", va, e);
                    continue;
                };
                decoder.decode(&insn_buf)
            };

            let insn = match maybe_insn {
                Ok(Some(insn)) => {
                    // common happy case: valid instruction that doesn't split two pages.
                    insn
                }
                Err(e) => {
                    // invalid instruction
                    log::warn!("invalid instruction: {:#x}: {:#?}", va, e);
                    continue;
                }
                Ok(None) => continue,
            };

            let successors: Flows = flow::get_insn_flow(module, va, &insn)?;

            // place fallthroughs at the very front (expecting: most local)
            // then non-fallthroughs after fallthroughs.
            // place calls at the back of the queue (expecting: least local)
            for target in successors.iter() {
                if let Flow::Fallthrough(va) = target {
                    queue.push_front(*va)
                }
            }
            for target in successors.iter() {
                match target {
                    Flow::Fallthrough(_) => {}
                    Flow::Call(va) => queue.push_back(*va),
                    _ => queue.push_front(target.va()),
                }
            }

            let desc = InstructionDescriptor {
                length: insn.length,
                successors,
            };

            self.insns_by_address.insert(va, desc);
        }

        Ok(())
    }
}

pub struct FlowIndex {
    pub flows_by_src: BTreeMap<VA, Flows>,
    pub flows_by_dst: BTreeMap<VA, Flows>,
}

impl FlowIndex {
    fn build_index(insns: &InstructionIndex) -> Result<FlowIndex> {
        let mut idx = FlowIndex {
            // each of these maps is guaranteed to have an entry for each of the given instructions.
            flows_by_src: Default::default(),
            flows_by_dst: Default::default(),
        };

        for (&src, insn) in insns.insns_by_address.iter() {
            idx.flows_by_src.insert(src, insn.successors.clone());
            idx.flows_by_dst.entry(src).or_default();

            for succ in insn.successors.iter() {
                let dst = succ.va();
                idx.flows_by_dst.entry(dst).or_default().push(succ.swap(src));
            }
        }

        Ok(idx)
    }
}

pub struct BasicBlock {
    pub address:              VA,
    pub length:               u64,
    pub address_of_last_insn: VA,
}

pub struct BasicBlockIndex {
    pub blocks_by_address:      BTreeMap<VA, BasicBlock>,
    // map from BasicBlock.address_of_last_insn to BasicBlock.address
    pub blocks_by_last_address: BTreeMap<VA, VA>,
}

// "edge" helpers.
// lets call an "edge" a flow that you'd see in IDA;
// that is, not a call flow or cmov, but a jump/fallthrough/etc.

fn edges<'a>(flows: &'a Flows) -> Box<dyn Iterator<Item = &'a Flow> + 'a> {
    Box::new(
        flows
            .iter()
            .filter(|flow| !matches!(flow, Flow::Call(_) | Flow::ConditionalMove(_))),
    )
}

fn fallthrough_edges<'a>(flows: &'a Flows) -> Box<dyn Iterator<Item = &'a Flow> + 'a> {
    Box::new(edges(flows).filter(|flow| matches!(flow, Flow::Fallthrough(_))))
}

fn non_fallthrough_edges<'a>(flows: &'a Flows) -> Box<dyn Iterator<Item = &'a Flow> + 'a> {
    Box::new(edges(flows).filter(|flow| !matches!(flow, Flow::Fallthrough(_))))
}

fn empty<'a, T>(mut i: Box<dyn Iterator<Item = T> + 'a>) -> bool {
    i.next().is_none()
}

// given instructions and flows, iterate over the tuples (va, insn, preds,
// succs)
fn iter_insn_flows<'a>(
    insns: &'a InstructionIndex,
    flows: &'a FlowIndex,
) -> Box<dyn Iterator<Item = (VA, &'a InstructionDescriptor, &'a Flows, &'a Flows)> + 'a> {
    let mut insns_iter = insns.insns_by_address.iter();
    let mut flows_by_src_iter = flows.flows_by_src.iter();
    let mut flows_by_dst_iter = flows.flows_by_dst.iter();

    let iter = std::iter::from_fn(move || {
        if let Some((&insnva, insn)) = insns_iter.next() {
            let (&va1, successors) = flows_by_src_iter.next().expect("flow index (src) out of sync");
            let (&va2, predecessors) = flows_by_dst_iter.next().expect("flow index (dst) out of sync");

            assert_eq!(insnva, va1);
            assert_eq!(insnva, va2);

            Some((insnva, insn, predecessors, successors))
        } else {
            None
        }
    });

    Box::new(iter)
}

impl BasicBlockIndex {
    fn build_index(insns: &InstructionIndex, flows: &FlowIndex) -> Result<BasicBlockIndex> {
        let mut blocks_by_address: BTreeMap<VA, BasicBlock> = Default::default();
        let mut blocks_by_last_address: BTreeMap<VA, VA> = Default::default();

        // find all the basic block start addresses.
        //
        // scan through all instructions, looking for:
        //  1. instruction with nothing before it, or
        //  2. instruction with a non-fallthrough flow to it (e.g. jmp target), or
        //  3. the prior instruction also branched elsewhere
        //
        // note: the resulting iterator is sorted by address.
        let starts = iter_insn_flows(insns, flows)
            .filter(|(_, _, preds, _)| {
                if empty(edges(preds)) {
                    // its a root, which is a start, because nothing flows here.
                    return true;
                }

                // its a bb start, because there's a branch to here.
                if !empty(non_fallthrough_edges(preds)) {
                    return true;
                }

                // its a bb start, because the instruction that fallthrough here
                // also branched somewhere else.
                for pred in fallthrough_edges(preds) {
                    if !empty(non_fallthrough_edges(&flows.flows_by_src[&pred.va()])) {
                        return true;
                    }
                }

                false
            })
            .map(|(insnva, _, _, _)| insnva);

        // find all the basic block last addresses.
        //
        // scan through all instructions, looking for:
        //  1. instruction with nothing before it, or
        //  2. instruction with a non-fallthrough flow to it (e.g. jmp target), or
        //  3. the prior instruction also branched elsewhere
        //
        // the resulting iterator is sorted by address.
        let lasts = iter_insn_flows(insns, flows)
            .filter(|(insnva, insn, _, succs)| {
                if succs.is_empty() {
                    // its a last, because nothing flows from here.
                    return true;
                }

                // there is no fallthrough here, so end of bb.
                // for example: ret has no fallthrough, and is end of basic block.
                if empty(fallthrough_edges(succs)) {
                    return true;
                }

                // there is a non-fallthrough flow, so end of bb.
                // for example: jnz has a non-fallthrough flow from it.
                if !empty(non_fallthrough_edges(succs)) {
                    return true;
                }

                // now we need to check the next instruction.
                // if its the start of a basic block,
                // then the current basic block must end.

                let next_va = insnva + (insn.length as u64);

                if let (Some(next_preds), Some(_)) =
                    (flows.flows_by_dst.get(&next_va), insns.insns_by_address.get(&next_va))
                {
                    // the next instruction has other flows to it, so its a new bb.
                    // the next instruction is not part of this bb.
                    // for example, the target of a fallthrough AND a jump from elsewhere.
                    if !empty(non_fallthrough_edges(next_preds)) {
                        return true;
                    }
                } else {
                    // there is not a subsequent instruction, so end of bb.
                    // e.g. flow to a non-instruction.
                    //
                    // this might be considered an analysis error.
                    // but, we don't have a better framework for this right now.
                    // options include:
                    //  1. pretend the current BB is ok, or
                    //  2. fail the whole analysis
                    // for right now, we're doing (1).
                    log::warn!("cfg: {:#x}: no subsequent instruction at {:#x}", insnva, next_va);
                    return true;
                }

                false
            })
            .map(|(insnva, _, _, _)| insnva)
            .collect::<Vec<_>>();

        // we don't simplify the lasts directly to an iter above
        // because below we'll create a bunch of clones of the iter,
        // and the iterator is not Clone.
        //
        // so, we realize `lasts` to a vec and then iter over that
        // (and clones should be cheap).
        let mut lasts = lasts.iter().peekable();

        for start in starts {
            // drop all the lasts less than start.
            // because a basic block cannot end before it starts.
            //
            // I think the only reason this would be the case should be
            // overlapping instructions (and therefore, basic blocks).
            //
            // precondition: starts is sorted.
            // precondition: lasts is sorted.
            //
            // postcondition: `lasts.next() >= start`
            while start > **lasts.peek().expect("missing bb last") {
                lasts.next();
            }

            let mut length: u64 = 0;
            let mut current = start;

            loop {
                let insn = &insns.insns_by_address[&current];
                length += insn.length as u64;

                // step through lasts, seeing if the current instruction is there.
                // short circuit when: current is found, or cannot exist.
                // because lasts is sorted, we can stop when lasts.peek() > current.
                let is_last: bool;
                // perf: this clone looks expensive, however, its not.
                // I profiled an alternative implementation with a clone-per-start
                // and there was not a measurable difference.
                // I think this routine is more intuitive, so we keep this clone.
                let mut cursor = lasts.clone();
                'next_cursor: loop {
                    // same as above: there should always be a last for each start.
                    // otherwise, programming error.
                    let last = **cursor.peek().expect("missing bb last");

                    match last.cmp(&current) {
                        std::cmp::Ordering::Less => {
                            // least common case: an overlapping instruction ends a BB in the middle of this
                            // instruction.
                            cursor.next();
                            continue 'next_cursor;
                        }
                        std::cmp::Ordering::Equal => {
                            // common case: this instruction is the last in the basic block.
                            // we'll break from all loops and insert the basic block.
                            is_last = true;
                            break 'next_cursor;
                        }
                        std::cmp::Ordering::Greater => {
                            // most common case: this instruction does not end the basic block.
                            // we'll break from this inner loop and step to the next instruction to try
                            // again.
                            is_last = false;
                            break 'next_cursor;
                        }
                    }
                }

                if is_last {
                    break;
                } else {
                    // instruction did not end basic block.
                    // step to next instruction and try again.
                    current += insn.length as u64;
                    continue;
                }
            }
            blocks_by_address.insert(
                start,
                BasicBlock {
                    address: start,
                    length,
                    address_of_last_insn: current,
                },
            );
            blocks_by_last_address.insert(current, start);
        }

        Ok(BasicBlockIndex {
            blocks_by_address,
            blocks_by_last_address,
        })
    }
}

pub struct CFG {
    pub insns:        InstructionIndex,
    pub flows:        FlowIndex,
    pub basic_blocks: BasicBlockIndex,
}

impl CFG {
    pub fn from_instructions(insns: InstructionIndex) -> Result<CFG> {
        let flows = FlowIndex::build_index(&insns)?;
        let basic_blocks = BasicBlockIndex::build_index(&insns, &flows)?;

        Ok(CFG {
            insns,
            flows,
            basic_blocks,
        })
    }

    pub fn get_reachable_blocks<'a>(&'a self, va: VA) -> Box<dyn Iterator<Item = &'a BasicBlock> + 'a> {
        log::debug!("reachable from: {:#x}", va);
        let mut seen: BTreeSet<VA> = Default::default();

        if !self.basic_blocks.blocks_by_address.contains_key(&va) {
            log::warn!("get_reachable_blocks: address is not a basic block: {:#x}", va);
            return Box::new(std::iter::empty());
        }

        let mut queue: VecDeque<VA> = Default::default();
        queue.push_back(va);

        let iter = std::iter::from_fn(move || loop {
            if let Some(bbva) = queue.pop_front() {
                if seen.contains(&bbva) {
                    continue;
                }
                log::debug!("reachable from: {:#x}: basic block: {:#x}", va, bbva);

                let bb = &self.basic_blocks.blocks_by_address[&bbva];

                let succs = &self.flows.flows_by_src[&bb.address_of_last_insn];
                for succ in succs.iter() {
                    if !matches!(succ, Flow::Call(_)) {
                        log::debug!(
                            "reachable from: {:#x}: basic block: {:#x}: successor: {:#x}",
                            va,
                            bbva,
                            succ.va()
                        );
                        queue.push_back(succ.va());
                    }
                }

                let preds = &self.flows.flows_by_dst[&bb.address];
                for pred in preds.iter() {
                    if !matches!(pred, Flow::Call(_)) {
                        log::debug!(
                            "reachable from: {:#x}: basic block: {:#x}: pred: {:#x}",
                            va,
                            bbva,
                            pred.va()
                        );
                        queue.push_back(self.basic_blocks.blocks_by_last_address[&pred.va()])
                    }
                }

                seen.insert(bbva);
                return Some(bb);
            } else {
                return None;
            }
        });

        Box::new(iter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{rsrc::*, test::*};
    use anyhow::Result;

    #[test]
    fn test_one_insn() -> Result<()> {
        // C3              RET
        let module = load_shellcode32(b"\xC3");
        let mut insns: InstructionIndex = Default::default();

        insns.build_index(&module, 0x0)?;

        let cfg = CFG::from_instructions(insns)?;

        assert_eq!(cfg.insns.insns_by_address.len(), 1);
        assert_eq!(cfg.basic_blocks.blocks_by_address.len(), 1);

        Ok(())
    }

    #[test]
    fn test_two_insn() -> Result<()> {
        // 90              NOP
        // C3              RET
        let module = load_shellcode32(b"\x90\xC3");
        let mut insns: InstructionIndex = Default::default();

        insns.build_index(&module, 0x0)?;

        let cfg = CFG::from_instructions(insns)?;

        assert_eq!(cfg.insns.insns_by_address.len(), 2);
        assert_eq!(cfg.basic_blocks.blocks_by_address.len(), 1);

        Ok(())
    }

    #[test]
    fn test_cjmp_insn() -> Result<()> {
        // 0:  75 02                   jne    3  |   BB1
        // 2:  c3                      ret        |  BB2
        // 3:  00
        // 3:  c3                      ret         | BB3
        let module = load_shellcode32(b"\x75\x02\x00\xC3\xC3");
        let mut insns: InstructionIndex = Default::default();

        insns.build_index(&module, 0x0)?;

        let cfg = CFG::from_instructions(insns)?;

        assert_eq!(cfg.insns.insns_by_address.len(), 3);
        assert_eq!(cfg.basic_blocks.blocks_by_address.len(), 3);

        Ok(())
    }

    #[test]
    fn test_cmov_insn() -> Result<()> {
        // 0:  0f 44 c3                cmove  eax,ebx  | BB1
        // 3:  c3                      ret             | BB1
        let module = load_shellcode32(b"\x0F\x44\xC3\xC3");
        let mut insns: InstructionIndex = Default::default();

        insns.build_index(&module, 0x0)?;

        let cfg = CFG::from_instructions(insns)?;

        assert_eq!(cfg.insns.insns_by_address.len(), 2);
        assert_eq!(cfg.basic_blocks.blocks_by_address.len(), 1);

        Ok(())
    }

    #[test]
    fn test_two_entry_points() -> Result<()> {
        //init_logging();

        // 0:  c3                      ret  | BB1
        // 1:  00
        // 2:  c3                      ret  | BB2
        let module = load_shellcode32(b"\xC3\x00\xC3");
        let mut insns: InstructionIndex = Default::default();

        insns.build_index(&module, 0x0)?;
        insns.build_index(&module, 0x2)?;

        let cfg = CFG::from_instructions(insns)?;

        assert_eq!(cfg.insns.insns_by_address.len(), 2);
        assert_eq!(cfg.basic_blocks.blocks_by_address.len(), 2);

        Ok(())
    }

    #[test]
    fn test_overlapping_instructions() -> Result<()> {
        // The instruction is jumping in the 2nd byte of itself:
        //
        // 00: EBFF    jmp $+1
        // 02: C0C3C3  rol bl, 0xC3
        // 05: C3      ret
        //
        // will actually be executed as
        //
        // 00: EBFF    jmp $+1
        // 01: FFC0    inc eax
        // 03: C3      retn
        //
        // via: https://reverseengineering.stackexchange.com/a/1661/17194
        let module = load_shellcode32(b"\xEB\xFF\xC0\xC3\xC3\xC3");

        let mut insns: InstructionIndex = Default::default();
        insns.build_index(&module, 0x0)?;
        // 00: EBFF    jmp $+1
        // 01: FFC0    inc eax
        // 03: C3      retn
        assert_eq!(insns.insns_by_address.len(), 3);

        let mut insns: InstructionIndex = Default::default();
        insns.build_index(&module, 0x2)?;
        // 02: C0C3C3  rol bl, 0xC3
        // 05: C3      ret
        assert_eq!(insns.insns_by_address.len(), 2);

        let mut insns: InstructionIndex = Default::default();
        insns.build_index(&module, 0x0)?;
        insns.build_index(&module, 0x2)?;
        // jmp $+1
        // -------
        //         rol bl, 0xC3
        //         ------------
        //                     ret
        //                     ----
        //     inc eax
        //     --------
        //             ret
        //             ----
        // EB  FF  C0  C3  C3  C3
        assert_eq!(insns.insns_by_address.len(), 5);
        let cfg = CFG::from_instructions(insns)?;
        // [jmp] -> [rol, ret]
        // [inc, ret]
        assert_eq!(cfg.basic_blocks.blocks_by_address.len(), 3);

        Ok(())
    }

    #[test]
    fn k32() -> Result<()> {
        let buf = get_buf(Rsrc::K32);
        let pe = crate::loader::pe::PE::from_bytes(&buf)?;
        let mut insns: InstructionIndex = Default::default();

        for &ep in crate::analysis::pe::entrypoints::find_pe_entrypoint(&pe)?.iter() {
            insns.build_index(&pe.module, ep)?;
        }

        for &exp in crate::analysis::pe::exports::find_pe_exports(&pe)?.iter() {
            insns.build_index(&pe.module, exp)?;
        }

        let cfg = CFG::from_instructions(insns)?;

        assert_eq!(cfg.insns.insns_by_address.len(), 84369);
        assert_eq!(cfg.basic_blocks.blocks_by_address.len(), 17145);

        Ok(())
    }

    #[test]
    fn reachable_blocks() -> Result<()> {
        init_logging();

        // 0:  b8 01 00 00 00          mov    eax,0x1   | BB1
        // 5:  75 01                   jne    8 <B>     | BB1
        // 7:  c3                      ret               | BB2
        //
        // 8:  b8 02 00 00 00          mov    eax,0x2     | BB3
        // d:  75 01                   jne    10 <C>      | BB3
        // f:  c3                      ret                 | BB4
        //
        // 10: c3                      ret                  | BB5
        let module = load_shellcode32(b"\xB8\x01\x00\x00\x00\x75\x01\xC3\xB8\x02\x00\x00\x00\x75\x01\xC3\xC3");
        let mut insns: InstructionIndex = Default::default();
        insns.build_index(&module, 0x0)?;
        let cfg = CFG::from_instructions(insns)?;

        assert_eq!(cfg.insns.insns_by_address.len(), 7);
        assert_eq!(cfg.basic_blocks.blocks_by_address.len(), 5);

        // asking for reachable blocks from [7: ret]
        // so it should traverse back to [0: mov, jne]
        // and then back down to [8, mov, jne] and beyond
        let mut blocks = cfg.get_reachable_blocks(0x7).map(|bb| bb.address).collect::<Vec<_>>();
        blocks.sort();

        assert_eq!(&blocks[..], [0x0, 0x7, 0x8, 0xF, 0x10]);

        Ok(())
    }
}
