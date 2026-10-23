use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    ops::{Not, RangeBounds},
};

use anyhow::Result;
use bitflags::bitflags;

pub mod flow;

pub mod code_references;
pub mod noret;
pub mod thunk;

use crate::{
    analysis::{
        cfg::flow::{Flow, Flows},
        dis,
        dis::Target,
    },
    aspace::{AbsoluteAddressSpace, AddressSpace},
    module::{Module, Permissions},
    VA,
};

#[derive(Clone, Debug)]
pub struct InstructionDescriptor {
    pub length:     u8,
    pub successors: Flows,
}

#[derive(Default, Clone)]
pub struct InstructionIndex {
    pub insns_by_address: BTreeMap<VA, InstructionDescriptor>,
    /// the addresses from which instructions were explored (see `build_index`):
    /// entry points, exports, symbols, pointer references, ...
    /// these are known to be code without any flow reaching them,
    /// so pruning flows never removes them.
    pub roots:            BTreeSet<VA>,
}

pub const PAGE_SIZE: usize = 0x1000;
const PAGE_MASK: u64 = 0xFFF;
const MAX_INSN_LENGTH: u64 = 0xF;

pub struct CachingPageReader {
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
    pub fn read(&mut self, address_space: &AbsoluteAddressSpace, va: VA) -> Result<&[u8; PAGE_SIZE]> {
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

pub fn read_insn_with_cache(
    reader: &mut CachingPageReader,
    address_space: &AbsoluteAddressSpace,
    va: VA,
    decoder: &zydis::Decoder,
) -> Result<Option<dis::DecodedInstruction>> {
    read_insn_with_cache_as::<zydis::AllOperands>(reader, address_space, va, decoder)
}

/// like `read_insn_with_cache`, but decode only the given operands.
/// decoding without operands (`zydis::NoOperands`) is approximately one third faster.
pub fn read_insn_with_cache_as<O: zydis::Operands>(
    reader: &mut CachingPageReader,
    address_space: &AbsoluteAddressSpace,
    va: VA,
    decoder: &zydis::Decoder,
) -> Result<Option<zydis::Instruction<O>>> {
    if va & PAGE_MASK <= (PAGE_SIZE - 0x10) as u64 {
        // common case: instruction doesn't split two pages (max insn size: 0x10).
        //
        // so we read from the page cache, which we expect to be pretty fast.
        let page = reader.read(address_space, va)?;
        let insn_buf = &page[(va & PAGE_MASK) as usize..];
        match decoder.decode_first::<O>(insn_buf) {
            Ok(i) => Ok(i),
            Err(e) => Err(e.into()),
        }
    } else {
        // uncommon case: potentially valid instruction that splits two pages.
        // so, we'll read 0x10 bytes across the two pages,
        // and try to decode again.
        //
        // we expect this to be a bit slower, because:
        //   1. we have read from two pages, and
        //   2. we have to reach into the address space, which isn't free.
        let mut insn_buf = [0u8; 0x10];
        if address_space.read_into(va, &mut insn_buf).is_ok() {
            match decoder.decode_first::<O>(&insn_buf) {
                Ok(i) => Ok(i),
                Err(e) => Err(e.into()),
            }
        } else {
            // the subsequent page is not mapped,
            // such as an instruction found at the very end of a section.
            // decode from the remainder of the current page,
            // which is enough for any instruction that's actually mapped.
            let page = reader.read(address_space, va)?;
            let insn_buf = &page[(va & PAGE_MASK) as usize..];
            match decoder.decode_first::<O>(insn_buf) {
                Ok(i) => Ok(i),
                Err(e) => Err(e.into()),
            }
        }
    }
}

impl InstructionIndex {
    /// explore the instructions reachable from the given address and add them to the index.
    /// returns the addresses of the instructions that were added.
    pub fn build_index(&mut self, module: &Module, va: VA) -> Result<Vec<VA>> {
        let mut new_insns: Vec<VA> = Default::default();
        let decoder = dis::get_disassembler(module)?;
        self.roots.insert(va);
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

            // decode without operands first, which is faster.
            // most instructions only fall through, and only the others need their operands.
            let insn =
                match read_insn_with_cache_as::<zydis::NoOperands>(&mut reader, &module.address_space, va, &decoder) {
                    Ok(Some(insn)) => {
                        // common happy case: valid instruction that doesn't split two pages.
                        insn
                    }
                    Err(e) => {
                        // invalid instruction
                        log::warn!("cfg: invalid instruction: {:#x}: {:#?}", va, e);
                        continue;
                    }
                    Ok(None) => continue,
                };

            let successors: Flows = if flow::needs_operands(insn.mnemonic) {
                match read_insn_with_cache(&mut reader, &module.address_space, va, &decoder) {
                    Ok(Some(insn)) => flow::get_insn_flow(module, va, &insn)?,
                    _ => continue,
                }
            } else {
                smallvec::smallvec![Flow::Fallthrough(va + insn.length as u64)]
            };

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
                    // fallthroughs went at the front
                    Flow::Fallthrough(_) => {}

                    // explore across direct flows
                    Flow::Call(Target::Direct(va)) => queue.push_back(*va),
                    Flow::UnconditionalJump(Target::Direct(va)) => queue.push_back(*va),
                    Flow::ConditionalJump(va) => queue.push_back(*va),

                    // but we can't resolve indirect flows
                    Flow::Call(Target::Indirect(_)) => {}
                    Flow::UnconditionalJump(Target::Indirect(_)) => {}
                }
            }

            let desc = InstructionDescriptor {
                length: insn.length,
                successors,
            };

            self.insns_by_address.insert(va, desc);
            new_insns.push(va);
        }

        Ok(new_insns)
    }
}

pub struct FlowIndex {
    pub flows_by_src: BTreeMap<VA, Flows>,
    pub flows_by_dst: BTreeMap<VA, Flows>,
}

impl FlowIndex {
    fn build_index(module: &Module, insns: &InstructionIndex) -> Result<FlowIndex> {
        // each of these maps is guaranteed to have an entry for each of the given instructions.
        //
        // we build both maps from sorted lists,
        // which is much faster than inserting each flow into a map.
        let flows_by_src: BTreeMap<VA, Flows> = insns
            .insns_by_address
            .iter()
            .map(|(&src, insn)| (src, insn.successors.clone()))
            .collect();

        // the flows to each destination, as (destination, order, flow),
        // where order is the position of the flow among the flows of all the instructions,
        // which orders the predecessors of each destination by their address.
        //
        // fallthroughs are most of the flows, and they're already sorted by destination
        // (unless instructions overlap), so only the other flows need to be sorted.
        let mut fallthroughs: Vec<(VA, u32, Flow)> = Vec::with_capacity(insns.insns_by_address.len());
        let mut others: Vec<(VA, u32, Flow)> = Default::default();
        let mut order: u32 = 0;
        for (&src, insn) in insns.insns_by_address.iter() {
            for succ in insn.successors.iter() {
                order += 1;
                let dst = match succ {
                    // direct flows
                    Flow::Fallthrough(va) => {
                        fallthroughs.push((*va, order, succ.swap(src)));
                        continue;
                    }
                    Flow::Call(Target::Direct(va)) => va,
                    Flow::UnconditionalJump(Target::Direct(va)) => va,
                    Flow::ConditionalJump(va) => va,

                    // indirect flows
                    Flow::Call(Target::Indirect(ptr)) | Flow::UnconditionalJump(Target::Indirect(ptr)) => {
                        if module.probe_va(*ptr, Permissions::RWX) {
                            ptr
                        } else {
                            // the pointer is not present in this address space,
                            // so don't consider it a pointer.
                            continue;
                        }
                    }
                };
                others.push((*dst, order, succ.swap(src)));
            }
        }
        if !fallthroughs.is_sorted_by_key(|&(dst, _, _)| dst) {
            fallthroughs.sort_unstable_by_key(|&(dst, order, _)| (dst, order));
        }
        others.sort_unstable_by_key(|&(dst, order, _)| (dst, order));

        // merge the instructions (each has an entry, even with no flows to it),
        // the fallthroughs, and the other flows.
        let mut flows_by_dst: Vec<(VA, Flows)> = Vec::with_capacity(insns.insns_by_address.len());
        let mut insns = insns.insns_by_address.keys().peekable();
        let mut fallthroughs = fallthroughs.into_iter().peekable();
        let mut others = others.into_iter().peekable();
        while let Some(dst) = [
            insns.peek().map(|&&va| va),
            fallthroughs.peek().map(|&(dst, _, _)| dst),
            others.peek().map(|&(dst, _, _)| dst),
        ]
        .into_iter()
        .flatten()
        .min()
        {
            insns.next_if(|&&va| va == dst);

            let mut preds: Flows = Default::default();
            loop {
                let fallthrough = fallthroughs.peek().filter(|&&(d, _, _)| d == dst);
                let other = others.peek().filter(|&&(d, _, _)| d == dst);
                let next = match (fallthrough, other) {
                    (Some((_, a, _)), Some((_, b, _))) if a < b => fallthroughs.next(),
                    (Some(_), None) => fallthroughs.next(),
                    (_, Some(_)) => others.next(),
                    (None, None) => break,
                };
                preds.push(next.expect("peeked").2);
            }

            flows_by_dst.push((dst, preds));
        }

        Ok(FlowIndex {
            flows_by_src,
            flows_by_dst: flows_by_dst.into_iter().collect(),
        })
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

fn edges(flows: &Flows) -> impl Iterator<Item = &Flow> + '_ {
    flows.iter().filter(|flow| !matches!(flow, Flow::Call(_)))
}

fn fallthrough_edges(flows: &Flows) -> impl Iterator<Item = &Flow> + '_ {
    edges(flows).filter(|flow| matches!(flow, Flow::Fallthrough(_)))
}

fn non_fallthrough_edges(flows: &Flows) -> impl Iterator<Item = &Flow> + '_ {
    edges(flows).filter(|flow| !matches!(flow, Flow::Fallthrough(_)))
}

fn direct_edges<'a>(i: impl Iterator<Item = &'a Flow> + 'a) -> impl Iterator<Item = &'a Flow> + 'a {
    i.filter(|f| match f {
        // direct
        Flow::Fallthrough(_) => true,
        Flow::Call(Target::Direct(_)) => true,
        Flow::UnconditionalJump(Target::Direct(_)) => true,
        Flow::ConditionalJump(_) => true,
        // indirect
        Flow::Call(Target::Indirect(_)) => false,
        Flow::UnconditionalJump(Target::Indirect(_)) => false,
    })
}

// careful, don't treat direct and indirect edges the same!
// probably filter to direct or indirect edges first.
fn edge_targets<'a>(i: impl Iterator<Item = &'a Flow> + 'a) -> impl Iterator<Item = VA> + 'a {
    i.map(|f| match f {
        // direct
        Flow::Fallthrough(va) => *va,
        Flow::Call(Target::Direct(va)) => *va,
        Flow::UnconditionalJump(Target::Direct(va)) => *va,
        Flow::ConditionalJump(va) => *va,
        // indirect
        Flow::Call(Target::Indirect(ptr)) => *ptr,
        Flow::UnconditionalJump(Target::Indirect(ptr)) => *ptr,
    })
}

fn empty<'a, T>(mut i: impl Iterator<Item = T> + 'a) -> bool {
    i.next().is_none()
}

// iterate over the tuples (va, insn, preds, succs) for the instructions in the given range.
fn iter_insn_flows<'a>(
    insns: &'a InstructionIndex,
    flows: &'a FlowIndex,
    range: impl RangeBounds<VA> + Clone + 'a,
) -> impl Iterator<Item = (VA, &'a InstructionDescriptor, &'a Flows, &'a Flows)> + 'a {
    let mut insns_iter = insns.insns_by_address.range(range.clone());
    let mut flows_by_src_iter = flows.flows_by_src.range(range.clone());
    let mut flows_by_dst_iter = flows.flows_by_dst.range(range);

    std::iter::from_fn(move || {
        if let Some((&insnva, insn)) = insns_iter.next() {
            let (mut va1, mut successors) = flows_by_src_iter.next().expect("flow index (src) out of sync");
            while insnva > *va1 {
                (va1, successors) = flows_by_src_iter.next().expect("flow index (src) out of sync");
            }

            let (mut va2, mut predecessors) = flows_by_dst_iter.next().expect("flow index (dst) out of sync");
            while insnva > *va2 {
                (va2, predecessors) = flows_by_dst_iter.next().expect("flow index (dst) out of sync");
            }

            Some((insnva, insn, predecessors, successors))
        } else {
            None
        }
    })
}

bitflags! {
    /// the properties of an instruction's flows that decide where basic blocks start and end.
    #[derive(Clone, Copy)]
    struct InsnFlags: u8 {
        const FALLS_THROUGH = 1 << 0;
        /// a non-fallthrough edge from here, like a jump.
        const BRANCHES = 1 << 1;
        /// a non-fallthrough edge, or more than one fallthrough, to here.
        const JOINS = 1 << 2;
        const START = 1 << 3;
        const LAST = 1 << 4;
    }
}

/// find the basic blocks that start within the given address range.
///
/// a basic block that starts before the range isn't found, even if it extends into the range,
/// so the range should start where a basic block starts.
///
/// returns None if a basic block extends past the end of the range.
/// that doesn't happen for the whole address space.
fn find_basic_blocks(
    insns: &InstructionIndex,
    flows: &FlowIndex,
    range: impl RangeBounds<VA> + Clone,
) -> Option<Vec<BasicBlock>> {
    // an instruction in the range, and the properties of its flows.
    #[derive(Clone, Copy)]
    struct Insn {
        va:     VA,
        length: u8,
        flags:  InsnFlags,
    }

    fn branches(succs: &Flows) -> bool {
        !empty(non_fallthrough_edges(succs))
    }

    fn joins(preds: &Flows) -> bool {
        !empty(non_fallthrough_edges(preds)) || fallthrough_edges(preds).count() > 1
    }

    // find the index of the instruction at the given address,
    // which is usually at the given index, unless instructions overlap.
    fn find(found: &[Insn], hint: usize, va: VA) -> Option<usize> {
        if found.get(hint).is_some_and(|insn| insn.va == va) {
            Some(hint)
        } else {
            found.binary_search_by_key(&va, |insn| insn.va).ok()
        }
    }

    // the instructions in the range, sorted by address.
    let mut found: Vec<Insn> = Default::default();

    // find all the basic block start addresses.
    //
    // scan through all instructions, looking for:
    //  1. instruction with nothing before it, or
    //  2. instruction with a non-fallthrough flow to it (e.g. jmp target), or
    //  3. multiple instructions fallthrough to it (they must be overlapping), or
    //  4. the prior instruction also branched elsewhere
    for (va, insn, preds, succs) in iter_insn_flows(insns, flows, range) {
        let start = empty(edges(preds))
            || joins(preds)
            || edge_targets(fallthrough_edges(preds)).any(|pred| {
                // a fallthrough comes from a lower address,
                // so we've seen it already, unless it's before the range.
                match find(&found, found.len().saturating_sub(1), pred) {
                    Some(i) => found[i].flags.contains(InsnFlags::BRANCHES),
                    None => branches(&flows.flows_by_src[&pred]),
                }
            });

        let mut flags = InsnFlags::empty();
        flags.set(InsnFlags::FALLS_THROUGH, !empty(fallthrough_edges(succs)));
        flags.set(InsnFlags::BRANCHES, branches(succs));
        flags.set(InsnFlags::JOINS, joins(preds));
        flags.set(InsnFlags::START, start);
        found.push(Insn {
            va,
            length: insn.length,
            flags,
        });
    }

    // find all the basic block last addresses.
    //
    // scan through all instructions, looking for:
    //  1. instruction with nothing after it, or
    //  2. instruction with no fallthrough (e.g. ret), or
    //  3. instruction with a non-fallthrough flow from it (e.g. jnz), or
    //  4. the next instruction starts a basic block, because of a jump or multiple fallthroughs to it.
    for i in 0..found.len() {
        let insn = found[i];
        let last = if insn.flags.contains(InsnFlags::BRANCHES) || !insn.flags.contains(InsnFlags::FALLS_THROUGH) {
            true
        } else {
            let next_va = insn.va + insn.length as u64;
            let next_joins = match find(&found, i + 1, next_va) {
                Some(j) => Some(found[j].flags.contains(InsnFlags::JOINS)),
                None => insns
                    .insns_by_address
                    .contains_key(&next_va)
                    .then(|| joins(&flows.flows_by_dst[&next_va])),
            };
            match next_joins {
                Some(next_joins) => next_joins,
                None => {
                    // there is not a subsequent instruction, so end of bb.
                    // e.g. flow to a non-instruction.
                    //
                    // this might be considered an analysis error.
                    // but, we don't have a better framework for this right now.
                    // options include:
                    //  1. pretend the current BB is ok, or
                    //  2. fail the whole analysis
                    // for right now, we're doing (1).
                    log::warn!("cfg: {:#x}: no subsequent instruction at {:#x}", insn.va, next_va);
                    true
                }
            }
        };
        found[i].flags.set(InsnFlags::LAST, last);
    }

    // walk from each start to the next last.
    let mut blocks: Vec<BasicBlock> = Default::default();
    for (i, first) in found.iter().enumerate() {
        if !first.flags.contains(InsnFlags::START) {
            continue;
        }

        let mut j = i;
        let mut length: u64 = 0;
        loop {
            let insn = &found[j];
            length += insn.length as u64;
            if insn.flags.contains(InsnFlags::LAST) {
                break;
            }
            // the next instruction exists, otherwise this would be a last.
            // it isn't in the range when the basic block extends past the range.
            j = find(&found, j + 1, insn.va + insn.length as u64)?;
        }

        blocks.push(BasicBlock {
            address: first.va,
            length,
            address_of_last_insn: found[j].va,
        });
    }

    Some(blocks)
}

/// the addresses whose flows changed while modifying the CFG.
#[derive(Default)]
struct Changes {
    /// the instructions whose successors changed.
    srcs:    Vec<VA>,
    /// the addresses whose predecessors changed.
    dsts:    Vec<VA>,
    /// the instructions that were removed, and their lengths.
    removed: BTreeMap<VA, u8>,
}

impl Changes {
    /// the addresses where a basic block may now start or end, sorted.
    ///
    /// whether an instruction starts a basic block depends on the flows to it,
    /// and on whether the instruction that falls through to it also branches.
    /// whether an instruction ends a basic block depends on the flows from it,
    /// and on the flows to the next instruction.
    fn addresses(&self, insns: &InstructionIndex, flows: &FlowIndex) -> Vec<VA> {
        let mut addresses: Vec<VA> = Vec::with_capacity(2 * (self.srcs.len() + self.dsts.len()));
        for &src in self.srcs.iter() {
            addresses.push(src);
            if let Some(succs) = flows.flows_by_src.get(&src) {
                addresses.extend(edge_targets(fallthrough_edges(succs)));
            }
        }
        for &dst in self.dsts.iter() {
            addresses.push(dst);
            // the instructions that end right at it (more than one, if they overlap).
            for (&prev, insn) in insns.insns_by_address.range(dst.saturating_sub(MAX_INSN_LENGTH)..dst) {
                if prev + insn.length as u64 == dst {
                    addresses.push(prev);
                }
            }
        }
        addresses.sort_unstable();
        addresses.dedup();
        addresses
    }

    /// did an instruction, before the changes, start before the given address and end after it?
    fn overlaps(&self, insns: &InstructionIndex, va: VA) -> bool {
        let before = va.saturating_sub(MAX_INSN_LENGTH)..va;
        insns
            .insns_by_address
            .range(before.clone())
            .map(|(&start, insn)| (start, insn.length))
            .chain(self.removed.range(before).map(|(&start, &length)| (start, length)))
            .any(|(start, length)| start + length as u64 > va)
    }
}

impl BasicBlockIndex {
    fn build_index(insns: &InstructionIndex, flows: &FlowIndex) -> Result<BasicBlockIndex> {
        let blocks =
            find_basic_blocks(insns, flows, ..).expect("a basic block extends past the end of the address space");

        let blocks_by_last_address = blocks.iter().map(|bb| (bb.address_of_last_insn, bb.address)).collect();
        let blocks_by_address = blocks.into_iter().map(|bb| (bb.address, bb)).collect();

        Ok(BasicBlockIndex {
            blocks_by_address,
            blocks_by_last_address,
        })
    }

    /// update the basic blocks around the given changes to the flows,
    /// rather than finding all of them again.
    ///
    /// the changes must only remove flows and instructions.
    ///
    /// returns false, having changed nothing, when basic blocks overlap around the changes,
    /// which is rare, and then the caller should find all the basic blocks again.
    fn update(&mut self, insns: &InstructionIndex, flows: &FlowIndex, changes: &Changes) -> bool {
        let Some(ranges) = self.ranges_containing(insns, flows, changes) else {
            return false;
        };

        // find all the new basic blocks before changing the index, so that it's unchanged on failure.
        // a basic block extends past its range only if it overlaps another.
        let Some(blocks) = ranges
            .iter()
            .map(|&(start, end)| find_basic_blocks(insns, flows, start..end))
            .collect::<Option<Vec<_>>>()
        else {
            return false;
        };

        for &(start, end) in ranges.iter() {
            let starts: Vec<VA> = self.blocks_by_address.range(start..end).map(|(&va, _)| va).collect();
            for va in starts {
                let bb = self.blocks_by_address.remove(&va).expect("basic block exists");
                self.blocks_by_last_address.remove(&bb.address_of_last_insn);
            }
        }

        for bb in blocks.into_iter().flatten() {
            self.blocks_by_last_address.insert(bb.address_of_last_insn, bb.address);
            self.blocks_by_address.insert(bb.address, bb);
        }

        true
    }

    /// the address ranges of the basic blocks that contain the addresses
    /// where a basic block may now start or end, sorted.
    ///
    /// a basic block grows only when the next one no longer starts a basic block,
    /// and then that start is one of these addresses, so its range is here, too.
    /// adjacent ranges are joined, so that the basic blocks found in each don't extend past it.
    ///
    /// returns None when basic blocks overlap around these addresses,
    /// since then an address may be in more than one basic block.
    fn ranges_containing(
        &self,
        insns: &InstructionIndex,
        flows: &FlowIndex,
        changes: &Changes,
    ) -> Option<Vec<(VA, VA)>> {
        let mut ranges: Vec<(VA, VA)> = Default::default();
        for va in changes.addresses(insns, flows) {
            if ranges.last().is_some_and(|&(_, end)| va < end) {
                continue;
            }

            let Some((&start, bb)) = self.blocks_by_address.range(..=va).next_back() else {
                continue;
            };
            // another basic block that contains the address would start earlier and overlap this one,
            // so one of its instructions would overlap the first instruction of this one.
            if changes.overlaps(insns, start) {
                return None;
            }
            let end = start + bb.length;
            if va >= end {
                continue;
            }

            match ranges.last_mut() {
                Some((_, last_end)) if *last_end >= start => *last_end = end.max(*last_end),
                _ => ranges.push((start, end)),
            }
        }
        Some(ranges)
    }
}

pub struct CFG {
    pub insns:        InstructionIndex,
    pub flows:        FlowIndex,
    pub basic_blocks: BasicBlockIndex,
}

impl CFG {
    pub fn from_instructions(module: &Module, insns: InstructionIndex) -> Result<CFG> {
        let flows = FlowIndex::build_index(module, &insns)?;
        let basic_blocks = BasicBlockIndex::build_index(&insns, &flows)?;

        Ok(CFG {
            insns,
            flows,
            basic_blocks,
        })
    }

    pub fn get_reachable_blocks(&self, va: VA) -> impl Iterator<Item = &BasicBlock> + '_ {
        log::debug!("cfg: reachable from: {:#x}", va);
        let mut seen: BTreeSet<VA> = Default::default();

        let mut queue: VecDeque<VA> = Default::default();
        if self.basic_blocks.blocks_by_address.contains_key(&va) {
            queue.push_back(va);
        }

        std::iter::from_fn(move || loop {
            let bbva = queue.pop_front()?;
            if seen.contains(&bbva) {
                continue;
            }
            log::debug!("cfg: reachable from: {:#x}: basic block: {:#x}", va, bbva);

            let bb = &self.basic_blocks.blocks_by_address[&bbva];

            let succs = &self.flows.flows_by_src[&bb.address_of_last_insn];
            for succ in edge_targets(direct_edges(edges(succs))) {
                if self.basic_blocks.blocks_by_address.contains_key(&succ).not() {
                    log::warn!(
                        "cfg: reachable from: {:#x}: basic block: {:#x}: succ: {:#x} (invalid)",
                        va,
                        bbva,
                        succ
                    );
                } else {
                    log::debug!(
                        "cfg: reachable from: {:#x}: basic block: {:#x}: succ: {:#x}",
                        va,
                        bbva,
                        succ
                    );
                    queue.push_back(succ);
                }
            }

            let preds = &self.flows.flows_by_dst[&bb.address];
            for pred in
                edge_targets(direct_edges(edges(preds))).map(|pred| self.basic_blocks.blocks_by_last_address[&pred])
            {
                log::debug!(
                    "cfg: reachable from: {:#x}: basic block: {:#x}: pred: {:#x}",
                    va,
                    bbva,
                    pred
                );
                queue.push_back(pred);
            }

            seen.insert(bbva);
            return Some(bb);
        })
    }

    pub fn get_reaches_from(&self, va: VA) -> impl Iterator<Item = &BasicBlock> + '_ {
        let mut seen: BTreeSet<VA> = Default::default();

        let mut queue: VecDeque<VA> = Default::default();
        if self.basic_blocks.blocks_by_address.contains_key(&va) {
            queue.push_back(va);
        }

        std::iter::from_fn(move || loop {
            let bbva = queue.pop_front()?;
            if seen.contains(&bbva) {
                continue;
            }

            let bb = &self.basic_blocks.blocks_by_address[&bbva];

            let succs = &self.flows.flows_by_src[&bb.address_of_last_insn];
            for succ in edge_targets(direct_edges(edges(succs))) {
                if self.basic_blocks.blocks_by_address.contains_key(&succ) {
                    queue.push_back(succ);
                }
            }

            seen.insert(bbva);
            return Some(bb);
        })
    }

    pub fn get_reaches_to(&self, va: VA) -> impl Iterator<Item = &BasicBlock> + '_ {
        let mut seen: BTreeSet<VA> = Default::default();

        let mut queue: VecDeque<VA> = Default::default();
        if self.basic_blocks.blocks_by_address.contains_key(&va) {
            queue.push_back(va);
        }

        std::iter::from_fn(move || loop {
            let bbva = queue.pop_front()?;
            if seen.contains(&bbva) {
                continue;
            }

            let bb = &self.basic_blocks.blocks_by_address[&bbva];

            let preds = &self.flows.flows_by_dst[&bb.address];
            for pred in
                edge_targets(direct_edges(edges(preds))).map(|pred| self.basic_blocks.blocks_by_last_address[&pred])
            {
                queue.push_back(pred);
            }

            seen.insert(bbva);
            return Some(bb);
        })
    }
}

// routines for modifying a CFG.
//
// three steps:
// 1. create batch,
// 2. operate on batch, queueing up operations,
// 3. commit batch, applying changes.
//
// this lets us collect a bunch of operations and apply them together,
// updating the basic blocks around the changes as a finalization step.
//
//
//     let mut batch: ChangeBatch = Default::default();
//     batch.prune_noret_call(0x401000);
//     batch.prune_noret_call(0x401103);
//     batch.prune_noret_call(0x401205);
//     cfg.commit(batch);
//
impl CFG {
    //
    // private implementations of change handling.
    //
    // these map to the members of the enum `Change`,
    // and are dispatched to within `CFG::commit()`.
    //

    // remove a flow from a given address.
    // this affects:
    //   - cfg.insn.insns_by_address[va].flows
    //   - cfg.flows.flows_by_src[va]
    //   - cfg.flows.flows_by_dst[target]
    //
    // if the target is then unreferenced by flows
    // (no flows to it), recursively remove its flows,
    // and remove that instruction.
    //
    // this is useful in cases like:
    //
    //     0: clc
    //     1: jnz 100
    //     2: int3
    //
    // and we know the jump will always be taken.
    // so we can remove the flow from 0x1 to 0x2,
    // which, because the instruction at 0x2 has a single flow to it,
    // will remove the instruction at 0x2 and onwards, recursively.
    //
    // note, this removes flows recursively "downwards",
    // that is, following flows from src to dst.
    // it does not remove flows "upwards".
    //
    // records the addresses whose flows changed in `changes`.
    fn prune_flow(&mut self, va: VA, flow: &Flow, changes: &mut Changes) {
        // remove flow from insn[va].flows
        // remove flow from flows.flows_by_src[va]
        // remove flow from flows.flows_by_dst[va]
        // if the target is now unreferenced:
        //   - recurse prune target instruction flows, and
        //   - remove target instruction
        //
        // at the moment, it removes flows recursively "downwards",
        // that is, following flows from src to dst.
        //
        // it does not remove flows "upwards".
        // this might be interesting, but not considered here.

        log::debug!("cfg: prune: {:x?} at {:#x}", flow, va);

        self.insns.insns_by_address.entry(va).and_modify(|insn| {
            insn.successors = insn.successors.clone().into_iter().filter(|s| s != flow).collect();
            log::trace!("cfg: prune: {:x?} at {:#x}: insn: {:x?}", flow, va, insn);
        });

        self.flows.flows_by_src.entry(va).and_modify(|succs| {
            *succs = succs.clone().into_iter().filter(|s| s != flow).collect();
            log::trace!("cfg: prune: {:x?} at {:#x}: succs: {:x?}", flow, va, succs);
        });

        let target = match flow {
            Flow::Fallthrough(va) => *va,
            Flow::Call(Target::Direct(va)) => *va,
            Flow::UnconditionalJump(Target::Direct(va)) => *va,
            Flow::ConditionalJump(va) => *va,
            Flow::Call(Target::Indirect(ptr)) => *ptr,
            Flow::UnconditionalJump(Target::Indirect(ptr)) => *ptr,
        };
        log::debug!("cfg: prune: {:x?} at {:#x}: target: {:#x}", flow, va, target);
        changes.srcs.push(va);
        changes.dsts.push(target);

        self.flows.flows_by_dst.entry(target).and_modify(|preds| {
            *preds = preds.clone().into_iter().filter(|s| s != &flow.swap(va)).collect();
            log::debug!(
                "cfg: prune: {:x?} at {:#x}: target: {:#x} preds: {:x?}",
                flow,
                va,
                target,
                preds
            );
        });

        match flow {
            // direct: potentially recurse prune target insn
            Flow::Fallthrough(_) => {}
            Flow::Call(Target::Direct(_)) => {}
            Flow::UnconditionalJump(Target::Direct(_)) => {}
            Flow::ConditionalJump(_) => {}

            // indirect: we're good, no recurse necessary.
            Flow::Call(Target::Indirect(_)) => {
                return;
            }
            Flow::UnconditionalJump(Target::Indirect(_)) => {
                return;
            }
        };

        // target has no flows pointing to it,
        // so its no longer an instruction.
        // remove it, and recurse any flows from it.
        if self.flows.flows_by_dst[&target].is_empty() {
            if self.insns.roots.contains(&target) {
                // the target is known to be code on its own account
                // (an entry point, export, symbol, pointer reference, ...),
                // so it stays, even with no flows to it.
                //
                // for example, a Go function's stack-growth stub is
                // `call runtime.morestack_noctxt; jmp <function start>`:
                // if the call is pruned as noret, the jump goes, but the
                // function (found via its pdata entry) must not.
                log::debug!("cfg: prune: {:x?} at {:#x}: target: {:#x}: root", flow, va, target);
                return;
            }

            log::debug!("cfg: prune: {:x?} at {:#x}: target: {:#x}: now empty", flow, va, target);
            // the target may not be an instruction at all:
            // a fallthrough or jump to bytes that didn't decode has a
            // flows_by_dst entry but no instruction and no flows of its own.
            if let Some(flows) = self.flows.flows_by_src.get(&target).cloned() {
                for flow in flows.iter() {
                    self.prune_flow(target, flow, changes);
                }
            }

            if let Some(insn) = self.insns.insns_by_address.remove(&target) {
                changes.removed.insert(target, insn.length);
            }
            self.flows.flows_by_src.remove(&target);
            self.flows.flows_by_dst.remove(&target);
            // TODO: this won't break a cycle/loop. but that sounds generally
            // hard.
        }
    }

    // prune fallthrough flows from the given call instruction,
    // leaving the call flow intact.
    //
    // this is useful in cases like:
    //
    //   1: push 0
    //   2: call [ExitProcess]
    //   3: int3
    //
    // here, we should not consider the instructions at 0x3 (int3) and beyond.
    // so, call `prune_noret_call` at 0x2 to remove the fallthrough
    // (and ending the basic block)
    // while maintaining the flow to ExitProcess.
    fn prune_noret_call(&mut self, va: VA, changes: &mut Changes) {
        // va should be a call instruction.
        // it should have two flows:
        //   - call func
        //   - fallthrough
        // keep the call, prune the fallthrough

        assert!(self.insns.insns_by_address.contains_key(&va));

        // use a copy so we can modify the indices.
        let succs = self.flows.flows_by_src[&va].clone();
        for fallthrough in fallthrough_edges(&succs) {
            self.prune_flow(va, fallthrough, changes);
        }
    }

    fn rebuild(&mut self) {
        // this should never fail: database inconsistency: programmer error
        self.basic_blocks =
            BasicBlockIndex::build_index(&self.insns, &self.flows).expect("failed to rebuild CFG index");
    }

    pub fn commit(&mut self, batch: ChangeBatch) {
        let mut changes: Changes = Default::default();
        for change in batch.changes.into_iter() {
            match change {
                Change::PruneFlow { va, flow } => self.prune_flow(va, &flow, &mut changes),
                Change::PruneNoretCall { va } => {
                    // When a batch contains multiple PruneNoretCall entries,
                    // an earlier entry's cascade (via prune_flow) can remove
                    // instructions queued for later processing. This happens
                    // when two callers share a fallthrough chain or are
                    // connected through flows where intermediaries have no
                    // other incoming edges.
                    if !self.insns.insns_by_address.contains_key(&va) {
                        continue;
                    }
                    self.prune_noret_call(va, &mut changes);
                }
            }
        }

        // the changes are usually few and local,
        // so update the basic blocks around them, rather than finding all the basic blocks again.
        if !self.basic_blocks.update(&self.insns, &self.flows, &changes) {
            self.rebuild();
        }
    }
}

enum Change {
    PruneFlow { va: VA, flow: Flow },
    PruneNoretCall { va: VA },
}

#[derive(Default)]
pub struct ChangeBatch {
    changes: Vec<Change>,
}

impl ChangeBatch {
    pub fn prune_flow(&mut self, va: VA, flow: Flow) {
        self.changes.push(Change::PruneFlow { va, flow });
    }

    pub fn prune_noret_call(&mut self, va: VA) {
        self.changes.push(Change::PruneNoretCall { va });
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

        let cfg = CFG::from_instructions(&module, insns)?;

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

        let cfg = CFG::from_instructions(&module, insns)?;

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

        let cfg = CFG::from_instructions(&module, insns)?;

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

        let cfg = CFG::from_instructions(&module, insns)?;

        assert_eq!(cfg.insns.insns_by_address.len(), 2);
        assert_eq!(cfg.basic_blocks.blocks_by_address.len(), 1);

        Ok(())
    }

    #[test]
    fn test_two_entry_points() -> Result<()> {
        // 0:  c3                      ret  | BB1
        // 1:  00
        // 2:  c3                      ret  | BB2
        let module = load_shellcode32(b"\xC3\x00\xC3");
        let mut insns: InstructionIndex = Default::default();

        insns.build_index(&module, 0x0)?;
        insns.build_index(&module, 0x2)?;

        let cfg = CFG::from_instructions(&module, insns)?;

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
        let cfg = CFG::from_instructions(&module, insns)?;
        // [jmp] -> [rol, ret]
        // [inc, ret]
        assert_eq!(cfg.basic_blocks.blocks_by_address.len(), 3);

        Ok(())
    }

    #[test]
    fn insns_at_high_base_address() -> Result<()> {
        // the page-split check in `read_insn_with_cache` used to compute the
        // page *base* instead of the offset within the page, so the page-cache
        // fast path was never taken for modules based above 0x1000
        // (i.e. any real module; the shellcode tests load at 0x0 and hid this).
        //
        // lay out two pages of NOPs with a RET at the very end, based at 0x401000,
        // so that the now-live fast path is exercised at a realistic address,
        // and instructions near the end of the first page exercise the
        // page-splitting slow path with a mapped subsequent page.
        let mut code = vec![0x90u8; 0x2000];
        code[0x1FFF] = 0xC3; // RET
        let module = crate::test::load_shellcode_at(crate::arch::Arch::X32, &code, 0x401000);

        let mut insns: InstructionIndex = Default::default();
        insns.build_index(&module, 0x401000)?;

        // 0x1FFF NOPs and one RET.
        assert_eq!(insns.insns_by_address.len(), 0x2000);
        assert!(insns.insns_by_address.contains_key(&0x401000));
        assert!(insns.insns_by_address.contains_key(&0x402FFF));

        Ok(())
    }

    #[test]
    fn insn_at_end_of_mapped_region() -> Result<()> {
        // regression test: an instruction within the final 15 bytes of the last
        // mapped page used to be dropped, because the page-splitting slow path
        // unconditionally read 0x10 bytes, which failed when the read crossed
        // into the unmapped subsequent page.
        //
        // note that the loaders map sections via `writezx`, which pads a full
        // extra zero page after page-aligned data, hiding this case. so map
        // exactly one page by hand, with a RET as the very last byte.
        let mut code = vec![0xCCu8; PAGE_SIZE];
        code[PAGE_SIZE - 1] = 0xC3; // RET

        let mut address_space = crate::aspace::RelativeAddressSpace::with_capacity(PAGE_SIZE as u64);
        address_space.map.write(0x0, &code).unwrap();
        assert!(!address_space.map.probe(PAGE_SIZE as u64), "next page must be unmapped");

        let module = Module {
            arch:          crate::arch::Arch::X32,
            sections:      vec![crate::module::Section {
                name:           "shellcode".to_string(),
                permissions:    Permissions::RWX,
                physical_range: 0x0..PAGE_SIZE as u64,
                virtual_range:  0x401000..0x401000 + PAGE_SIZE as u64,
            }],
            address_space: address_space.into_absolute(0x401000).unwrap(),
        };

        let mut insns: InstructionIndex = Default::default();
        insns.build_index(&module, 0x401FFF)?;

        assert!(insns.insns_by_address.contains_key(&0x401FFF));
        assert_eq!(insns.insns_by_address.len(), 1);

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

        let cfg = CFG::from_instructions(&pe.module, insns)?;

        assert_eq!(cfg.insns.insns_by_address.len(), 84368);
        assert_eq!(cfg.basic_blocks.blocks_by_address.len(), 17857);

        Ok(())
    }

    #[test]
    fn flow_index() -> Result<()> {
        // the flow index has the same flows, in the same order,
        // as when we insert each flow into the maps, one at a time.
        for rsrc in [Rsrc::K32, Rsrc::I236B] {
            let buf = get_buf(rsrc);
            let pe = crate::loader::pe::PE::from_bytes(&buf)?;
            let mut insns: InstructionIndex = Default::default();
            for function in crate::analysis::pe::find_functions(&pe)?.iter() {
                if let crate::analysis::pe::Function::Local(va) = function {
                    insns.build_index(&pe.module, *va)?;
                }
            }

            let mut flows_by_src: BTreeMap<VA, Flows> = Default::default();
            let mut flows_by_dst: BTreeMap<VA, Flows> = Default::default();
            for (&src, insn) in insns.insns_by_address.iter() {
                flows_by_src.insert(src, insn.successors.clone());
                flows_by_dst.entry(src).or_default();
                for succ in insn.successors.iter() {
                    let dst = match succ {
                        Flow::Fallthrough(va)
                        | Flow::Call(Target::Direct(va))
                        | Flow::UnconditionalJump(Target::Direct(va))
                        | Flow::ConditionalJump(va) => *va,
                        Flow::Call(Target::Indirect(ptr)) | Flow::UnconditionalJump(Target::Indirect(ptr)) => {
                            if !pe.module.probe_va(*ptr, Permissions::RWX) {
                                continue;
                            }
                            *ptr
                        }
                    };
                    flows_by_dst.entry(dst).or_default().push(succ.swap(src));
                }
            }

            let flows = FlowIndex::build_index(&pe.module, &insns)?;
            assert_eq!(flows.flows_by_src, flows_by_src);
            assert_eq!(flows.flows_by_dst, flows_by_dst);
        }

        Ok(())
    }

    #[test]
    fn reachable_blocks() -> Result<()> {
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
        let cfg = CFG::from_instructions(&module, insns)?;

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

    #[test]
    fn reachable_blocks_overlapping() -> Result<()> {
        // b8 ff c0 ff c0 c3
        // ---------------
        // mov eax, 0xC0FFC0FF
        //    ------
        //    inc eax
        //          ------
        //          inc eax
        //                ----
        //                ret
        let module = load_shellcode32(b"\xB8\xFF\xC0\xFF\xC0\xC3");
        let mut insns: InstructionIndex = Default::default();
        insns.build_index(&module, 0x0)?;
        insns.build_index(&module, 0x1)?;
        let cfg = CFG::from_instructions(&module, insns)?;

        assert_eq!(cfg.insns.insns_by_address.len(), 4);
        // [0: mov] -> [5: ret]
        // [1: inc, inc] -> [5: ret]
        assert_eq!(cfg.basic_blocks.blocks_by_address.len(), 3);

        // asking for reachable blocks from [5: ret]
        // so it should traverse back to [0: mov]
        // and also to [1: inc, inc].
        // both via fallthrough flows.
        let mut blocks = cfg.get_reachable_blocks(0x5).map(|bb| bb.address).collect::<Vec<_>>();
        blocks.sort();

        assert_eq!(&blocks[..], [0x0, 0x1, 0x5]);

        Ok(())
    }

    mod prune {
        use super::*;

        /// assert that the basic blocks, after updates, are the same as when found from scratch.
        fn assert_blocks_consistent(cfg: &CFG) {
            let full = BasicBlockIndex::build_index(&cfg.insns, &cfg.flows).unwrap();
            let blocks = |index: &BasicBlockIndex| {
                index
                    .blocks_by_address
                    .values()
                    .map(|bb| (bb.address, bb.length, bb.address_of_last_insn))
                    .collect::<Vec<_>>()
            };
            assert_eq!(blocks(&cfg.basic_blocks), blocks(&full));
            assert_eq!(cfg.basic_blocks.blocks_by_last_address, full.blocks_by_last_address);
        }

        #[test]
        fn prune_flow_into_undecodable_bytes() -> Result<()> {
            // 0: 90 nop
            // |
            // V fallthrough
            // 1: 90 nop
            // |
            // V fallthrough
            // 2: 06 (invalid in 64-bit mode: not an instruction)
            //
            // pruning the fallthrough into the undecodable bytes must not
            // panic.
            let module = load_shellcode64(b"\x90\x90\x06");
            let mut insns: InstructionIndex = Default::default();
            insns.build_index(&module, 0x0)?;
            let mut cfg = CFG::from_instructions(&module, insns)?;

            assert!(cfg.insns.insns_by_address.contains_key(&0x2).not());

            let fallthrough = cfg.flows.flows_by_src[&0x0][0];
            let mut batch: ChangeBatch = Default::default();
            batch.prune_flow(0x0, fallthrough);
            cfg.commit(batch);
            assert_blocks_consistent(&cfg);

            assert_eq!(cfg.insns.insns_by_address.len(), 1);
            assert!(cfg.insns.insns_by_address.contains_key(&0x0));
            assert!(cfg.insns.insns_by_address.contains_key(&0x1).not());

            Ok(())
        }

        #[test]
        fn prune_flow_keeps_roots() -> Result<()> {
            // 0: EB 02 jmp 4
            // 2: 90 90 (padding)
            // 4: 90 nop     <- also a root: explored on its own
            // 5: C3 ret
            //
            // pruning the jump leaves the root with no flows to it,
            // but it must stay, along with what follows it.
            let module = load_shellcode32(b"\xEB\x02\x90\x90\x90\xC3");
            let mut insns: InstructionIndex = Default::default();
            insns.build_index(&module, 0x0)?;
            insns.build_index(&module, 0x4)?;
            let mut cfg = CFG::from_instructions(&module, insns)?;

            let jump = cfg.flows.flows_by_src[&0x0][0];
            let mut batch: ChangeBatch = Default::default();
            batch.prune_flow(0x0, jump);
            cfg.commit(batch);
            assert_blocks_consistent(&cfg);

            assert!(cfg.insns.insns_by_address.contains_key(&0x4));
            assert!(cfg.insns.insns_by_address.contains_key(&0x5));
            assert!(cfg.flows.flows_by_dst[&0x4].is_empty());
            assert!(cfg.basic_blocks.blocks_by_address.contains_key(&0x4));

            Ok(())
        }

        #[test]
        fn prune_flow_simple_bb() -> Result<()> {
            // 0: 90 nop
            // |
            // V fallthrough
            // 1: 90 nop
            // |
            // V fallthrough
            // 2: 90 nop
            // |
            // V fallthrough
            // 3: C3 ret
            let module = load_shellcode32(b"\x90\x90\x90\xC3");
            let mut insns: InstructionIndex = Default::default();
            insns.build_index(&module, 0x0)?;
            let mut cfg = CFG::from_instructions(&module, insns)?;

            let fallthrough = cfg.flows.flows_by_src[&0x1][0];
            let mut batch: ChangeBatch = Default::default();
            batch.prune_flow(0x1, fallthrough);
            cfg.commit(batch);
            assert_blocks_consistent(&cfg);

            // 0: 90 nop
            // |
            // V fallthrough
            // 1: 90 nop
            //
            // db 90 c3
            assert_eq!(cfg.insns.insns_by_address.len(), 2);
            assert_eq!(cfg.basic_blocks.blocks_by_address.len(), 1);
            assert_eq!(cfg.basic_blocks.blocks_by_address[&0].length, 2);

            assert!(cfg.insns.insns_by_address.contains_key(&0x0));
            assert!(cfg.insns.insns_by_address.contains_key(&0x1));
            assert!(cfg.insns.insns_by_address.contains_key(&0x2).not());
            assert!(cfg.insns.insns_by_address.contains_key(&0x3).not());

            Ok(())
        }

        #[test]
        fn prune_flow_few_bbs() -> Result<()> {
            //    ┌─────────────────────────────────┐
            //    │ 0: B8 01 00 00 00  mov eax, 0x1 │
            //    │ 5: 75 05           jne      C   │
            //    └─────────────┬─┬─────────────────┘
            //      fallthrough │ │
            //                  │ └────────────────────┐
            //                  ▼                      │
            //    ┌─────────────────────────────────┐  │ cond jump
            //    │ 7: B8 02 00 00 00  mov eax, 02  │  │
            //    └─────────────┬───────────────────┘  │
            //      fallthrough │                      │
            //                  │ ┌────────────────────┘
            //                  ▼ ▼
            //    ┌─────────────────────────────────┐
            //    │ C: C3              ret          │
            //    └─────────────────────────────────┘
            let module = load_shellcode32(b"\xB8\x01\x00\x00\x00\x75\x05\xB8\x02\x00\x00\x00\xC3");
            let mut insns: InstructionIndex = Default::default();
            insns.build_index(&module, 0x0)?;
            let mut cfg = CFG::from_instructions(&module, insns)?;

            // cut second fallthrough, which should remove the edge,
            // but not any of the instructions.

            let fallthrough = fallthrough_edges(&cfg.flows.flows_by_src[&0x7]).next().unwrap();
            let mut batch: ChangeBatch = Default::default();
            batch.prune_flow(0x7, *fallthrough);
            cfg.commit(batch);
            assert_blocks_consistent(&cfg);

            //    ┌─────────────────────────────────┐
            //    │ 0: B8 01 00 00 00  mov eax, 0x1 │
            //    │ 5: 75 05           jne      C   │
            //    └─────────────┬─┬─────────────────┘
            //      fallthrough │ │
            //                  │ └────────────────────┐
            //                  ▼                      │
            //    ┌─────────────────────────────────┐  │ cond jump
            //    │ 7: B8 02 00 00 00  mov eax, 02  │  │
            //    └─────────────────────────────────┘  │
            //                                         │
            //                    ┌────────────────────┘
            //                    ▼
            //    ┌─────────────────────────────────┐
            //    │ C: C3              ret          │
            //    └─────────────────────────────────┘

            assert_eq!(cfg.insns.insns_by_address.len(), 4);
            assert_eq!(cfg.basic_blocks.blocks_by_address.len(), 3);

            assert!(cfg.insns.insns_by_address.contains_key(&0x0));
            assert!(cfg.insns.insns_by_address.contains_key(&0x5));
            assert!(cfg.insns.insns_by_address.contains_key(&0x7));
            assert!(cfg.insns.insns_by_address.contains_key(&0xC));

            // cut the first fallthrough, which should remove the edge,
            // and also the basic block at 0x7 (mov eax, 0x2).

            let fallthrough = fallthrough_edges(&cfg.flows.flows_by_src[&0x5]).next().unwrap();
            let mut batch: ChangeBatch = Default::default();
            batch.prune_flow(0x5, *fallthrough);
            cfg.commit(batch);
            assert_blocks_consistent(&cfg);

            //    ┌─────────────────────────────────┐
            //    │ 0: B8 01 00 00 00  mov eax, 0x1 │
            //    │ 5: 75 05           jne      C   │
            //    └───────────────┬─────────────────┘
            //                    │
            //                    └────────────────────┐
            //                                         │
            //    ┌─────────────────────────────────┐  │ cond jump
            //    │ 7: B8 02 00 00 00               │  │
            //    └─────────────────────────────────┘  │
            //                                         │
            //                    ┌────────────────────┘
            //                    ▼
            //    ┌─────────────────────────────────┐
            //    │ C: C3              ret          │
            //    └─────────────────────────────────┘

            assert_eq!(cfg.insns.insns_by_address.len(), 3);
            assert_eq!(cfg.basic_blocks.blocks_by_address.len(), 2);

            assert!(cfg.insns.insns_by_address.contains_key(&0x0));
            assert!(cfg.insns.insns_by_address.contains_key(&0x5));
            assert!(cfg.insns.insns_by_address.contains_key(&0x7).not());
            assert!(cfg.insns.insns_by_address.contains_key(&0xC));

            Ok(())
        }

        #[test]
        fn prune_noret_call_batch_cascade_removal() -> Result<()> {
            // 0x00: call 0x10   ; E8 0B 00 00 00
            // 0x05: call 0x10   ; E8 06 00 00 00
            // 0x0A: nop (x6)
            // 0x10: ret         ; C3
            //
            // Both 0x00 and 0x05 call the same target.
            // PruneNoretCall(0x00) prunes fallthrough to 0x05, which
            // cascade-removes 0x05 (its only incoming flow was that
            // fallthrough). commit() skips the subsequent
            // PruneNoretCall(0x05) since the instruction no longer exists.
            let module = load_shellcode32(b"\xE8\x0B\x00\x00\x00\xE8\x06\x00\x00\x00\x90\x90\x90\x90\x90\x90\xC3");
            let mut insns: InstructionIndex = Default::default();
            insns.build_index(&module, 0x0)?;
            let mut cfg = CFG::from_instructions(&module, insns)?;

            assert!(cfg.insns.insns_by_address.contains_key(&0x00));
            assert!(cfg.insns.insns_by_address.contains_key(&0x05));
            assert!(cfg.insns.insns_by_address.contains_key(&0x10));

            let mut batch: ChangeBatch = Default::default();
            batch.prune_noret_call(0x00);
            batch.prune_noret_call(0x05);
            cfg.commit(batch);
            assert_blocks_consistent(&cfg);

            assert!(cfg.insns.insns_by_address.contains_key(&0x00));
            assert!(cfg.insns.insns_by_address.contains_key(&0x05).not());
            assert!(cfg.insns.insns_by_address.contains_key(&0x0A).not());
            assert!(cfg.insns.insns_by_address.contains_key(&0x10));

            Ok(())
        }

        #[test]
        fn prune_merges_blocks() -> Result<()> {
            // 0x0: E8 1B 00 00 00 call 0x20 (noret)
            // 0x5: EB 04          jmp 0xB  (dead: only reached by the fallthrough)
            // 0x7: 90             nop      <- also a root: explored on its own
            // 0x8: 90 90 90       nop
            // 0xB: 90             nop      (jump target, starts a basic block)
            // 0xC: C3             ret
            // 0xD: CC ...         padding
            // 0x20: EB FE         jmp $
            //
            // pruning the call's fallthrough removes the jump,
            // so the basic blocks at 0x7 and 0xB merge.
            let mut code = b"\xE8\x1B\x00\x00\x00\xEB\x04\x90\x90\x90\x90\x90\xC3".to_vec();
            code.resize(0x20, 0xCC);
            code.extend_from_slice(b"\xEB\xFE");
            let module = load_shellcode32(&code);
            let mut insns: InstructionIndex = Default::default();
            insns.build_index(&module, 0x0)?;
            insns.build_index(&module, 0x7)?;
            let mut cfg = CFG::from_instructions(&module, insns)?;

            assert_eq!(cfg.basic_blocks.blocks_by_address[&0x7].length, 4);
            assert!(cfg.basic_blocks.blocks_by_address.contains_key(&0xB));

            let mut batch: ChangeBatch = Default::default();
            batch.prune_noret_call(0x0);
            cfg.commit(batch);
            assert_blocks_consistent(&cfg);

            assert!(cfg.insns.insns_by_address.contains_key(&0x5).not());
            assert_eq!(cfg.basic_blocks.blocks_by_address[&0x0].length, 5);
            assert_eq!(cfg.basic_blocks.blocks_by_address[&0x7].length, 6);
            assert!(cfg.basic_blocks.blocks_by_address.contains_key(&0xB).not());

            Ok(())
        }

        #[test]
        fn prune_overlapping_instructions() -> Result<()> {
            // 00: EB FF    jmp $+1
            // 01: FF C0    inc eax  (only reached by the jump)
            // 03: C3       ret
            //
            // 02: C0 C3 C3 rol bl, 0xC3  <- also a root: explored on its own
            // 05: C3       ret
            //
            // the basic blocks overlap. pruning the jump removes [inc, ret].
            let module = load_shellcode32(b"\xEB\xFF\xC0\xC3\xC3\xC3");
            let mut insns: InstructionIndex = Default::default();
            insns.build_index(&module, 0x0)?;
            insns.build_index(&module, 0x2)?;
            let mut cfg = CFG::from_instructions(&module, insns)?;
            assert_eq!(cfg.basic_blocks.blocks_by_address.len(), 3);

            let jump = cfg.flows.flows_by_src[&0x0][0];
            let mut batch: ChangeBatch = Default::default();
            batch.prune_flow(0x0, jump);
            cfg.commit(batch);
            assert_blocks_consistent(&cfg);

            assert!(cfg.insns.insns_by_address.contains_key(&0x1).not());
            assert!(cfg.insns.insns_by_address.contains_key(&0x3).not());
            assert_eq!(cfg.basic_blocks.blocks_by_address.len(), 2);
            assert_eq!(cfg.basic_blocks.blocks_by_address[&0x2].length, 4);

            Ok(())
        }

        #[test]
        fn prune_in_overlapped_block() -> Result<()> {
            // 0: B8 C3 90 90 90  mov eax, 0x909090C3
            // 5: 90              nop
            // 6: 90              nop
            // 7: C3              ret
            //
            // 1: C3              ret  <- also a root: explored on its own
            //
            // the basic block at 0x1 is within the one at 0x0, so it's the closest one before 0x6.
            // pruning the fallthrough to 0x6 must still update the basic block at 0x0.
            let module = load_shellcode32(b"\xB8\xC3\x90\x90\x90\x90\x90\xC3");
            let mut insns: InstructionIndex = Default::default();
            insns.build_index(&module, 0x0)?;
            insns.build_index(&module, 0x1)?;
            let mut cfg = CFG::from_instructions(&module, insns)?;
            assert_eq!(cfg.basic_blocks.blocks_by_address[&0x0].length, 8);
            assert_eq!(cfg.basic_blocks.blocks_by_address[&0x1].length, 1);

            let fallthrough = cfg.flows.flows_by_src[&0x5][0];
            let mut batch: ChangeBatch = Default::default();
            batch.prune_flow(0x5, fallthrough);
            cfg.commit(batch);
            assert_blocks_consistent(&cfg);

            assert_eq!(cfg.basic_blocks.blocks_by_address[&0x0].length, 6);

            Ok(())
        }

        /// in rounds, prune the fallthrough of some of the calls, like noret analysis does,
        /// and some single flows, and check the updated basic blocks each time.
        fn check_updates(rsrc: Rsrc) -> Result<()> {
            let buf = get_buf(rsrc);
            let pe = crate::loader::pe::PE::from_bytes(&buf)?;
            let mut ws = crate::workspace::PEWorkspace::from_pe(crate::workspace::config::empty(), pe)?;
            let cfg = &mut ws.cfg;

            for round in 0..4 {
                let calls: Vec<VA> = cfg
                    .flows
                    .flows_by_src
                    .iter()
                    .filter(|(_, flows)| flows.iter().any(|flow| matches!(flow, Flow::Call(_))))
                    .map(|(&va, _)| va)
                    .collect();
                let mut batch: ChangeBatch = Default::default();
                for &va in calls.iter().step_by(13 + round) {
                    batch.prune_noret_call(va);
                }
                cfg.commit(batch);
                assert_blocks_consistent(cfg);

                // prune single jumps and fallthroughs, which may merge basic blocks.
                let flows: Vec<(VA, Flow)> = cfg
                    .flows
                    .flows_by_src
                    .iter()
                    .flat_map(|(&va, flows)| flows.iter().map(move |&flow| (va, flow)))
                    .filter(|(_, flow)| !matches!(flow, Flow::Call(_)))
                    .step_by(cfg.flows.flows_by_src.len() / 16 + round)
                    .collect();
                for (va, flow) in flows {
                    if !cfg
                        .flows
                        .flows_by_src
                        .get(&va)
                        .is_some_and(|flows| flows.contains(&flow))
                    {
                        continue;
                    }
                    let mut batch: ChangeBatch = Default::default();
                    batch.prune_flow(va, flow);
                    cfg.commit(batch);
                    assert_blocks_consistent(cfg);
                }
            }

            Ok(())
        }

        #[test]
        fn update_nop() -> Result<()> {
            check_updates(Rsrc::NOP)
        }

        #[test]
        fn update_mimikatz() -> Result<()> {
            check_updates(Rsrc::MIMI)
        }

        #[test]
        fn update_overlapping() -> Result<()> {
            // these have instructions, and basic blocks, that overlap.
            check_updates(Rsrc::I236A)?;
            check_updates(Rsrc::I236B)
        }
    }
}
