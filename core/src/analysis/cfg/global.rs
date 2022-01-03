use std::collections::btree_map::Entry;

use anyhow::Result;

use crate::analysis::cfg::{flow::Flows, CFG};

pub fn merge_cfg(dst: &mut CFG, src: CFG) -> Result<()> {
    for (va, bb) in src.basic_blocks.into_iter() {
        match dst.basic_blocks.entry(va) {
            Entry::Occupied(mut existing) => {
                let existing = existing.get_mut();

                if existing.address != bb.address {
                    // programming error.
                    // the indexed address does not match the found address.
                    panic!("addresses don't match");
                }

                if existing.length != bb.length {
                    unimplemented!("mismatched bb sizes");
                }

                let mut new_successors: Flows = Default::default();
                // TODO: this is O(n**2), does that ever matter?
                for succ in bb.successors.iter() {
                    if existing
                        .successors
                        .iter()
                        .find(|&existing_succ| existing_succ == succ)
                        .is_none()
                    {
                        new_successors.push(*succ)
                    }
                }
                existing.successors.extend(new_successors);

                let mut new_predecessors: Flows = Default::default();
                // TODO: this is O(n**2), does that ever matter?
                for succ in bb.predecessors.iter() {
                    if existing
                        .predecessors
                        .iter()
                        .find(|&existing_succ| existing_succ == succ)
                        .is_none()
                    {
                        new_predecessors.push(*succ)
                    }
                }
                existing.predecessors.extend(new_predecessors);
            }
            Entry::Vacant(entry) => {
                entry.insert(bb);
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{
        analysis::cfg::{flow::Flow, BasicBlock, CFG},
        VA,
    };
    use anyhow::Result;

    fn new_basic_block(address: VA, length: u64) -> BasicBlock {
        BasicBlock {
            address,
            length,
            predecessors: smallvec::smallvec![],
            successors: smallvec::smallvec![],
        }
    }

    // an empty CFG + empty CFG = empty CFG
    #[test]
    fn empty_plus_empty() -> Result<()> {
        let mut dst: CFG = Default::default();
        let src: CFG = Default::default();

        super::merge_cfg(&mut dst, src).unwrap();
        assert_eq!(dst.len(), 0);

        Ok(())
    }

    #[test]
    fn one_plus_empty() -> Result<()> {
        let mut dst: CFG = Default::default();
        let src: CFG = Default::default();

        dst.basic_blocks.insert(0x0, new_basic_block(0x0, 1));

        super::merge_cfg(&mut dst, src).unwrap();
        assert_eq!(dst.len(), 1);

        Ok(())
    }

    #[test]
    fn empty_plus_one() -> Result<()> {
        let mut dst: CFG = Default::default();
        let mut src: CFG = Default::default();

        src.basic_blocks.insert(0x0, new_basic_block(0x0, 1));

        super::merge_cfg(&mut dst, src).unwrap();
        assert_eq!(dst.len(), 1);

        Ok(())
    }

    #[test]
    fn disjoint_add() -> Result<()> {
        let mut dst: CFG = Default::default();
        let mut src: CFG = Default::default();

        dst.basic_blocks.insert(0x1, new_basic_block(0x1, 1));
        src.basic_blocks.insert(0x0, new_basic_block(0x0, 1));

        super::merge_cfg(&mut dst, src).unwrap();
        assert_eq!(dst.len(), 2);

        Ok(())
    }

    #[test]
    fn duplicate_block() -> Result<()> {
        let mut dst: CFG = Default::default();
        let mut src: CFG = Default::default();

        dst.basic_blocks.insert(0x0, new_basic_block(0x0, 1));

        src.basic_blocks.insert(0x0, new_basic_block(0x0, 1));

        super::merge_cfg(&mut dst, src).unwrap();
        assert_eq!(dst.len(), 1);

        Ok(())
    }

    // when the same BB is encountered (same address and size),
    // merge the preds and succs.
    #[test]
    fn merge_preds_and_succs() -> Result<()> {
        let mut dst: CFG = Default::default();
        let mut src: CFG = Default::default();

        dst.basic_blocks.insert(
            0x0,
            BasicBlock {
                address:      0x0,
                length:       1,
                predecessors: smallvec::smallvec![],
                successors:   smallvec::smallvec![Flow::Fallthrough(0x1)],
            },
        );

        src.basic_blocks.insert(
            0x0,
            BasicBlock {
                address:      0x0,
                length:       1,
                // uncond jmp is new
                predecessors: smallvec::smallvec![Flow::UnconditionalJump(0x1)],
                // fallthrough is a duplicate
                // cond jmp is new
                successors:   smallvec::smallvec![Flow::Fallthrough(0x1), Flow::ConditionalJump(0x2)],
            },
        );

        super::merge_cfg(&mut dst, src).unwrap();
        assert_eq!(dst.len(), 1);
        assert_eq!(dst.basic_blocks.get(&0x0).unwrap().predecessors.len(), 1);
        assert_eq!(dst.basic_blocks.get(&0x0).unwrap().successors.len(), 2);

        Ok(())
    }
}
