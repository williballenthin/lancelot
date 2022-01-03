use std::collections::BTreeMap;

use crate::VA;

pub mod flow;
use flow::Flows;

mod local;
pub use local::build_cfg;

mod global;

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

#[derive(Default)]
pub struct CFG {
    // we use a btree so that we can conveniently iterate in order.
    // alternative choice would be an FNV hash map,
    // because the keys are small.
    pub basic_blocks: BTreeMap<VA, BasicBlock>,
}

impl CFG {
    pub fn len(&self) -> usize {
        self.basic_blocks.len()
    }
}
