use std::collections::HashMap;

use crate::VA;

#[derive(Debug, Clone)]
pub struct BasicBlock {
    /// start VA of the basic block.
    pub addr: VA,

    /// length of the basic block in bytes.
    pub length: u64,

    /// VAs of start addresses of basic blocks that flow here.
    // TODO: use SmallVec::<[VA; 1]>
    pub predecessors: Vec<VA>,

    /// VAs of start addresses of basic blocks that flow from here.
    // TODO: use SmallVec::<[VA; 2]>
    pub successors: Vec<VA>,
}

pub struct CFG {
    // TODO: use FNV because the keys are small.
    basic_blocks: HashMap<VA, BasicBlock>,
}
