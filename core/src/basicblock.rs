use super::arch::RVA;

#[derive(Debug, Clone)]
pub struct BasicBlock {
    /// start RVA of the basic block.
    pub addr: RVA,

    /// length of the basic block in bytes.
    pub length: u64,

    /// RVAs of start addresses of basic blocks that flow here.
    pub predecessors: Vec<RVA>,

    /// RVAs of start addresses of basic blocks that flow from here.
    pub successors: Vec<RVA>,

    /// RVAs of instructions found in this basic block.
    pub insns: Vec<RVA>,
}