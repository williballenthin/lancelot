use std::collections::HashMap;
use std::collections::VecDeque;
use num::{ToPrimitive};

use failure::{Error, Fail};
use log::{warn, debug};

use super::arch::{Arch};
use super::loader::{LoadedModule, Section};
use super::flowmeta::FlowMeta;
use super::workspace::{Workspace};

#[derive(Debug, Fail)]
pub enum AnalysisError {
    #[fail(display = "foo")]
    Foo,
    #[fail(display = "foo")]
    InvalidInstruction
}

pub enum AnalysisCommand<A: Arch> {
    MakeInsn(A::RVA),
}

pub struct XrefAnalysis<A: Arch> {
    // dst rva -> src rva
    to: HashMap<A::RVA, A::RVA>,
    // src rva -> dst rva
    from: HashMap<A::RVA, A::RVA>,
}

pub struct FlowAnalysis<A: Arch> {
    // one entry for each section in the module.
    // if executable, then one FlowMeta for each address in the section.
    // that is, Vec<FlowMeta>.len() == Section.buf.len()
    meta: Vec<Vec<FlowMeta>>,
    xrefs: XrefAnalysis<A>,
}

pub struct Analysis<A: Arch> {
    queue: VecDeque<AnalysisCommand<A>>,

    flow: FlowAnalysis<A>,
    // datameta
    // symbols
    // functions
}

impl<A: Arch> Analysis<A> {
    pub fn new(module: &LoadedModule<A>) -> Analysis<A> {
        let flow_meta: Vec<Vec<FlowMeta>> = module.sections.iter()
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
            flow: FlowAnalysis {
                meta: flow_meta,
                xrefs: XrefAnalysis {
                    to: HashMap::new(),
                    from: HashMap::new(),
                }
            }
        }
    }

}

// here we've logically split off the analysis portion of workspace.
// this should keep file sizes smaller, and hopefully easier to understand.
impl<A: Arch + 'static> Workspace<A> {
    pub fn make_insn(&mut self, rva: A::RVA) -> Result<(), Error> {
        self.analysis.queue.push_back(AnalysisCommand::MakeInsn(rva));
        Ok(())
    }

    fn get_meta(&self, rva: A::RVA) -> Option<FlowMeta> {
        self.module.sections
            .iter()
            .enumerate()
            .filter(|(_, section)| section.contains(rva))
            .nth(0)
            .and_then(|(i, section): (usize, &Section<A>)| -> Option<FlowMeta> {
                // rva is guaranteed to be within this section,
                // so we can do an unchecked subtract here.
                let offset = rva - section.addr;
                A::RVA::to_usize(&offset)
                    .and_then(|offset| {
                        Some(self.analysis.flow.meta[i][offset].clone())
                    })
            })
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
        let mut meta = match self.get_meta(rva) {
            None => {
                // this might happen if:
                //   - the instruction is in a non-executable section
                //   - the memory is not mapped
                warn!("invalid instruction: no flow meta: {:x}", rva);
                return Ok(vec![]);
            },
            Some(meta) => {
                if meta.is_insn() {
                    debug!("duplicate instruction: {:x}", rva);
                    return Ok(vec![]);
                } else {
                    // this is the happy path:
                    //   - this is a valid place for an instruction
                    //   - and it doesn't yet exist
                    meta
                }
            }
        };

        let insn = match self.read_insn(rva) {
            Err(e) => {
                warn!("invalid instruction: {:}: {:x}", e, rva);
                return Ok(vec![]);
            },
            Ok(insn) => insn,
        };

        // 2. compute instruction len
        let length = insn.length;

        // 3. compute fallthrough
        // 4. compute flow ref
        // 5. update flowmeta
        Ok(ret)
    }

    pub fn analyze(&mut self) -> Result<(), Error> {
        while let Some(cmd) = self.analysis.queue.pop_front() {
            let cmds = match cmd {
                AnalysisCommand::MakeInsn(rva) => self.handle_make_insn(rva)?,
            };
            self.analysis.queue.extend(cmds);
        }

        Ok(())
    }
}
