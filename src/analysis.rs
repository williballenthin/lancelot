use std::collections::HashMap;
use std::collections::VecDeque;
use num::{ToPrimitive};

use log::{warn, debug};
use failure::{Error, Fail};
use zydis::gen::*;

use super::arch::{Arch};
use super::xref::{Xref, XrefType};
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
    // TODO: use FNV because the keys are small.
    // TODO: use SmallVec(1) for `.from` values,
    // TODO: use SmallVec(X) for `.to` values,

    // dst rva -> src rva
    to: HashMap<A::RVA, A::RVA>,
    // src rva -> dst rva
    from: HashMap<A::RVA, A::RVA>,
}

pub struct FlowAnalysis<A: Arch> {
    // one entry for each section in the module.
    // if executable, then one FlowMeta for each address in the section.
    // that is, Vec<FlowMeta>.len() == Section.buf.len()
    // TODO: order these entries so that the most common sections are first (`.code`?)
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

    /// Does the given instruction have a fallthrough flow?
    ///
    /// ```
    /// use lancelot::test;
    ///
    /// // JMP $+0;
    /// let insn = test::get_shellcode32_workspace(b"\xEB\xFE").read_insn(0x0).unwrap();
    /// assert_eq!(ws::does_insn_fallthrough(&insn), false);
    ///
    /// // PUSH 0x11
    /// let ws = test::get_shellcode32_workspace(b"\x6A\x11").read_insn(0x0).unwrap();
    /// assert_eq!(ws::does_insn_fallthrough(&insn), true);
    /// ```
    pub fn does_insn_fallthrough(insn: &ZydisDecodedInstruction) -> bool {
        match insn.mnemonic as i32 {
            ZYDIS_MNEMONIC_JMP => false,
            ZYDIS_MNEMONIC_RET => false,
            ZYDIS_MNEMONIC_IRET => false,
            ZYDIS_MNEMONIC_IRETD => false,
            ZYDIS_MNEMONIC_IRETQ => false,
            // TODO: call may not fallthrough if function is noret.
            // will need another pass to clean this up.
            ZYDIS_MNEMONIC_CALL => true,
            _ => true,
        }
    }

    fn get_call_insn_flow(&self, rva: A::RVA, insn: &ZydisDecodedInstruction) -> Result<Vec<Xref<A>>, Error> {
        // TODO
        Ok(vec![])
    }
    fn get_jmp_insn_flow(&self, rva: A::RVA, insn: &ZydisDecodedInstruction) -> Result<Vec<Xref<A>>, Error> {
        // TODO
        Ok(vec![])
    }
    fn get_ret_insn_flow(&self, rva: A::RVA, insn: &ZydisDecodedInstruction) -> Result<Vec<Xref<A>>, Error> {
        // TODO
        Ok(vec![])
    }
    fn get_cjmp_insn_flow(&self, rva: A::RVA, insn: &ZydisDecodedInstruction) -> Result<Vec<Xref<A>>, Error> {
        // TODO
        Ok(vec![])
    }
    fn get_cmov_insn_flow(&self, rva: A::RVA, insn: &ZydisDecodedInstruction) -> Result<Vec<Xref<A>>, Error> {
        // TODO
        Ok(vec![])
    }

    fn get_insn_flow(&self, rva: A::RVA, insn: &ZydisDecodedInstruction) -> Result<Vec<Xref<A>>, Error> {
        match insn.mnemonic as i32 {
            ZYDIS_MNEMONIC_CALL => self.get_call_insn_flow(rva, insn),

            ZYDIS_MNEMONIC_JMP => self.get_jmp_insn_flow(rva, insn),

            ZYDIS_MNEMONIC_RET
            | ZYDIS_MNEMONIC_IRET
            | ZYDIS_MNEMONIC_IRETD
            | ZYDIS_MNEMONIC_IRETQ => self.get_ret_insn_flow(rva, insn),

            ZYDIS_MNEMONIC_JB
            | ZYDIS_MNEMONIC_JBE
            | ZYDIS_MNEMONIC_JCXZ
            | ZYDIS_MNEMONIC_JECXZ
            | ZYDIS_MNEMONIC_JKNZD
            | ZYDIS_MNEMONIC_JKZD
            | ZYDIS_MNEMONIC_JL
            | ZYDIS_MNEMONIC_JLE
            | ZYDIS_MNEMONIC_JNB
            | ZYDIS_MNEMONIC_JNBE
            | ZYDIS_MNEMONIC_JNL
            | ZYDIS_MNEMONIC_JNLE
            | ZYDIS_MNEMONIC_JNO
            | ZYDIS_MNEMONIC_JNP
            | ZYDIS_MNEMONIC_JNS
            | ZYDIS_MNEMONIC_JNZ
            | ZYDIS_MNEMONIC_JO
            | ZYDIS_MNEMONIC_JP
            | ZYDIS_MNEMONIC_JRCXZ
            | ZYDIS_MNEMONIC_JS
            | ZYDIS_MNEMONIC_JZ => self.get_cjmp_insn_flow(rva, insn),

            ZYDIS_MNEMONIC_CMOVB
            | ZYDIS_MNEMONIC_CMOVBE
            | ZYDIS_MNEMONIC_CMOVL
            | ZYDIS_MNEMONIC_CMOVLE
            | ZYDIS_MNEMONIC_CMOVNB
            | ZYDIS_MNEMONIC_CMOVNBE
            | ZYDIS_MNEMONIC_CMOVNL
            | ZYDIS_MNEMONIC_CMOVNLE
            | ZYDIS_MNEMONIC_CMOVNO
            | ZYDIS_MNEMONIC_CMOVNP
            | ZYDIS_MNEMONIC_CMOVNS
            | ZYDIS_MNEMONIC_CMOVNZ
            | ZYDIS_MNEMONIC_CMOVO
            | ZYDIS_MNEMONIC_CMOVP
            | ZYDIS_MNEMONIC_CMOVS
            | ZYDIS_MNEMONIC_CMOVZ => self.get_cmov_insn_flow(rva, insn),

            // TODO: syscall, sysexit, sysret, vmcall, vmmcall

            _ => Ok(vec![]),
        }
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
        let does_fallthrough = Workspace::<A>::does_insn_fallthrough(&insn);

        // 4. compute flow ref
        let flows = self.get_insn_flow(rva, &insn)?;

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
