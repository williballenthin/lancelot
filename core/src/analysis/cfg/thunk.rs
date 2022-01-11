// a thunk is a function that immediately unconditionally jumps to another
// function. often seen with thunks to imports.

use std::collections::BTreeSet;

use crate::{
    analysis::cfg::{flow::Flow, CFG},
    VA,
};

pub fn find_thunks<'a, T>(cfg: &CFG, functions: T) -> BTreeSet<VA>
where
    T: Iterator<Item = &'a VA>,
{
    let mut thunks: BTreeSet<VA> = Default::default();

    for &function in functions {
        if let Some(succs) = cfg.flows.flows_by_src.get(&function) {
            if succs.len() != 1 {
                continue;
            }

            if let Flow::UnconditionalJump(_) = succs[0] {
                thunks.insert(function);
            }
        }
    }

    return thunks;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        analysis::cfg::{InstructionIndex, CFG},
        rsrc::*,
    };
    use anyhow::Result;

    #[test]
    fn nop() -> Result<()> {
        let buf = get_buf(Rsrc::NOP);
        let pe = crate::loader::pe::PE::from_bytes(&buf)?;

        let mut insns: InstructionIndex = Default::default();

        for &ep in crate::analysis::pe::entrypoints::find_pe_entrypoint(&pe)?.iter() {
            insns.build_index(&pe.module, ep)?;
        }

        for &exp in crate::analysis::pe::exports::find_pe_exports(&pe)?.iter() {
            insns.build_index(&pe.module, exp)?;
        }

        // int __cdecl _except_handler3(int, PVOID TargetFrame, int)
        // eventually flows to RtlUnwind
        insns.build_index(&pe.module, 0x4027F4)?;

        let cfg = CFG::from_instructions(&pe.module, insns)?;

        let thunks = find_thunks(&cfg, [0x405F42, 0x401000].iter());

        // ```
        //     .text:00405F42  ; void __stdcall RtlUnwind(PVOID TargetFrame, PVOID TargetIp, PEXCEPTION_RECORD ExceptionRecord, PVOID ReturnValue)
        //     .text:00405F42  RtlUnwind       proc near               ; CODE XREF: __global_unwind2+13↑p
        //     .text:00405F42
        //     .text:00405F42  TargetFrame     = dword ptr  4
        //     .text:00405F42  TargetIp        = dword ptr  8
        //     .text:00405F42  ExceptionRecord = dword ptr  0Ch
        //     .text:00405F42  ReturnValue     = dword ptr  10h
        //     .text:00405F42
        //     .text:00405F42 000 FF 25 7C 60 40 00  jmp     ds:__imp_RtlUnwind
        //     .text:00405F42  RtlUnwind       endp
        // ```
        assert!(thunks.contains(&0x405F42));

        Ok(())
    }
}
