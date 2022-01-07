use std::collections::BTreeSet;

use anyhow::Result;

use crate::{
    analysis::{
        cfg::{flow::Flow, ChangeBatch, CFG},
        dis::Target,
        pe::{self, ImportedSymbol},
    },
    loader::pe::PE,
};

pub fn cfg_prune_noret_imports(pe: &PE, cfg: &mut CFG) -> Result<()> {
    let noret = pe::get_imports(&pe)?
        .values()
        .filter(|imp| match (&*imp.dll, &imp.symbol) {
            ("kernel32.dll", ImportedSymbol::Name(symbol)) if symbol == "ExitProcess" => true,
            ("kernel32.dll", ImportedSymbol::Ordinal(171)) => true,
            (_, _) => false,
        })
        .map(|imp| imp.address)
        .collect::<BTreeSet<_>>();

    let mut batch: ChangeBatch = Default::default();
    for impva in noret.iter() {
        for flow in cfg
            .flows
            .flows_by_dst
            .get(impva)
            .unwrap_or(&Default::default())
            .clone()
            .iter()
        {
            let insn = match flow {
                // references to the import table should all be indirect,
                // like: call [CreateProcess]
                // and never like: call CreateProcess

                // indirect: what we want.
                Flow::Call(Target::Indirect(ptr)) => ptr,
                Flow::UnconditionalJump(Target::Indirect(ptr)) => ptr,

                // direct: shouldn't see this.
                _ => continue,
            };

            log::info!("call from {:#x} to noret import {:#x}", insn, impva);
            batch.prune_noret_call(*insn);
        }
    }
    cfg.commit(batch);

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::ops::Not;

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

        let mut cfg = CFG::from_instructions(&pe.module, insns)?;

        cfg_prune_noret_imports(&pe, &mut cfg)?;

        // there are two calls to ExitProcess:
        //
        //     .text:00401C73                 push    [esp+uExitCode] ; uExitCode
        //     .text:00401C77                 call    ds:ExitProcess
        //     .text:00401C77 ___crtExitProcess endp
        //     .text:00401C77
        //     .text:00401C77 ;
        // ---------------------------------------------------------------------------
        //     .text:00401C7D                 align 2

        assert!(cfg.insns.insns_by_address.contains_key(&0x401C77));
        assert!(cfg.insns.insns_by_address.contains_key(&0x401C7D).not());

        // and:
        //
        //     .text:00402D69                 push    3               ; uExitCode
        //     .text:00402D6B                 call    ds:ExitProcess
        //     .text:00402D6B ; } // starts at 402D41
        //     .text:00402D6B _report_failure endp
        //     .text:00402D6B
        //     .text:00402D6B ;
        // ---------------------------------------------------------------------------
        //     .text:00402D71                 align 2

        assert!(cfg.insns.insns_by_address.contains_key(&0x402D6B));
        assert!(cfg.insns.insns_by_address.contains_key(&0x402D71).not());

        Ok(())
    }
}
