use std::collections::BTreeSet;

use anyhow::Result;

use crate::{
    analysis::{
        cfg::CFG,
        pe::{self, ImportedSymbol},
    },
    loader::pe::PE,
    VA,
};

pub fn cfg_prune_noret_imports(pe: &PE, cfg: &mut CFG) -> Result<BTreeSet<VA>> {
    let mut noret = pe::get_imports(&pe)?
        .values()
        .filter(|imp| match (&*imp.dll, &imp.symbol) {
            ("kernel32.dll", ImportedSymbol::Name(symbol)) if symbol == "ExitProcess" => true,
            ("kernel32.dll", ImportedSymbol::Ordinal(171)) => true,
            (_, _) => false,
        })
        .map(|imp| imp.address)
        .collect::<BTreeSet<_>>();

    for &noret_import in noret.clone().iter() {
        log::debug!("noret import {:#x}", noret_import);
        noret.extend(crate::analysis::cfg::noret::cfg_mark_noret(
            &pe.module,
            cfg,
            noret_import,
        )?);
    }

    Ok(noret)
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

        // _report_failure is part of __security_check_cookie (tail call),
        // which is not noret.
        //
        // ___crtExitProcess is noret:
        //
        //    .text:00401C4E ; =============== S U B R O U T I N E
        // =======================================    .text:00401C4E
        //    .text:00401C4E ; Attributes: library function noreturn
        //    .text:00401C4E
        //    .text:00401C4E ; void __cdecl __noreturn __crtExitProcess(UINT uExitCode)
        //    .text:00401C4E ___crtExitProcess proc near             ; CODE XREF:
        // start+EA↑p    .text:00401C4E
        // ; _doexit+BA↓p
        //
        // which has a call to it like:
        //
        //     .text:00401161                 call    __NMSG_WRITE
        //     .text:00401166                 push    0FFh            ; uExitCode
        //     .text:0040116B                 call    ___crtExitProcess
        //     .text:00401170 ;
        // ---------------------------------------------------------------------------
        //     .text:00401170                 db  59h ; Y
        //     .text:00401171                 db  59h ; Y

        assert!(cfg.insns.insns_by_address.contains_key(&0x40116B));
        assert!(cfg.insns.insns_by_address.contains_key(&0x401170).not());

        Ok(())
    }
}
