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
    let mut noret = pe::get_imports(pe)?
        .values()
        .filter(|imp| match (&*imp.dll, &imp.symbol) {
            ("kernel32.dll", ImportedSymbol::Name(symbol)) if symbol == "ExitProcess" => true,
            ("kernel32.dll", ImportedSymbol::Ordinal(171)) => true,
            ("msvcrt.dll", ImportedSymbol::Name(symbol)) if symbol == "_CxxThrowException" => true,
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
    use crate::{analysis::cfg::InstructionIndex, rsrc::*};

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
        let norets = cfg_prune_noret_imports(&pe, &mut cfg)?;

        const EXIT_PROCESS: VA = 0x40600C;
        assert!(norets.contains(&EXIT_PROCESS));

        // there are two calls to ExitProcess().
        //
        // *************************
        // First call to ExitProcess
        // *************************
        //
        //     .text:00401C73                 push    [esp+uExitCode] ; uExitCode
        //     .text:00401C77                 call    ds:ExitProcess
        //     .text:00401C7D  CC             align 2
        //
        assert!(cfg.insns.insns_by_address.contains_key(&0x401C77));
        assert!(cfg.insns.insns_by_address.contains_key(&0x401C7D).not());
        //
        // this is the end of ___crtExitProcess().
        // and IDA detects this function as:
        //
        //    .text:00401C4E ; Attributes: library function noreturn
        //    .text:00401C4E ; void __cdecl __noreturn __crtExitProcess(UINT uExitCode)
        //
        // this is a noret function because it terminates with a call to ExitProcess.
        assert!(norets.contains(&0x401C4E));
        // ___crtExitProcess() has a call to it like:
        //
        //     .text:00401161                 call    __NMSG_WRITE
        //     .text:00401166                 push    0FFh            ; uExitCode
        //     .text:0040116B                 call    ___crtExitProcess
        //     .text:00401170                 db  59h ; Y
        //     .text:00401171                 db  59h ; Y
        //
        // this is part of start():
        //
        //     .text:00401081                             ; int start()
        //     .text:00401081                             public start
        //     .text:00401081                             start proc near
        //
        // note start() is *not* noret
        assert!(norets.contains(&0x401081).not());
        //
        // however, this leaf BB is terminated by the noret call.
        assert!(cfg.insns.insns_by_address.contains_key(&0x40116B));
        assert!(cfg.insns.insns_by_address.contains_key(&0x401170).not());

        // **************************
        // Second call to ExitProcess
        // **************************
        //
        //     .text:00402D69                 push    3               ; uExitCode
        //     .text:00402D6B                 call    ds:ExitProcess
        //     .text:00402D71  CC             align 2
        //
        // this is part of _report_failure (0x402D41)
        // which is part of __security_check_cookie (0x402D72) that tailcalls to
        // _report_failure. IDA detects it as such:
        //
        //     .text:00402D72  ; Attributes: library function
        //     .text:00402D72  ; void __fastcall __security_check_cookie(uintptr_t)
        //
        // while _report_failure is noret, __security_check_cookie is *not* noret.
        assert!(norets.contains(&0x402D72).not());
        //
        // however, this leaf BB is terminated by the noret call.
        assert!(cfg.insns.insns_by_address.contains_key(&0x402D6B));
        assert!(cfg.insns.insns_by_address.contains_key(&0x402D71).not());

        Ok(())
    }
}
