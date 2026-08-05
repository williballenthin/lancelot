use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;

use crate::{
    analysis::{
        cfg,
        cfg::{flow::Flow, ChangeBatch, CFG},
        dis,
        dis::Target,
    },
    aspace::AddressSpace,
    module::Module,
    VA,
};

// TODO: add cfg_check_noret(module, cfg, va) that optionally marks as noret, if
// valid.

/// names of functions that are known to never return.
///
/// keep this list strictly to routines that terminate the process/thread or
/// unwind (throw), never "usually fatal" routines like TerminateProcess.
/// each entry here lets the CFG pass prune the dead bytes following a call,
/// so a wrong entry would remove valid code.
///
/// entries are bare function names; they're matched against both plain names
/// (COFF symbols, FLIRT matches) and the function part of import names like
/// `kernel32.dll!ExitProcess`. x86 decorated variants (leading underscore,
/// stdcall `@N` suffixes) are listed explicitly where they occur in practice.
pub const NORET_NAMES: &[&str] = &[
    // win32
    "ExitProcess",
    "ExitThread",
    "FatalExit",
    "FatalAppExitA",
    "FatalAppExitW",
    // ntdll
    "RtlExitUserThread",
    "RtlExitUserProcess",
    // C runtime: process termination
    "exit",
    "_exit",
    "__exit",
    "_Exit",
    "__Exit",
    "quick_exit",
    "_quick_exit",
    "abort",
    "_abort",
    "_amsg_exit",
    "__amsg_exit",
    // C runtime: fatal error handlers
    "_invalid_parameter_noinfo_noreturn",
    "__invalid_parameter_noinfo_noreturn",
    "_invoke_watson",
    "__invoke_watson",
    "__report_gsfailure",
    "___report_gsfailure",
    "__report_rangecheckfailure",
    "___report_rangecheckfailure",
    "__fastfail",
    "___fastfail",
    "_purecall",
    "__purecall",
    // C++ runtime: exception unwinding/termination
    "_CxxThrowException",
    "__CxxThrowException@8",
    "?terminate@@YAXXZ",
];

/// prune CFG flows following calls to functions that are known, by name,
/// to never return (see [`NORET_NAMES`]).
///
/// names are given as a map from name to address, such as
/// `WorkspaceAnalysis.names.addresses_by_name`: plain names for local
/// functions, and `dll!symbol` for imports.
///
/// returns the set of addresses recognized as noret, including callers that
/// are found to never return as a consequence (see [`cfg_mark_noret`]).
pub fn cfg_prune_noret_by_name(module: &Module, cfg: &mut CFG, names: &BTreeMap<String, VA>) -> Result<BTreeSet<VA>> {
    let mut noret: BTreeSet<VA> = Default::default();

    for (name, &va) in names.iter() {
        // for import names like `kernel32.dll!ExitProcess`,
        // match against the function name part.
        let function_name = name.rsplit('!').next().unwrap_or(name);

        if NORET_NAMES.contains(&function_name) {
            log::info!("noret via name: {}: {:#x}", name, va);
            noret.extend(cfg_mark_noret(module, cfg, va)?);
        }
    }

    Ok(noret)
}

// With the given function address,
// either as the target of a direct or indirect call,
// consider it to be non-returning (such as ExitProcess).
//
// Recursively consider its callers,
// possibly pruning instructions after the calls,
// and possibly considering those functions as noret, too.
//
// Returns the set of functions newly recognized as noret.
pub fn cfg_mark_noret(module: &Module, cfg: &mut CFG, va: VA) -> Result<BTreeSet<VA>> {
    let mut seen: BTreeSet<VA> = Default::default();
    cfg_mark_noret_inner(module, cfg, va, &mut seen)
}

fn cfg_mark_noret_inner(module: &Module, cfg: &mut CFG, va: VA, seen: &mut BTreeSet<VA>) -> Result<BTreeSet<VA>> {
    log::debug!("mark noret: {:#x}", va);
    let mut ret: BTreeSet<VA> = Default::default();
    let mut batch: ChangeBatch = Default::default();

    if !seen.insert(va) {
        // already visited during this walk.
        // this breaks infinite recursion when a noret function flows to
        // itself (e.g. terminates with `jmp $`) or when noret functions
        // flow into each other in a cycle.
        return Ok(ret);
    }

    // the given address is the target to either direct or indirect calls (import).
    // for each of these, remove any fallthrough flows from that call instruction.
    // then, rebuild the CFG.
    let mut callers: Vec<VA> = Default::default();
    let flows_to = cfg
        .flows
        .flows_by_dst
        .get(&va)
        .unwrap_or(&Default::default())
        .clone()
        .into_iter();
    for flow in flows_to {
        let src = match flow {
            Flow::Call(Target::Direct(src)) => src,
            Flow::Call(Target::Indirect(src)) => src,
            // tail call
            Flow::UnconditionalJump(Target::Direct(src)) => src,
            // thunk to import, like:
            //
            //```
            // ; void __stdcall __noreturn CxxThrowException(void *pExceptionObject, _ThrowInfo *pThrowInfo)
            // jmp ds:__imp__CxxThrowException
            //```
            Flow::UnconditionalJump(Target::Indirect(src)) => src,
            _ => continue,
        };
        log::debug!("mark noret: {:#x}: caller: {:#x}", va, src);

        callers.push(src);
    }

    for &src in &callers {
        batch.prune_noret_call(src);
    }
    cfg.commit(batch);

    let decoder = dis::get_disassembler(module).expect("invalid disassembler");

    // for each of the call instructions that flow to the given va,
    // search backwards for function starts.
    // these are basic blocks to which call instructions flow.
    //
    // then, search forwards to find "leaf" basic blocks.
    // these are basic blocks with no edge successors.
    // check to see if any of these blocks ends in a ret instruction.
    //
    // if none do, then this is a noret function, too.
    //
    // recurse.
    for call_insn in callers.into_iter() {
        // This caller may have been cascade-removed during the batch commit
        // above: when caller A's fallthrough is pruned, `prune_flow` removes
        // any instruction whose incoming flows all disappear — which may
        // include another caller B on the same fallthrough chain or reachable
        // only through flows from the removed region.
        if !cfg.insns.insns_by_address.contains_key(&call_insn) {
            continue;
        }

        // the basic block that ends with a call to noret function at given va.
        let leaf_block = cfg.basic_blocks.blocks_by_last_address[&call_insn];

        for head in cfg.get_reaches_to(leaf_block) {
            // if the head appears to be the start of a function,
            // by looking at if there are any call flows here.
            // TODO: augment with function database?
            //
            // this is a function that flows to the block ending with a noret call.
            if cfg.flows.flows_by_dst[&head.address]
                .iter()
                .any(|flow| matches!(flow, Flow::Call(_)))
            {
                // are there any other exit points from this function?
                let is_ret = cfg
                    .get_reaches_from(head.address)
                    .filter(|block| cfg::empty(cfg::edges(&cfg.flows.flows_by_src[&block.address_of_last_insn])))
                    .any(|block| {
                        let mut insn_buf = [0u8; 16];
                        module
                            .address_space
                            .read_into(block.address_of_last_insn, &mut insn_buf)
                            .unwrap();
                        let insn = dis::decode(&decoder, &insn_buf)
                            .expect("invalid instruction")
                            .expect("missing instruction");
                        matches!(insn.mnemonic, zydis::Mnemonic::RET)
                    });

                if !is_ret {
                    log::debug!("noret function: {:#x}", head.address);
                    ret.insert(head.address);
                }
            }
        }
    }

    for &caller in ret.clone().iter() {
        ret.extend(cfg_mark_noret_inner(module, cfg, caller, seen)?);
    }
    ret.insert(va);

    Ok(ret)
}

#[cfg(test)]
mod tests {
    use std::ops::Not;

    use super::*;
    use crate::{analysis::cfg::InstructionIndex, test::*};

    #[test]
    fn noret_by_local_name() -> Result<()> {
        // a call to a function named `abort` never returns,
        // so the bytes following the call must be pruned.
        //
        // 0x0: E8 06 00 00 00    call 0xB (abort)
        // 0x5: 90                nop      (dead: must be pruned)
        // 0x6: C3                ret      (dead: must be pruned)
        // 0x7: CC CC CC CC       padding
        // 0xB: EB FE             jmp $    (abort's body, irrelevant)
        let module = load_shellcode32(b"\xE8\x06\x00\x00\x00\x90\xC3\xCC\xCC\xCC\xCC\xEB\xFE");
        let mut insns: InstructionIndex = Default::default();
        insns.build_index(&module, 0x0)?;
        let mut cfg = CFG::from_instructions(&module, insns)?;

        assert!(cfg.insns.insns_by_address.contains_key(&0x5));

        let mut names: BTreeMap<String, VA> = Default::default();
        names.insert("abort".to_string(), 0xB);

        let noret = cfg_prune_noret_by_name(&module, &mut cfg, &names)?;

        assert!(noret.contains(&0xB));
        assert!(cfg.insns.insns_by_address.contains_key(&0x0));
        assert!(cfg.insns.insns_by_address.contains_key(&0x5).not());
        assert!(cfg.insns.insns_by_address.contains_key(&0x6).not());

        Ok(())
    }

    #[test]
    fn noret_by_import_name() -> Result<()> {
        // same, via an indirect call through a pointer named like an import.
        //
        // 0x0:  FF 15 10 00 00 00   call [0x10] (ExitProcess)
        // 0x6:  90                  nop         (dead: must be pruned)
        // 0x7:  C3                  ret         (dead: must be pruned)
        // 0x8:  CC x8               padding
        // 0x10: 44 33 22 11         (pointer data)
        let module =
            load_shellcode32(b"\xFF\x15\x10\x00\x00\x00\x90\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x44\x33\x22\x11");
        let mut insns: InstructionIndex = Default::default();
        insns.build_index(&module, 0x0)?;
        let mut cfg = CFG::from_instructions(&module, insns)?;

        assert!(cfg.insns.insns_by_address.contains_key(&0x6));

        let mut names: BTreeMap<String, VA> = Default::default();
        names.insert("kernel32.dll!ExitProcess".to_string(), 0x10);

        let noret = cfg_prune_noret_by_name(&module, &mut cfg, &names)?;

        assert!(noret.contains(&0x10));
        assert!(cfg.insns.insns_by_address.contains_key(&0x0));
        assert!(cfg.insns.insns_by_address.contains_key(&0x6).not());
        assert!(cfg.insns.insns_by_address.contains_key(&0x7).not());

        Ok(())
    }

    #[test]
    fn returning_names_untouched() -> Result<()> {
        // a call to a function not on the noret list must keep its fallthrough.
        let module = load_shellcode32(b"\xE8\x06\x00\x00\x00\x90\xC3\xCC\xCC\xCC\xCC\xEB\xFE");
        let mut insns: InstructionIndex = Default::default();
        insns.build_index(&module, 0x0)?;
        let mut cfg = CFG::from_instructions(&module, insns)?;

        let mut names: BTreeMap<String, VA> = Default::default();
        names.insert("memcpy".to_string(), 0xB);

        let noret = cfg_prune_noret_by_name(&module, &mut cfg, &names)?;

        assert!(noret.is_empty());
        assert!(cfg.insns.insns_by_address.contains_key(&0x5));
        assert!(cfg.insns.insns_by_address.contains_key(&0x6));

        Ok(())
    }
}
