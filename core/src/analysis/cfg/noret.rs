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

/// does the given function provably never return,
/// judging by the shape of its CFG alone?
///
/// this is conservative:
///
///   - any reachable block ending in RET means the function returns.
///   - any reachable block ending in an unresolved flow means we don't know, so
///     we assume the function returns. unresolved flows are indirect
///     unconditional jumps (possible tail call through the import table, or an
///     unrecovered switch table) and direct edges to addresses that are not
///     part of the CFG.
///
/// only when every reachable path ends in a dead end (an INT3, a call whose
/// fallthrough was already pruned as noret, an infinite loop, ...) do we
/// conclude the function never returns.
fn is_provably_noret(module: &Module, cfg: &CFG, decoder: &zydis::Decoder, va: VA) -> bool {
    if !cfg.basic_blocks.blocks_by_address.contains_key(&va) {
        // not a basic block, e.g. not analyzed as code.
        return false;
    }

    let mut reader: cfg::CachingPageReader = Default::default();

    for block in cfg.get_reaches_from(va) {
        let last = block.address_of_last_insn;
        let succs = &cfg.flows.flows_by_src[&last];

        if succs
            .iter()
            .any(|f| matches!(f, Flow::UnconditionalJump(Target::Indirect(_))))
        {
            // unresolved flow: a tail call through the import table or a
            // register, or an unrecovered switch table. we can't see where
            // this goes, so conservatively assume it returns.
            return false;
        }

        if cfg::edge_targets(cfg::direct_edges(cfg::edges(succs)))
            .any(|target| !cfg.basic_blocks.blocks_by_address.contains_key(&target))
        {
            // flow to an address that isn't part of the CFG,
            // so the analysis here is incomplete.
            // conservatively assume the function returns.
            return false;
        }

        if cfg::empty(cfg::edges(succs)) {
            // leaf block: no edges out of the final instruction.
            // only trust instructions we positively know to be dead ends;
            // everything else is unknown, so assume the function returns.
            match cfg::read_insn_with_cache(&mut reader, &module.address_space, last, decoder) {
                Ok(Some(insn)) => match insn.mnemonic {
                    // the function returns.
                    zydis::Mnemonic::RET | zydis::Mnemonic::IRET | zydis::Mnemonic::IRETD | zydis::Mnemonic::IRETQ => {
                        return false;
                    }

                    // dead ends:
                    // INT3/INT 0x29/INT 0x2C don't flow onwards
                    // (see does_insn_fallthrough), and a CALL with no
                    // remaining flows had its fallthrough pruned as noret.
                    zydis::Mnemonic::INT3 | zydis::Mnemonic::INT | zydis::Mnemonic::CALL => {}

                    // anything else is unknown. notably, this includes
                    // unresolved jumps that produce no flows at all, like
                    // an unrecovered switch `jmp [table + reg*4]` (e.g.
                    // the dispatch inside msvc's memcpy): we can't see
                    // where they go, so assume the function returns.
                    _ => {
                        return false;
                    }
                },
                _ => {
                    // can't decode the final instruction: unknown,
                    // so conservatively assume the function returns.
                    return false;
                }
            }
        }
    }

    // every reachable path is a dead end: this function never returns.
    true
}

/// find functions that provably never return, judging by CFG shape (see
/// [`is_provably_noret`]), and prune the fallthrough flows after calls to
/// them.
///
/// this catches no-return functions that aren't recognized by name (see
/// [`cfg_prune_noret_by_name`]), such as in stripped or statically-linked
/// binaries: infinite loops, INT3-terminated fatal handlers, and wrappers
/// around already-pruned no-return calls.
///
/// iterates to a fixpoint: pruning one function's callers can turn a caller
/// into a provably no-return function itself.
///
/// returns the set of addresses recognized as noret.
pub fn cfg_prune_noret_functions(module: &Module, cfg: &mut CFG, functions: &BTreeSet<VA>) -> Result<BTreeSet<VA>> {
    let decoder = dis::get_disassembler(module)?;
    let mut noret: BTreeSet<VA> = Default::default();

    loop {
        let mut changed = false;

        for &function in functions.iter() {
            if noret.contains(&function) {
                continue;
            }

            if is_provably_noret(module, cfg, &decoder, function) {
                log::info!("noret via cfg: {:#x}", function);
                noret.insert(function);
                noret.extend(cfg_mark_noret(module, cfg, function)?);
                changed = true;
            }
        }

        if !changed {
            break;
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
    fn noret_by_cfg_infinite_loop() -> Result<()> {
        // B (0xB) is an infinite loop, so it provably never returns,
        // even though it has no name. the pass must prune the bytes after
        // A's call to B, and then A itself becomes provably no-return
        // (its only path now ends at the pruned call): the fixpoint.
        //
        // A:
        // 0x0: E8 06 00 00 00    call 0xB
        // 0x5: 90                nop      (dead: must be pruned)
        // 0x6: C3                ret      (dead: must be pruned)
        // 0x7: CC CC CC CC       padding
        // B:
        // 0xB: EB FE             jmp $
        let module = load_shellcode32(b"\xE8\x06\x00\x00\x00\x90\xC3\xCC\xCC\xCC\xCC\xEB\xFE");
        let mut insns: InstructionIndex = Default::default();
        insns.build_index(&module, 0x0)?;
        let mut cfg = CFG::from_instructions(&module, insns)?;

        assert!(cfg.insns.insns_by_address.contains_key(&0x5));

        let functions: BTreeSet<VA> = [0x0, 0xB].into_iter().collect();
        let noret = cfg_prune_noret_functions(&module, &mut cfg, &functions)?;

        assert!(noret.contains(&0xB));
        assert!(noret.contains(&0x0));
        assert!(cfg.insns.insns_by_address.contains_key(&0x0));
        assert!(cfg.insns.insns_by_address.contains_key(&0x5).not());
        assert!(cfg.insns.insns_by_address.contains_key(&0x6).not());

        Ok(())
    }

    #[test]
    fn noret_by_cfg_returning_functions_untouched() -> Result<()> {
        // C calls D, and D plainly returns: nothing may be marked or pruned.
        //
        // C:
        // 0x0: E8 06 00 00 00    call 0xB
        // 0x5: 90                nop
        // 0x6: C3                ret
        // 0x7: CC CC CC CC       padding
        // D:
        // 0xB: C3                ret
        let module = load_shellcode32(b"\xE8\x06\x00\x00\x00\x90\xC3\xCC\xCC\xCC\xCC\xC3");
        let mut insns: InstructionIndex = Default::default();
        insns.build_index(&module, 0x0)?;
        let mut cfg = CFG::from_instructions(&module, insns)?;

        let functions: BTreeSet<VA> = [0x0, 0xB].into_iter().collect();
        let noret = cfg_prune_noret_functions(&module, &mut cfg, &functions)?;

        assert!(noret.is_empty());
        assert!(cfg.insns.insns_by_address.contains_key(&0x5));
        assert!(cfg.insns.insns_by_address.contains_key(&0x6));

        Ok(())
    }

    #[test]
    fn noret_by_cfg_indirect_jump_is_conservative() -> Result<()> {
        // E ends with an indirect jump (like a thunk to an import, or an
        // unrecovered switch table): we can't see where it goes, so it must
        // NOT be considered no-return, and F's post-call bytes must survive.
        //
        // F:
        // 0x0:  E8 0B 00 00 00     call 0x10
        // 0x5:  90                 nop      (must survive)
        // 0x6:  C3                 ret      (must survive)
        // 0x7:  CC x9              padding
        // E:
        // 0x10: FF 25 18 00 00 00  jmp [0x18]
        // 0x16: CC CC              padding
        // 0x18: 44 33 22 11        (pointer data)
        let module = load_shellcode32(
            b"\xE8\x0B\x00\x00\x00\x90\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xFF\x25\x18\x00\x00\x00\xCC\xCC\x44\x33\x22\x11",
        );
        let mut insns: InstructionIndex = Default::default();
        insns.build_index(&module, 0x0)?;
        let mut cfg = CFG::from_instructions(&module, insns)?;

        let functions: BTreeSet<VA> = [0x0, 0x10].into_iter().collect();
        let noret = cfg_prune_noret_functions(&module, &mut cfg, &functions)?;

        assert!(noret.is_empty());
        assert!(cfg.insns.insns_by_address.contains_key(&0x5));
        assert!(cfg.insns.insns_by_address.contains_key(&0x6));

        Ok(())
    }

    #[test]
    fn noret_by_cfg_switch_dispatch_is_conservative() -> Result<()> {
        // regression test: a scaled-index indirect jump (an unrecovered
        // switch table, like the dispatch inside msvc's memcpy) produces NO
        // flows at all, so its block looks like a dead-end leaf. it must not
        // be considered no-return: the function jumps somewhere we can't see,
        // and (in memcpy's case) very much returns.
        //
        // F:
        // 0x0:  E8 0B 00 00 00        call 0x10
        // 0x5:  90                    nop   (must survive)
        // 0x6:  C3                    ret   (must survive)
        // 0x7:  CC x9                 padding
        // S:
        // 0x10: FF 24 85 18 00 00 00  jmp [eax*4+0x18]
        // 0x17: CC                    padding
        // 0x18: 44 33 22 11           (table data)
        let module = load_shellcode32(
            b"\xE8\x0B\x00\x00\x00\x90\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xFF\x24\x85\x18\x00\x00\x00\xCC\x44\x33\x22\x11",
        );
        let mut insns: InstructionIndex = Default::default();
        insns.build_index(&module, 0x0)?;
        let mut cfg = CFG::from_instructions(&module, insns)?;

        // the switch dispatch produced no flows: it's a leaf ending in JMP.
        assert!(cfg.flows.flows_by_src[&0x10].is_empty());

        let functions: BTreeSet<VA> = [0x0, 0x10].into_iter().collect();
        let noret = cfg_prune_noret_functions(&module, &mut cfg, &functions)?;

        assert!(noret.is_empty());
        assert!(cfg.insns.insns_by_address.contains_key(&0x5));
        assert!(cfg.insns.insns_by_address.contains_key(&0x6));

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
