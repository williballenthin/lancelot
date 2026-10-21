use std::collections::{BTreeMap, BTreeSet, VecDeque};

use anyhow::Result;

use crate::{
    analysis::{
        cfg,
        cfg::{flow::Flow, ChangeBatch, CFG},
        dis,
        dis::{zydis, Target},
    },
    module::Module,
    VA,
};

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
/// an entry may also be a full import name, for imports by ordinal.
pub const NORET_NAMES: &[&str] = &[
    // win32
    "ExitProcess",
    "kernel32.dll!#171", // ExitProcess by ordinal
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
/// names are given as a map from address to name, such as
/// `WorkspaceAnalysis.names.names_by_address`: plain names for local
/// functions, and `dll!symbol` for imports. the map is keyed by address
/// because two import slots can have the same name.
///
/// `noret` is the set of addresses known to never return. it's extended with
/// the functions recognized here, including callers that are found to never
/// return as a consequence (see [`cfg_mark_noret`]).
pub fn cfg_prune_noret_by_name(
    module: &Module,
    cfg: &mut CFG,
    names: &BTreeMap<VA, String>,
    noret: &mut BTreeSet<VA>,
) -> Result<()> {
    let mut found: Vec<VA> = Default::default();

    for (&va, name) in names.iter() {
        // for import names like `kernel32.dll!ExitProcess`,
        // match against the function name part, too.
        let function_name = name.rsplit('!').next().unwrap_or(name);

        if NORET_NAMES.contains(&name.as_str()) || NORET_NAMES.contains(&function_name) {
            log::info!("noret via name: {}: {:#x}", name, va);
            found.push(va);
        }
    }

    cfg_mark_noret(module, cfg, found, noret)
}

/// the analysis of the function at `va` is incomplete at instruction `at`,
/// for the given reason, so we can't tell whether it returns.
fn unknown(va: VA, at: VA, reason: &str) -> bool {
    log::trace!("noret: {:#x}: unknown at {:#x}: {}", va, at, reason);
    false
}

/// the path through the function at `va` ends at instruction `at`.
fn dead_end(va: VA, at: VA, what: &str) {
    log::trace!("noret: {:#x}: dead end at {:#x}: {}", va, at, what);
}

/// does the function at the given address provably never return,
/// judging from its CFG alone?
///
/// walks every block reachable from the function start along direct edges
/// (fallthroughs and jumps, not calls) and classifies how each path ends:
///
///   - a RET: the function returns.
///   - a known dead end: a call or tail jump to a function in `noret` (so its
///     fallthrough was already pruned), `int 0x29`/`int 0x2c`, or an `int3`
///     directly after a call, which is what MSVC and clang emit after a call to
///     a function declared `noreturn`.
///   - something we can't see through: an indirect jump (a tail call through
///     the import table or a register, or an unrecovered switch table), a jump
///     whose target was dropped while building the CFG, a flow to bytes that
///     didn't decode, or an `int3` reached some other way than from a call.
///
/// only when every path ends in a known dead end, or never ends at all (an
/// infinite loop), is the function noret. an incomplete analysis never is,
/// which matters because marking a function noret prunes the code after
/// every call to it.
///
/// `noret` is the set of addresses already known to never return: function
/// addresses, thunks, and the import pointers that indirect calls and jumps go
/// through. a direct jump to an address in `noret` is a dead end. a
/// fallthrough or a conditional jump to such an address is not: the address
/// can be an import pointer, which is data, and bytes decoded as code can
/// flow into it.
///
/// this rule has two known limits. it marks as noret a function that gives
/// control back to its caller without a RET, such as Go's `runtime.morestack`
/// through a stack switch. it takes an `int3` after a call to a function that
/// does return, with an exception handler that continues past it, as a dead
/// end.
pub fn is_provably_noret(module: &Module, cfg: &CFG, decoder: &zydis::Decoder, va: VA, noret: &BTreeSet<VA>) -> bool {
    if !cfg.basic_blocks.blocks_by_address.contains_key(&va) {
        return unknown(va, va, "not a basic block");
    }

    let mut reader: cfg::CachingPageReader = Default::default();
    let mut seen: BTreeSet<VA> = Default::default();
    let mut queue: VecDeque<VA> = vec![va].into();

    while let Some(bbva) = queue.pop_front() {
        if !seen.insert(bbva) {
            continue;
        }

        let bb = &cfg.basic_blocks.blocks_by_address[&bbva];
        let last = bb.address_of_last_insn;

        // decode the block up to its final instruction, which tells how the
        // path ends. the earlier ones matter only to spot a conditional jump
        // whose target was dropped while building the CFG: it has only its
        // fallthrough, so it doesn't end the block, yet part of the function
        // is missing behind it.
        let mut insn_va = bb.address;
        let mut after_call = false;
        let insn = loop {
            let insn = match cfg::read_insn_with_cache(&mut reader, &module.address_space, insn_va, decoder) {
                Ok(Some(insn)) => insn,
                _ => return unknown(va, insn_va, "undecodable instruction"),
            };

            if insn_va == last {
                break insn;
            }

            if insn.meta.category == zydis::InstructionCategory::COND_BR
                && cfg::empty(cfg::non_fallthrough_edges(&cfg.flows.flows_by_src[&insn_va]))
            {
                return unknown(va, insn_va, "conditional jump with dropped target");
            }

            // an int3 that starts its block is reached by a jump, by more
            // than one instruction, or by nothing. so it is not the marker.
            after_call = insn.meta.category == zydis::InstructionCategory::CALL;
            insn_va += insn.length as VA;
        };

        // where the final instruction flows directly: fallthrough and jump
        // targets, in the CFG. a flow dropped while building the CFG, because
        // its target isn't code or isn't in the image, is missing here.
        let succs = &cfg.flows.flows_by_src[&last];
        let targets: Vec<VA> = cfg::edge_targets(cfg::direct_edges(cfg::edges(succs))).collect();
        let indirect = succs.iter().find_map(|f| match f {
            Flow::UnconditionalJump(Target::Indirect(ptr)) | Flow::Call(Target::Indirect(ptr)) => Some(*ptr),
            Flow::Call(Target::Direct(callee)) => Some(*callee),
            _ => None,
        });

        use zydis::InstructionCategory::*;
        match insn.meta.category {
            RET => return false,
            // only `int 0x29`, `int 0x2c` and `int3` don't fall through (see
            // does_insn_fallthrough). the first two are fatal; an `int3` is a
            // dead end only directly after a call, otherwise it may be a
            // debug break that execution continues past, or padding we
            // flowed into by mistake.
            INTERRUPT if targets.is_empty() => {
                if insn.mnemonic == zydis::Mnemonic::INT3 && !after_call {
                    return unknown(va, last, "int3 not after a call");
                }
                dead_end(va, last, "interrupt");
                continue;
            }
            // a tail jump to a noret function, or a thunk to a noret import.
            UNCOND_BR
                if indirect.is_some_and(|ptr| noret.contains(&ptr))
                    || targets.first().is_some_and(|target| noret.contains(target)) =>
            {
                dead_end(va, last, "jump to noret");
                continue;
            }
            // a tail call through the import table or a register, a switch
            // table dispatch like `jmp [table + reg*4]` that we didn't recover
            // (the one inside msvc's memcpy, for example), or a target that
            // was dropped: we can't see where this goes.
            UNCOND_BR if indirect.is_some() || targets.len() != 1 => {
                return unknown(va, last, "indirect jump or dropped target");
            }
            COND_BR if targets.len() != 2 => return unknown(va, last, "conditional jump with dropped target"),
            // the fallthrough was pruned, which only happens after a call to a
            // function known to never return.
            CALL if targets.is_empty() && indirect.is_some_and(|callee| noret.contains(&callee)) => {
                dead_end(va, last, "call to noret");
                continue;
            }
            _ if targets.is_empty() => return unknown(va, last, "no fallthrough"),
            _ => {}
        }

        for target in targets {
            if !cfg.basic_blocks.blocks_by_address.contains_key(&target) {
                return unknown(va, target, "flow to bytes that didn't decode");
            }
            queue.push_back(target);
        }
    }

    // every path ends in a dead end, or loops forever.
    true
}

/// find functions that provably never return, judging from the CFG alone (see
/// [`is_provably_noret`]), and prune the fallthrough flows after calls to them.
///
/// this catches no-return functions that aren't recognized by name (see
/// [`cfg_prune_noret_by_name`]), such as in stripped or statically linked
/// binaries: infinite loops, `__fastfail` handlers, and wrappers around calls
/// that are already known to never return.
///
/// iterates to a fixpoint: pruning after the calls to one function can make a
/// caller provably no-return in turn.
///
/// `noret` is the set of addresses known to never return, extended with the
/// functions recognized here.
pub fn cfg_prune_noret_functions(
    module: &Module,
    cfg: &mut CFG,
    functions: &BTreeSet<VA>,
    noret: &mut BTreeSet<VA>,
) -> Result<()> {
    let decoder = dis::get_disassembler(module)?;

    loop {
        let found: Vec<VA> = functions
            .iter()
            .cloned()
            .filter(|&function| !noret.contains(&function) && is_provably_noret(module, cfg, &decoder, function, noret))
            .collect();

        if found.is_empty() {
            return Ok(());
        }

        for function in found.iter() {
            log::info!("noret via cfg: {:#x}", function);
        }

        cfg_mark_noret(module, cfg, found, noret)?;
    }
}

/// consider the given functions, as the targets of direct or indirect calls
/// and jumps, to never return (such as ExitProcess).
///
/// prune the instructions following the calls to them, and then consider
/// their callers: a caller whose every path now ends in a dead end (see
/// [`is_provably_noret`]) is noret too, and so on. this works in generations:
/// the calls to a whole generation are pruned together and the CFG rebuilt
/// once, then the callers found noret make up the next generation.
///
/// `noret` is the set of addresses known to never return, extended with the
/// given functions and the callers recognized here.
pub fn cfg_mark_noret(
    module: &Module,
    cfg: &mut CFG,
    functions: impl IntoIterator<Item = VA>,
    noret: &mut BTreeSet<VA>,
) -> Result<()> {
    let decoder = dis::get_disassembler(module)?;
    let mut generation: Vec<VA> = functions.into_iter().collect();

    while !generation.is_empty() {
        let mut batch: ChangeBatch = Default::default();
        let mut callers: Vec<VA> = Default::default();

        for va in generation.drain(..) {
            log::debug!("mark noret: {:#x}", va);

            if !noret.insert(va) {
                // already known to never return, so the calls to it were
                // already pruned. this also breaks the cycle when noret
                // functions flow to each other, or a noret function flows
                // to itself (e.g. terminates with `jmp $`).
                continue;
            }

            // remove the fallthrough flow from each call to it,
            // and remember the call for the search for callers below.
            // a tail jump counts as a call, including a thunk to an import:
            //
            //```
            // ; void __stdcall __noreturn CxxThrowException(...)
            // jmp ds:__imp__CxxThrowException
            //```
            for flow in cfg.flows.flows_by_dst.get(&va).cloned().unwrap_or_default() {
                let src = match flow {
                    Flow::Call(Target::Direct(src))
                    | Flow::Call(Target::Indirect(src))
                    | Flow::UnconditionalJump(Target::Direct(src))
                    | Flow::UnconditionalJump(Target::Indirect(src)) => src,
                    _ => continue,
                };
                log::debug!("mark noret: {:#x}: caller: {:#x}", va, src);

                batch.prune_noret_call(src);
                callers.push(src);
            }
        }

        if callers.is_empty() {
            break;
        }

        cfg.commit(batch);

        // for each of the calls, search backwards for function starts:
        // basic blocks to which call instructions flow.
        // if every path through such a function now ends in a dead end,
        // then it's a noret function, too.
        let mut seen: BTreeSet<VA> = Default::default();
        for call_insn in callers {
            // the commit above may have removed the call itself, when it was
            // only reachable through another pruned fallthrough.
            let Some(&leaf_block) = cfg.basic_blocks.blocks_by_last_address.get(&call_insn) else {
                continue;
            };

            for head in cfg.get_reaches_to(leaf_block) {
                // TODO: augment with function database?
                let is_function = cfg.flows.flows_by_dst[&head.address]
                    .iter()
                    .any(|flow| matches!(flow, Flow::Call(_)));

                if is_function
                    && !noret.contains(&head.address)
                    && seen.insert(head.address)
                    && is_provably_noret(module, cfg, &decoder, head.address, noret)
                {
                    log::debug!("noret function: {:#x}", head.address);
                    generation.push(head.address);
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::ops::Not;

    use super::*;
    use crate::{
        analysis::{cfg::InstructionIndex, pe::ImportedSymbol},
        rsrc::*,
        test::*,
    };

    fn build_cfg(module: &Module) -> Result<CFG> {
        let mut insns: InstructionIndex = Default::default();
        insns.build_index(module, 0x0)?;
        CFG::from_instructions(module, insns)
    }

    fn prune_by_name(module: &Module, cfg: &mut CFG, names: &[(VA, &str)]) -> Result<BTreeSet<VA>> {
        let names = names.iter().map(|&(va, name)| (va, name.to_string())).collect();
        let mut noret = BTreeSet::new();
        cfg_prune_noret_by_name(module, cfg, &names, &mut noret)?;
        Ok(noret)
    }

    fn prune_functions(module: &Module, cfg: &mut CFG, functions: &[VA]) -> Result<BTreeSet<VA>> {
        let functions = functions.iter().cloned().collect();
        let mut noret = BTreeSet::new();
        cfg_prune_noret_functions(module, cfg, &functions, &mut noret)?;
        Ok(noret)
    }

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
        let mut cfg = build_cfg(&module)?;

        assert!(cfg.insns.insns_by_address.contains_key(&0x5));

        let noret = prune_by_name(&module, &mut cfg, &[(0xB, "abort")])?;

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
        let mut cfg = build_cfg(&module)?;

        assert!(cfg.insns.insns_by_address.contains_key(&0x6));

        let noret = prune_by_name(&module, &mut cfg, &[(0x10, "kernel32.dll!ExitProcess")])?;

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
        let mut cfg = build_cfg(&module)?;

        let noret = prune_by_name(&module, &mut cfg, &[(0xB, "memcpy")])?;

        assert!(noret.is_empty());
        assert!(cfg.insns.insns_by_address.contains_key(&0x5));
        assert!(cfg.insns.insns_by_address.contains_key(&0x6));

        Ok(())
    }

    #[test]
    fn noret_propagates_to_caller() -> Result<()> {
        // A's only path ends in a call to `abort`, so once the call's
        // fallthrough is pruned, A itself never returns.
        //
        // A:
        // 0x0: E8 07 00 00 00    call 0xC (abort)
        // 0x5: 90                nop      (dead: must be pruned)
        // 0x6: C3                ret      (dead: must be pruned)
        // B: (something has to call A for it to be considered a function)
        // 0x7: E8 F4 FF FF FF    call 0x0 (A)
        // abort:
        // 0xC: EB FE             jmp $
        let module = load_shellcode32(b"\xE8\x07\x00\x00\x00\x90\xC3\xE8\xF4\xFF\xFF\xFF\xEB\xFE");
        let mut insns: InstructionIndex = Default::default();
        insns.build_index(&module, 0x7)?;
        let mut cfg = CFG::from_instructions(&module, insns)?;

        let noret = prune_by_name(&module, &mut cfg, &[(0xC, "abort")])?;

        assert!(noret.contains(&0xC));
        assert!(noret.contains(&0x0));
        assert!(cfg.insns.insns_by_address.contains_key(&0x5).not());

        Ok(())
    }

    #[test]
    fn noret_propagation_stops_at_bare_int3() -> Result<()> {
        // A calls `abort` on one path and jumps to an `int3` on the other.
        // an int3 that isn't right after a call might be a debug break that
        // execution continues past, so A must NOT be noret.
        //
        // A:
        // 0x0:  85 C0              test eax, eax
        // 0x2:  74 0A              jz 0xE
        // 0x4:  E8 0F 00 00 00     call 0x18 (abort)
        // 0x9:  CC CC CC CC CC     padding
        // 0xE:  CC                 int3 (jump target)
        // 0xF:  CC                 padding
        // B:
        // 0x10: E8 EB FF FF FF     call 0x0 (A)
        // 0x15: 90                 nop      (must survive)
        // 0x16: C3                 ret      (must survive)
        // 0x17: CC                 padding
        // abort:
        // 0x18: EB FE              jmp $
        let module = load_shellcode32(
            b"\x85\xC0\x74\x0A\xE8\x0F\x00\x00\x00\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xE8\xEB\xFF\xFF\xFF\x90\xC3\xCC\xEB\xFE",
        );
        let mut insns: InstructionIndex = Default::default();
        insns.build_index(&module, 0x10)?;
        let mut cfg = CFG::from_instructions(&module, insns)?;

        let noret = prune_by_name(&module, &mut cfg, &[(0x18, "abort")])?;

        assert!(noret.contains(&0x18));
        assert!(noret.contains(&0x0).not());
        assert!(cfg.insns.insns_by_address.contains_key(&0x15));
        assert!(cfg.insns.insns_by_address.contains_key(&0x16));

        Ok(())
    }

    #[test]
    fn noret_thunk() -> Result<()> {
        // a thunk that tail jumps through a noret import pointer is noret too,
        // so a call to the thunk loses its fallthrough.
        //
        // 0x0:  E8 03 00 00 00     call 0x8 (thunk)
        // 0x5:  90                 nop         (dead: must be pruned)
        // 0x6:  C3                 ret         (dead: must be pruned)
        // 0x7:  CC                 padding
        // 0x8:  FF 25 10 00 00 00  jmp [0x10]  (thunk to ExitProcess)
        // 0xE:  CC CC              padding
        // 0x10: 44 33 22 11        (pointer data)
        let module =
            load_shellcode32(b"\xE8\x03\x00\x00\x00\x90\xC3\xCC\xFF\x25\x10\x00\x00\x00\xCC\xCC\x44\x33\x22\x11");
        let mut cfg = build_cfg(&module)?;

        let noret = prune_by_name(&module, &mut cfg, &[(0x10, "kernel32.dll!ExitProcess")])?;

        assert!(noret.contains(&0x10));
        assert!(noret.contains(&0x8));
        assert!(cfg.insns.insns_by_address.contains_key(&0x5).not());
        assert!(cfg.insns.insns_by_address.contains_key(&0x6).not());

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
        let mut cfg = build_cfg(&module)?;

        assert!(cfg.insns.insns_by_address.contains_key(&0x5));

        let noret = prune_functions(&module, &mut cfg, &[0x0, 0xB])?;

        assert!(noret.contains(&0xB));
        assert!(noret.contains(&0x0));
        assert!(cfg.insns.insns_by_address.contains_key(&0x0));
        assert!(cfg.insns.insns_by_address.contains_key(&0x5).not());
        assert!(cfg.insns.insns_by_address.contains_key(&0x6).not());

        Ok(())
    }

    #[test]
    fn noret_by_cfg_fastfail() -> Result<()> {
        // B ends in `int 0x29` (__fastfail), which never returns.
        //
        // A:
        // 0x0: E8 06 00 00 00    call 0xB
        // 0x5: 90                nop      (dead: must be pruned)
        // 0x6: C3                ret      (dead: must be pruned)
        // 0x7: CC CC CC CC       padding
        // B:
        // 0xB: B9 07 00 00 00    mov ecx, 7
        // 0x10: CD 29            int 0x29
        let module = load_shellcode32(b"\xE8\x06\x00\x00\x00\x90\xC3\xCC\xCC\xCC\xCC\xB9\x07\x00\x00\x00\xCD\x29");
        let mut cfg = build_cfg(&module)?;

        let noret = prune_functions(&module, &mut cfg, &[0x0, 0xB])?;

        assert!(noret.contains(&0xB));
        assert!(noret.contains(&0x0));
        assert!(cfg.insns.insns_by_address.contains_key(&0x5).not());

        Ok(())
    }

    #[test]
    fn noret_by_cfg_int3_after_call() -> Result<()> {
        // H calls a function we know nothing about (it even returns), but an
        // int3 directly after the call is the compiler's marker for a call
        // that doesn't return, so H is noret, and then so is A.
        //
        // A:
        // 0x0:  E8 06 00 00 00    call 0xB (H)
        // 0x5:  90                nop      (dead: must be pruned)
        // 0x6:  C3                ret      (dead: must be pruned)
        // 0x7:  CC CC CC CC       padding
        // H:
        // 0xB:  E8 06 00 00 00    call 0x16
        // 0x10: CC                int3
        // 0x11: CC CC CC CC CC    padding
        // 0x16: C3                ret
        let module = load_shellcode32(
            b"\xE8\x06\x00\x00\x00\x90\xC3\xCC\xCC\xCC\xCC\xE8\x06\x00\x00\x00\xCC\xCC\xCC\xCC\xCC\xCC\xC3",
        );
        let mut cfg = build_cfg(&module)?;

        let noret = prune_functions(&module, &mut cfg, &[0x0, 0xB, 0x16])?;

        assert!(noret.contains(&0xB));
        assert!(noret.contains(&0x0));
        assert!(noret.contains(&0x16).not());
        assert!(cfg.insns.insns_by_address.contains_key(&0x5).not());

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
        let mut cfg = build_cfg(&module)?;

        let noret = prune_functions(&module, &mut cfg, &[0x0, 0xB])?;

        assert!(noret.is_empty());
        assert!(cfg.insns.insns_by_address.contains_key(&0x5));
        assert!(cfg.insns.insns_by_address.contains_key(&0x6));

        Ok(())
    }

    #[test]
    fn noret_by_cfg_indirect_jump_is_conservative() -> Result<()> {
        // E ends with an indirect jump (like a thunk to an import): we can't
        // see where it goes, so it must NOT be considered no-return, and F's
        // post-call bytes must survive.
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
        let mut cfg = build_cfg(&module)?;

        let noret = prune_functions(&module, &mut cfg, &[0x0, 0x10])?;

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
        let mut cfg = build_cfg(&module)?;

        // the switch dispatch produced no flows: it's a leaf ending in JMP.
        assert!(cfg.flows.flows_by_src[&0x10].is_empty());

        let noret = prune_functions(&module, &mut cfg, &[0x0, 0x10])?;

        assert!(noret.is_empty());
        assert!(cfg.insns.insns_by_address.contains_key(&0x5));
        assert!(cfg.insns.insns_by_address.contains_key(&0x6));

        Ok(())
    }

    #[test]
    fn noret_by_cfg_dropped_branch_is_conservative() -> Result<()> {
        // G loops, but has a conditional exit whose target was dropped while
        // building the CFG (it points at a NULL byte, which isn't code).
        // part of G is missing, so it must NOT be considered no-return.
        //
        // F:
        // 0x0:  E8 06 00 00 00     call 0xB
        // 0x5:  90                 nop   (must survive)
        // 0x6:  C3                 ret   (must survive)
        // 0x7:  CC CC CC CC        padding
        // G:
        // 0xB:  74 03              jz 0x10 (dropped: 0x10 is a NULL byte)
        // 0xD:  EB FC              jmp 0xB
        // 0xF:  CC                 padding
        // 0x10: 00 00              (data)
        let module = load_shellcode32(b"\xE8\x06\x00\x00\x00\x90\xC3\xCC\xCC\xCC\xCC\x74\x03\xEB\xFC\xCC\x00\x00");
        let mut cfg = build_cfg(&module)?;

        // the conditional jump target was dropped.
        assert!(cfg.flows.flows_by_src[&0xB]
            .iter()
            .all(|f| !matches!(f, Flow::ConditionalJump(_))));

        let noret = prune_functions(&module, &mut cfg, &[0x0, 0xB])?;

        assert!(noret.is_empty());
        assert!(cfg.insns.insns_by_address.contains_key(&0x5));
        assert!(cfg.insns.insns_by_address.contains_key(&0x6));

        Ok(())
    }

    #[test]
    fn noret_imports_nop() -> Result<()> {
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

        // name the imports like the workspace does: `dll!symbol`.
        let mut names: BTreeMap<VA, String> = Default::default();
        for import in crate::analysis::pe::get_imports(&pe)?.values() {
            let name = match &import.symbol {
                ImportedSymbol::Name(name) => format!("{}!{}", import.dll, name),
                ImportedSymbol::Ordinal(ordinal) => format!("{}!#{}", import.dll, ordinal),
            };
            names.insert(import.address, name);
        }

        let mut norets: BTreeSet<VA> = Default::default();
        cfg_prune_noret_by_name(&pe.module, &mut cfg, &names, &mut norets)?;

        const EXIT_PROCESS: VA = 0x40600C;
        assert!(norets.contains(&EXIT_PROCESS));

        // there are two calls to ExitProcess().
        //
        // *************************
        // First call to ExitProcess
        // *************************
        //
        //     .text:00401C73  push  [esp+uExitCode] ; uExitCode
        //     .text:00401C77  call  ds:ExitProcess
        //     .text:00401C7D  CC  align 2
        //
        assert!(cfg.insns.insns_by_address.contains_key(&0x401C77));
        assert!(cfg.insns.insns_by_address.contains_key(&0x401C7D).not());
        //
        // this is the end of ___crtExitProcess().
        // and IDA detects this function as:
        //
        //    .text:00401C4E  ; Attributes: library function noreturn
        //    .text:00401C4E  ; void __cdecl __noreturn __crtExitProcess(UINT)
        //
        // this is a noret function because it ends with a call to ExitProcess.
        assert!(norets.contains(&0x401C4E));
        // ___crtExitProcess() has a call to it like:
        //
        //     .text:00401161  call  __NMSG_WRITE
        //     .text:00401166  push  0FFh  ; uExitCode
        //     .text:0040116B  call  ___crtExitProcess
        //     .text:00401170  db  59h ; Y
        //     .text:00401171  db  59h ; Y
        //
        // this is part of start():
        //
        //     .text:00401081  ; int start()
        //     .text:00401081  public start
        //     .text:00401081  start proc near
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
        //     .text:00402D69  push  3  ; uExitCode
        //     .text:00402D6B  call  ds:ExitProcess
        //     .text:00402D71  CC  align 2
        //
        // this is part of _report_failure (0x402D41)
        // which is part of __security_check_cookie (0x402D72) that tailcalls to
        // _report_failure. IDA detects it as such:
        //
        //     .text:00402D72  ; Attributes: library function
        //     .text:00402D72  ; void __fastcall __security_check_cookie(size_t)
        //
        // _report_failure is noret, but __security_check_cookie is *not*.
        assert!(norets.contains(&0x402D72).not());
        //
        // however, this leaf BB is terminated by the noret call.
        assert!(cfg.insns.insns_by_address.contains_key(&0x402D6B));
        assert!(cfg.insns.insns_by_address.contains_key(&0x402D71).not());

        Ok(())
    }
}
