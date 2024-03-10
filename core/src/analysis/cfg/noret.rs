use std::collections::BTreeSet;

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
    log::debug!("mark noret: {:#x}", va);
    let mut ret: BTreeSet<VA> = Default::default();
    let mut batch: ChangeBatch = Default::default();

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

        batch.prune_noret_call(src);
        callers.push(src);
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
                        let insn = decoder
                            .decode(&insn_buf)
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
        ret.extend(cfg_mark_noret(module, cfg, caller)?);
    }
    ret.insert(va);

    Ok(ret)
}
