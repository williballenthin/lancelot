use std::collections::BTreeSet;

use anyhow::Result;

use crate::{
    analysis::{
        cfg::CFG,
        elf::{self},
    },
    loader::elf::ELF,
    VA,
};

pub fn cfg_prune_noret_imports(elf: &ELF, cfg: &mut CFG) -> Result<BTreeSet<VA>> {
    let mut noret = elf::get_imports(elf)?
        .values()
        .filter(|imp| {
            let is_got_entry = imp.symbol.got_address.is_some() && 
                               (imp.symbol.plt_address.is_none() || 
                                imp.address == imp.symbol.got_address.unwrap_or(0) + elf.module.address_space.base_address);
            
            if !is_got_entry {
                return false;
            }
            
            match (&*imp.library, &imp.symbol.name) {
                ("libc.so.6", name) if name == "exit" => true,
                ("libc.so.6", name) if name == "_exit" => true,
                ("libc.so.6", name) if name == "__exit" => true,
                ("libc.so.6", name) if name == "_Exit" => true,
                ("libc.so.6", name) if name == "abort" => true,
                (_, _) => false,
            }
        })
        .map(|imp| imp.address)
        .collect::<BTreeSet<_>>();

    for &noret_import in noret.clone().iter() {
        log::debug!("noret import {:#x}", noret_import);
        noret.extend(crate::analysis::cfg::noret::cfg_mark_noret(
            &elf.module,
            cfg,
            noret_import,
        )?);
    }

    Ok(noret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{analysis::cfg::InstructionIndex, rsrc::*};

    #[test]
    fn nop_elf() -> Result<()> {
        let buf = get_buf(Rsrc::NOPELF);
        let elf = crate::loader::elf::ELF::from_bytes(&buf)?;
        let mut insns: InstructionIndex = Default::default();

        for &ep in crate::analysis::elf::entrypoints::find_elf_entrypoint(&elf)?.iter() {
            insns.build_index(&elf.module, ep)?;
        }

        for &exp in crate::analysis::elf::exports::find_elf_exports(&elf)?.iter() {
            insns.build_index(&elf.module, exp)?;
        }

        let mut cfg = CFG::from_instructions(&elf.module, insns)?;
        let norets = cfg_prune_noret_imports(&elf, &mut cfg)?;

        assert_eq!(0, norets.len());

        Ok(())
    }
}