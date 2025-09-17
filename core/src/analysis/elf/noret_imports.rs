use std::collections::BTreeSet;

use anyhow::Result;

use crate::{
    analysis::{
        cfg::CFG,
        elf::{self},
    },
    loader::elf::{ELF, import::{ELFImportSymbol, ELFSymbolType}},
    VA,
};

pub fn cfg_prune_noret_imports(elf: &ELF, cfg: &mut CFG) -> Result<BTreeSet<VA>> {
    let mut noret = elf::get_imports(elf)?
        .values()
        .filter(|imp| match (&*imp.library, &imp.symbol.name) {
            ("libc.so.6", name) if name == "exit" => true,
            ("libc.so.6", name) if name == "_exit" => true,
            ("libc.so.6", name) if name == "__exit" => true,
            ("libc.so.6", name) if name == "_Exit" => true,
            ("libc.so.6", name) if name == "abort" => true,
            (_, _) => false,
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