use std::collections::BTreeMap;

use anyhow::Result;
use goblin::elf;
use log::debug;

use crate::{
    loader::elf::{ELF, import::{read_import_libraries, ELFDynamicImport, ELFImportSymbol}},
    VA,
};

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub struct ELFImport {
    /// the address of the import (PLT or GOT entry)
    pub address: VA,
    pub library: String,
    pub symbol:  ELFImportSymbol,
}

pub fn get_imports(elf: &ELF) -> Result<BTreeMap<VA, ELFImport>> {
    let mut imports: BTreeMap<VA, ELFImport> = Default::default();

    // parse the ELF file
    let goblin_elf = elf::Elf::parse(&elf.buf)?;

    // read import libraries and symbols
    let import_libs = read_import_libraries(&goblin_elf);

    for lib in import_libs {
        for symbol in lib.symbols {
            // use PLT address if available, otherwise GOT address
            let address = symbol.plt_address
                .or(symbol.got_address)
                .unwrap_or(0);

            if address != 0 {
                imports.insert(
                    address,
                    ELFImport {
                        address,
                        library: lib.lib_name.clone(),
                        symbol,
                    },
                );
            }
        }
    }

    Ok(imports)
}

#[cfg(feature = "disassembler")]
pub fn find_function_starts(elf: &ELF) -> Result<Vec<VA>> {
    use std::collections::BTreeSet;
    use crate::analysis::heuristics;

    let mut function_starts: BTreeSet<VA> = Default::default();

    // parse the ELF file
    let goblin_elf = elf::Elf::parse(&elf.buf)?;

    // add entry point
    if let Some(entry) = goblin_elf.header.e_entry.checked_add(elf.module.address_space.base_address) {
        if entry != elf.module.address_space.base_address {
            debug!("elf: found function start at entry point: {:#x}", entry);
            function_starts.insert(entry);
        }
    }

    // add symbols from symbol table
    for sym in goblin_elf.dynsyms.iter() {
        if sym.st_type() == elf::sym::STT_FUNC && sym.st_value != 0 {
            let addr = sym.st_value + elf.module.address_space.base_address;
            debug!("elf: found function start in dynsym: {:#x} (sym value: {:#x})", addr, sym.st_value);
            function_starts.insert(addr);
        }
    }

    // add symbols from symtab if available
    for sym in goblin_elf.syms.iter() {
        if sym.st_type() == elf::sym::STT_FUNC && sym.st_value != 0 {
            let addr = sym.st_value + elf.module.address_space.base_address;
            debug!("elf: found function start in symtab: {:#x} (sym value: {:#x})", addr, sym.st_value);
            function_starts.insert(addr);
        }
    }

    // filter to ensure addresses look like code
    #[cfg(feature = "disassembler")]
    {
        let decoder = crate::analysis::dis::get_disassembler(&elf.module)?;
        let filtered_starts: Vec<VA> = function_starts
            .into_iter()
            .filter(|&va| heuristics::is_probably_code(&elf.module, &decoder, va))
            .collect();
        Ok(filtered_starts)
    }
}

pub mod noret_imports;