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

    // add PLT entries as function starts
    if let Some(plt_section) = goblin_elf.section_headers.iter().find(|sh| {
        goblin_elf.shdr_strtab.get_at(sh.sh_name).map(|name| name == ".plt").unwrap_or(false)
    }) {
        let plt_start = plt_section.sh_addr;
        let plt_size = plt_section.sh_size;
        let entry_size = 16;
        let mut addr = plt_start + entry_size;
        while addr < plt_start + plt_size {
            debug!("elf: found function start in PLT: {:#x}", addr);
            function_starts.insert(addr);
            addr += entry_size;
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
            .collect();
        Ok(filtered_starts)
    }
}

pub mod noret_imports;