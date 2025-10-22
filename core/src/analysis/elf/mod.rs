use std::collections::BTreeMap;

use anyhow::Result;
use goblin::elf;

use crate::{
    loader::elf::{ELF, import::{read_import_libraries, ELFImportSymbol}},
    VA,
};

mod fde;
pub mod entrypoints;
pub mod exports;
mod patterns;

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
    use crate::analysis::{dis, heuristics};

    let mut function_starts: BTreeSet<VA> = Default::default();

    // parse the ELF file
    let goblin_elf = elf::Elf::parse(&elf.buf)?;

    // add FDE-related function starts
    //function_starts.extend(fde::find_fde_function_starts(elf, &goblin_elf)?);

    // add entry points
    let entrypoints = entrypoints::find_elf_entrypoint(elf)?;
    for ep in entrypoints {
        function_starts.insert(ep);
    }

    // add patterns
    let decoder = dis::get_disassembler(&elf.module)?;
    function_starts.extend(
        patterns::find_function_prologues(elf)?
            .into_iter()
            .filter(|&va| heuristics::is_probably_code(&elf.module, &decoder, va))
    );
    
    let filtered_starts: Vec<VA> = function_starts
        .into_iter()
        .collect();
    Ok(filtered_starts)
}

pub mod noret_imports;