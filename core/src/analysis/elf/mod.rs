//! ELF binary analysis including function detection.
//!
//! This module implements function detection using multiple strategies, including
//! several concepts inspired by the Jima algorithm:
//!
//! ## Jima-Inspired Concepts:
//!
//! 1. **Call Target Analysis** (`call_targets` module):
//!    - Uses call targets found during linear disassembly as initial function candidates
//!    - Analyzes alignment patterns of call targets (90% threshold) to inform boundary detection
//!
//! 2. **Inflection Points** (implemented in `cfg::flow`):
//!    - Inflection-out: instructions that leave sequential flow (jumps, returns, calls to terminal functions)
//!    - Inflection-in: instructions that are targets of calls or jumps
//!    - These form natural basic block boundaries
//!
//! 3. **Terminal Functions** (`noret_imports` module):
//!    - Identifies non-returning functions (exit, abort, etc.)
//!    - Treats calls to terminal functions as function exit points
//!
//! 4. **Function Boundary Heuristics** (`jima_heuristics` module):
//!    - Jump over NOPs: detects jumps that skip NOP sequences, marking function end
//!    - NOP padding: significant NOP sequences indicate function boundaries
//!    - Alignment-based boundary detection using call target statistics
//!
//! ## Additional Detection Methods:
//!
//! - **FDE Analysis**: Frame Description Entries from .eh_frame section
//! - **Symbol Tables**: Function symbols from symtab and dynsym
//! - **DWARF Debug Info**: Function information from debug sections
//! - **Entry Points**: Program entry points
//! - **Pattern Matching**: Function prologue patterns

use std::collections::BTreeMap;

use anyhow::Result;
use goblin::elf;

use crate::{
    loader::elf::{ELF, import::{read_import_libraries, ELFImportSymbol}},
    VA,
};

mod fde;
mod symtab;
mod dwarf;
pub mod entrypoints;
pub mod exports;
mod patterns;
mod call_targets;

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
    function_starts.extend(fde::find_fde_function_starts(elf, &goblin_elf)?);

    // add symtab/dynsym function starts
    function_starts.extend(symtab::find_symtab_function_starts(elf, &goblin_elf)?);

    // add DWARF debug info
    if let Ok(dwarf_starts) = dwarf::find_dwarf_function_starts(elf) {
        function_starts.extend(dwarf_starts);
    }

    // add entry points
    let entrypoints = entrypoints::find_elf_entrypoint(elf)?;
    for ep in entrypoints {
        function_starts.insert(ep);
    }

    // add call targets
    let decoder = dis::get_disassembler(&elf.module)?;
    function_starts.extend(
        call_targets::find_elf_call_targets(elf)?
            .into_iter()
            .filter(|&va| heuristics::is_probably_code(&elf.module, &decoder, va))
    );

    // add patterns
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