use std::{collections::BTreeMap, ops::Not};

use anyhow::Result;
use log::debug;

#[cfg(feature = "disassembler")]
use crate::analysis::dis;
use crate::{
    aspace::AddressSpace,
    loader::pe::{
        imports,
        imports::{read_best_thunk_data, IMAGE_THUNK_DATA},
        PE,
    },
    module::Permissions,
    RVA, VA,
};
#[cfg(feature = "disassembler")]
use std::collections::BTreeSet;

#[cfg(feature = "disassembler")]
pub mod call_targets;
pub mod control_flow_guard;
pub mod entrypoints;
pub mod exports;
pub mod patterns;
pub mod pointers;
pub mod runtime_functions;
pub mod safeseh;

#[cfg(feature = "disassembler")]
pub mod noret_imports;

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub enum ImportedSymbol {
    Ordinal(u32),
    Name(String),
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub struct Import {
    /// the address of the First Thunk.
    /// that is, the thing that will be referenced by code.
    pub address: VA,
    pub dll:     String,
    pub symbol:  ImportedSymbol,
}

impl std::fmt::Display for Import {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.symbol {
            ImportedSymbol::Ordinal(ord) => write!(f, "{}!#{}", self.dll, ord),
            ImportedSymbol::Name(name) => write!(f, "{}!{}", self.dll, name),
        }
    }
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub enum ThunkTarget {
    Import(Import),
    Function(VA),
}

impl std::fmt::Display for ThunkTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            ThunkTarget::Import(import) => write!(f, "Import({})", import),
            ThunkTarget::Function(va) => write!(f, "Function(0x{:x})", va),
        }
    }
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct Thunk {
    /// the address of the function thunk
    pub address: VA,
    pub target:  ThunkTarget,
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum Function {
    Local(VA),
    Thunk(Thunk),
    Import(Import),
}

pub fn get_imports(pe: &PE) -> Result<BTreeMap<VA, Import>> {
    let mut imports: BTreeMap<VA, Import> = Default::default();

    if let Some(import_directory) = imports::get_import_directory(pe)? {
        let base_address = pe.module.address_space.base_address;
        let psize = pe.module.arch.pointer_size();

        for import_descriptor in imports::read_import_descriptors(pe, import_directory) {
            let dll = pe
                .module
                .address_space
                .relative
                .read_ascii(import_descriptor.name, 1)?
                .to_lowercase();

            for i in 0.. {
                let oft = base_address + import_descriptor.original_first_thunk + (i * psize) as RVA;
                let ft = base_address + import_descriptor.first_thunk + (i * psize) as RVA;

                if pe.module.read_rva_at_va(ft)? == 0x0 {
                    break;
                }

                let symbol = match read_best_thunk_data(pe, oft, ft) {
                    Ok(IMAGE_THUNK_DATA::Function(name_rva)) => {
                        // u16    hint
                        // asciiz name
                        let name = pe.module.address_space.relative.read_ascii(name_rva + 2, 1)?;
                        ImportedSymbol::Name(name)
                    }
                    Ok(IMAGE_THUNK_DATA::Ordinal(ord)) => ImportedSymbol::Ordinal(ord),
                    Err(e) => {
                        debug!("imports: error reading thunk: {}", e);
                        continue;
                    }
                };

                imports.insert(
                    ft,
                    Import {
                        address: ft,
                        dll: dll.to_string(),
                        symbol,
                    },
                );
            }
        }
    }

    Ok(imports)
}

#[cfg(feature = "disassembler")]
pub fn find_thunks(pe: &PE, imports: &BTreeMap<VA, Import>, functions: &BTreeSet<VA>) -> Result<BTreeMap<VA, Thunk>> {
    use super::dis::get_operand_xref;

    let mut thunks: BTreeMap<VA, Thunk> = Default::default();
    let decoder = dis::get_disassembler(&pe.module)?;

    for &function in functions.iter() {
        if let Ok(insn_buf) = pe.module.address_space.read_bytes(function, 0x10) {
            if let Ok(Some(insn)) = decoder.decode(&insn_buf) {
                if insn.mnemonic != zydis::Mnemonic::JMP {
                    continue;
                }

                let op = dis::get_first_operand(&insn).expect("JMP has no target");

                if let Ok(Some(target)) = get_operand_xref(&pe.module, function, &insn, op) {
                    match target {
                        dis::Target::Direct(target) => {
                            let thunk = if let Some(import) = imports.get(&target) {
                                Thunk {
                                    address: function,
                                    target:  ThunkTarget::Import(import.clone()),
                                }
                            } else if functions.contains(&target) {
                                Thunk {
                                    address: function,
                                    target:  ThunkTarget::Function(target),
                                }
                            } else {
                                if pe.module.probe_va(target, Permissions::X).not() {
                                    continue;
                                }

                                // not a function found at this location yet.
                                // but that should be ok. this is newly discovered code.
                                Thunk {
                                    address: function,
                                    target:  ThunkTarget::Function(target),
                                }
                            };
                            debug!("thunk: {:#x} -> {:}", thunk.address, thunk.target);
                            thunks.insert(thunk.address, thunk);
                        }
                        dis::Target::Indirect(_) => {
                            // unable to resolve, such as `jmp [0x0]` or `jmp eax`
                            continue;
                        }
                    }
                }
            }
        }
    }

    Ok(thunks)
}

#[cfg(feature = "disassembler")]
pub fn find_functions(pe: &PE) -> Result<Vec<Function>> {
    use crate::analysis::heuristics;

    let imports = get_imports(pe)?;
    debug!("imports: found {} imports", imports.len());
    for (va, import) in imports.iter() {
        debug!("imports: {va:#x}: {import}");
    }

    let mut function_starts: BTreeSet<VA> = Default::default();
    function_starts.extend(crate::analysis::pe::entrypoints::find_pe_entrypoint(pe)?);
    function_starts.extend(crate::analysis::pe::exports::find_pe_exports(pe)?);
    function_starts.extend(crate::analysis::pe::safeseh::find_pe_safeseh_handlers(pe)?);
    function_starts.extend(crate::analysis::pe::runtime_functions::find_pe_runtime_functions(pe)?);
    function_starts.extend(crate::analysis::pe::control_flow_guard::find_pe_cfguard_functions(pe)?);

    // the following are heuristics,
    // so ensure the found addresses look like code.
    let decoder = dis::get_disassembler(&pe.module)?;
    function_starts.extend(
        crate::analysis::pe::call_targets::find_pe_call_targets(pe)?
            .into_iter()
            .filter(|&va| heuristics::is_probably_code(&pe.module, &decoder, va)),
    );
    function_starts.extend(
        crate::analysis::pe::patterns::find_function_prologues(pe)?
            .into_iter()
            .filter(|&va| heuristics::is_probably_code(&pe.module, &decoder, va)),
    );

    // ensure that all functions pointed to by a thunk are a function.
    // some of these target functions may not be recongized by other passes.
    //
    // we keep searching until we reach a fixed point,
    // to ensure we account for thunks to thunks to functions.
    let mut thunk_candidates = function_starts.clone();
    let mut thunks: BTreeMap<VA, Thunk> = Default::default();
    while thunk_candidates.is_empty().not() {
        let confirmed_thunks = find_thunks(pe, &imports, &thunk_candidates)?;

        // these are all the addresses pointed to by thunks,
        // which we need to ensure are functions.
        let function_thunk_targets = confirmed_thunks
            .values()
            .filter_map(|thunk| match thunk.target {
                ThunkTarget::Function(target) => Some(target),
                ThunkTarget::Import(_) => None,
            })
            .collect::<Vec<VA>>();

        thunks.extend(confirmed_thunks.into_iter());

        let mut next_candidates: BTreeSet<VA> = Default::default();
        for &target in function_thunk_targets.iter() {
            if function_starts.insert(target) {
                debug!("found new function candidate from thunk target: 0x{target:x}");
                next_candidates.insert(target);
                // next loop we'll check if this target is a thunk, too.
            }
        }

        debug!("found {} thunk candidates this round", next_candidates.len());
        thunk_candidates = next_candidates;
    }

    debug!("functions: found {} function candidates", function_starts.len());
    debug!("functions: found {} thunks", thunks.len());

    for function_start in function_starts.iter() {
        debug!("functions: function candidate: {function_start:#x}");
    }

    let function_starts: Vec<_> = function_starts
        .difference(&thunks.keys().cloned().collect())
        .cloned()
        .collect();
    debug!("functions: found {} functions", function_starts.len());

    let mut functions: Vec<Function> = Default::default();
    functions.extend(function_starts.iter().map(|&f| Function::Local(f)));
    functions.extend(thunks.values().cloned().map(Function::Thunk));
    functions.extend(imports.values().cloned().map(Function::Import));
    functions.sort_unstable();

    Ok(functions)
}

#[cfg(feature = "disassembler")]
pub fn find_function_starts(pe: &PE) -> Result<Vec<VA>> {
    Ok(find_functions(pe)?
        .into_iter()
        .filter_map(|f| match f {
            Function::Local(va) => Some(va),
            Function::Thunk(Thunk { address: va, .. }) => Some(va),
            _ => None,
        })
        .collect())
}
