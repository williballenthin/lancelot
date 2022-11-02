use std::collections::BTreeMap;

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
    util, RVA, VA,
};
#[cfg(feature = "disassembler")]
use std::collections::HashSet;

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

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum ImportedSymbol {
    Ordinal(u32),
    Name(String),
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
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

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct Thunk {
    /// the address of the function thunk
    pub address: VA,
    pub import:  Import,
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
            debug!("imports: {}", dll);

            for i in 0.. {
                let oft = base_address + import_descriptor.original_first_thunk + (i * psize) as RVA;
                let ft = base_address + import_descriptor.first_thunk + (i * psize) as RVA;

                if pe.module.read_rva_at_va(ft)? == 0x0 {
                    break;
                }

                let symbol = match read_best_thunk_data(pe, oft, ft)? {
                    IMAGE_THUNK_DATA::Function(name_rva) => {
                        // u16    hint
                        // asciiz name
                        let name = pe.module.address_space.relative.read_ascii(name_rva + 2, 1)?;
                        debug!("imports: {}!{}", dll, name);
                        ImportedSymbol::Name(name)
                    }
                    IMAGE_THUNK_DATA::Ordinal(ord) => {
                        debug!("imports: {}!#{}", dll, ord);
                        ImportedSymbol::Ordinal(ord)
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
pub fn find_thunks(pe: &PE, imports: &BTreeMap<VA, Import>, functions: &HashSet<VA>) -> Result<BTreeMap<VA, Thunk>> {
    let mut thunks: BTreeMap<VA, Thunk> = Default::default();
    let decoder = dis::get_disassembler(&pe.module)?;

    for &function in functions.iter() {
        if let Ok(insn_buf) = pe.module.address_space.read_bytes(function, 0x10) {
            if let Ok(Some(insn)) = decoder.decode(&insn_buf) {
                if insn.mnemonic != zydis::Mnemonic::JMP {
                    continue;
                }

                let op = dis::get_first_operand(&insn).expect("JMP has no target");

                if let zydis::OperandType::MEMORY = op.ty {
                    // 32-bit
                    if op.mem.base == zydis::Register::NONE
                        && op.mem.index == zydis::Register::NONE
                        && op.mem.scale == 0
                        && op.mem.disp.has_displacement
                    {
                        // the operand is a deref of a memory address.
                        // for example: JMP [0x0]
                        // this means: read the ptr from 0x0, and then jump to it.

                        if op.mem.disp.displacement < 0 {
                            continue;
                        }
                        let ptr: VA = op.mem.disp.displacement as u64;

                        if let Some(import) = imports.get(&ptr) {
                            let thunk = Thunk {
                                address: function,
                                import:  import.clone(),
                            };
                            debug!("thunk: {:#x} -> {}", thunk.address, thunk.import);
                            thunks.insert(thunk.address, thunk);
                        }
                    } else if op.mem.base == zydis::Register::RIP
                            // only valid on x64
                            && op.mem.index == zydis::Register::NONE
                            && op.mem.scale == 0
                            && op.mem.disp.has_displacement
                    {
                        // this is RIP-relative addressing.
                        // it works like a relative immediate,
                        // that is: dst = *(rva + displacement + instruction len)

                        let ptr =
                            match util::va_add_signed(function + insn.length as u64, op.mem.disp.displacement) {
                                None => continue,
                                Some(ptr) => ptr,
                            };

                        if let Some(import) = imports.get(&ptr) {
                            let thunk = Thunk {
                                address: function,
                                import:  import.clone(),
                            };
                            debug!("thunk: {:#x} -> {}", thunk.address, thunk.import);
                            thunks.insert(thunk.address, thunk);
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
    let imports = get_imports(pe)?;
    debug!("imports: found {} imports", imports.len());

    let mut function_starts: HashSet<VA> = Default::default();
    function_starts.extend(crate::analysis::pe::entrypoints::find_pe_entrypoint(pe)?);
    function_starts.extend(crate::analysis::pe::exports::find_pe_exports(pe)?);
    function_starts.extend(crate::analysis::pe::safeseh::find_pe_safeseh_handlers(pe)?);
    function_starts.extend(crate::analysis::pe::runtime_functions::find_pe_runtime_functions(pe)?);
    function_starts.extend(crate::analysis::pe::control_flow_guard::find_pe_cfguard_functions(pe)?);
    function_starts.extend(crate::analysis::pe::call_targets::find_pe_call_targets(pe)?);
    function_starts.extend(crate::analysis::pe::patterns::find_function_prologues(pe)?);
    /*
    function_starts.extend(crate::analysis::pe::pointers::find_pe_nonrelocated_executable_pointers(
        pe,
    )?);
    */

    // TODO: validate that the code looks ok

    let thunks = find_thunks(pe, &imports, &function_starts)?;
    debug!("functions: found {} function candidates", function_starts.len());
    debug!("functions: found {} thunks", thunks.len());

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
        .filter(|f| matches!(f, Function::Local(_)))
        .map(|f| match f {
            Function::Local(va) => va,
            _ => unreachable!(),
        })
        .collect())
}
