use anyhow::Result;
use std::collections::HashMap;

use crate::{
    arch::Arch,
    aspace::{self, RelativeAddressSpace},
    module::{Module, Permissions, Section},
    util, RVA, VA,
};

#[derive(Clone)]
pub struct ELFDynamicImport {
    pub lib_name: String,
    pub symbols: Vec<ELFImportSymbol>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ELFImportSymbol {
    pub name: String,
    pub symbol_type: ELFSymbolType,
    pub visibility: ElfSymbolBinding,
    pub plt_address: Option<u64>,
    pub got_address: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ELFSymbolType {
    Function,
    Object,
    Unknown(u8),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ElfSymbolBinding {
    Local,
    Global,
    Weak,
    Unknown(u8),
}

pub fn read_import_libraries(elf: &goblin::elf::Elf) -> Vec<ELFDynamicImport> {
    let mut imports = Vec::new();
    
    // get all import symbols with PLT/GOT addresses resolved
    let import_symbols = read_import_symbols(elf);
    
    // group symbols by library
    let mut lib_symbols: HashMap<String, Vec<ELFImportSymbol>> = HashMap::new();
    
    // initialize with known libraries
    for lib in elf.libraries.iter() {
        lib_symbols.insert(lib.to_string(), Vec::new());
    }
    
    // add undefined symbols
    for symbol in import_symbols {
        if !symbol.name.is_empty() {
            // cant easily determine library for each symbol so just assigned to first library for now
            let lib_name = determine_symbol_library(&symbol.name, &elf.libraries)
                .unwrap_or_else(|| "unknown".to_string());
            
            lib_symbols.entry(lib_name).or_insert_with(Vec::new).push(symbol);
        }
    }
    
    // convert to final structure
    for (lib_name, symbols) in lib_symbols {
        if !symbols.is_empty() || elf.libraries.contains(&lib_name.as_str()) {
            imports.push(ELFDynamicImport { lib_name, symbols });
        }
    }
    
    imports
}

fn determine_symbol_library(symbol_name: &str, libraries: &[&str]) -> Option<String> {
    // for now just return the first library or None needs to be improved
    if !libraries.is_empty() {
        Some(libraries[0].to_string())
    } else {
        None
    }
}

pub fn read_symbol_table(elf: &goblin::elf::Elf) -> Vec<ELFImportSymbol> {
    let mut symbols = Vec::new();
    
    for sym in elf.dynsyms.iter() {
        let name = elf.dynstrtab.get_at(sym.st_name)
            .unwrap_or("")
            .to_string();
            
        let symbol_type = match sym.st_type() {
            goblin::elf::sym::STT_NOTYPE => ELFSymbolType::Unknown(0),
            goblin::elf::sym::STT_OBJECT => ELFSymbolType::Object,
            goblin::elf::sym::STT_FUNC => ELFSymbolType::Function,
            t => ELFSymbolType::Unknown(t),
        };
        
        let visibility = match sym.st_bind() {
            goblin::elf::sym::STB_LOCAL => ElfSymbolBinding::Local,
            goblin::elf::sym::STB_GLOBAL => ElfSymbolBinding::Global,
            goblin::elf::sym::STB_WEAK => ElfSymbolBinding::Weak,
            b => ElfSymbolBinding::Unknown(b),
        };
        
        symbols.push(ELFImportSymbol {
            name,
            symbol_type,
            visibility,
            plt_address: None,
            got_address: None,
        });
    }
    
    symbols
}

pub fn read_import_symbols(elf: &goblin::elf::Elf) -> Vec<ELFImportSymbol> {
    let mut symbols = read_symbol_table(elf);
    
    // find PLT and GOT sections
    let plt_section = find_section_by_name(elf, ".plt");
    let plt_got_section = find_section_by_name(elf, ".plt.got");
    let got_plt_section = find_section_by_name(elf, ".got.plt");
    let got_section = find_section_by_name(elf, ".got");
    
    // use .got.plt if available otherwise fall back to .got
    let got_section = got_plt_section.or(got_section);
    
    if plt_section.is_none() && plt_got_section.is_none() && got_section.is_none() {
        return symbols.into_iter()
            .filter(|sym| is_import_symbol(elf, sym))
            .collect();
    }
    
    // build symbol index from relocations
    let mut symbol_addresses: HashMap<usize, (Option<u64>, Option<u64>)> = HashMap::new();
    
    // process PLT relocations
    for rel in elf.dynrels.iter() {
        let sym_idx = rel.r_sym;
        
        // check if this relocation is in any PLT range
        let is_plt_reloc = [plt_section, plt_got_section]
            .iter()
            .flatten()
            .any(|plt| rel.r_offset >= plt.sh_addr && rel.r_offset < plt.sh_addr + plt.sh_size);
        
        // check if this relocation is in GOT range  
        let is_got_reloc = if let Some(got) = got_section {
            rel.r_offset >= got.sh_addr && rel.r_offset < got.sh_addr + got.sh_size
        } else {
            false
        };
        
        if is_plt_reloc || is_got_reloc {
            let entry = symbol_addresses.entry(sym_idx).or_insert((None, None));
            
            if is_plt_reloc {
                entry.0 = Some(rel.r_offset);
            }
            if is_got_reloc {
                entry.1 = Some(rel.r_offset);
            }
        }
    }

    for rel in elf.dynrelas.iter() {
        let sym_idx = rel.r_sym;
        
        // check if this relocation is in any PLT range
        let is_plt_reloc = [plt_section, plt_got_section]
            .iter()
            .flatten()
            .any(|plt| rel.r_offset >= plt.sh_addr && rel.r_offset < plt.sh_addr + plt.sh_size);
        
        // check if this relocation is in GOT range  
        let is_got_reloc = if let Some(got) = got_section {
            rel.r_offset >= got.sh_addr && rel.r_offset < got.sh_addr + got.sh_size
        } else {
            false
        };
        
        if is_plt_reloc || is_got_reloc {
            let entry = symbol_addresses.entry(sym_idx).or_insert((None, None));
            
            if is_plt_reloc {
                entry.0 = Some(rel.r_offset);
            }
            if is_got_reloc {
                entry.1 = Some(rel.r_offset);
            }
        }
    }
    
    // update symbols with addresses and filter for imports only
    symbols.into_iter().enumerate()
        .filter_map(|(idx, mut symbol)| {
            // update with PLT/GOT addresses if available
            if let Some((plt_addr, got_addr)) = symbol_addresses.get(&idx) {
                symbol.plt_address = *plt_addr;
                symbol.got_address = *got_addr;
            }
            
            // only return import symbols
            if is_import_symbol(elf, &symbol) {
                Some(symbol)
            } else {
                None
            }
        })
        .collect()
}

fn find_section_by_name<'a>(elf: &'a goblin::elf::Elf<'a>, name: &'a str) -> Option<&'a goblin::elf::SectionHeader> {
    elf.section_headers.iter().find(|sh| {
        elf.shdr_strtab.get_at(sh.sh_name)
            .map(|section_name| section_name == name)
            .unwrap_or(false)
    })
}

fn is_import_symbol(elf: &goblin::elf::Elf, symbol: &ELFImportSymbol) -> bool {
    // find the corresponding dynsym entry
    for (idx, sym) in elf.dynsyms.iter().enumerate() {
        if let Some(sym_name) = elf.dynstrtab.get_at(sym.st_name) {
            if sym_name == symbol.name {
                // import symbols are typically undefined and have names
                // Also include weak symbols that might be resolved at runtime
                let is_undefined = sym.st_shndx == goblin::elf::section_header::SHN_UNDEF as usize;
                let is_weak = sym.st_bind() == goblin::elf::sym::STB_WEAK;
                let has_name = !symbol.name.is_empty();
                
                return (is_undefined || is_weak) && has_name;
            }
        }
    }
    false
}
