use anyhow::Result;
use log::debug;
use gimli::{EndianSlice, RunTimeEndian};

use crate::{
    loader::elf::ELF,
    VA,
};

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct DwarfFunction {
    pub address: VA,
    pub size: u64,
    pub name: Option<String>,
}

pub fn find_dwarf_function_starts(elf: &ELF) -> Result<Vec<VA>> {
    let goblin_elf = goblin::elf::Elf::parse(&elf.buf)?;
    let base_address = elf.module.address_space.base_address;
    let endian = if goblin_elf.header.endianness()? == goblin::container::Endian::Little {
        RunTimeEndian::Little
    } else {
        RunTimeEndian::Big
    };
    
    // load DWARF
    let dwarf = load_dwarf_sections(&goblin_elf, &elf.buf, endian)?;
    
    // find functions
    let functions = parse_dwarf_functions(&dwarf, base_address)?;
    
    let mut function_starts: Vec<VA> = functions.iter()
        .map(|f| f.address)
        .collect();
    
    function_starts.sort();
    function_starts.dedup();
    
    debug!("dwarf: found {} function starts", function_starts.len());
    
    Ok(function_starts)
}

fn load_dwarf_sections<'a>(goblin_elf: &goblin::elf::Elf, buf: &'a [u8], endian: RunTimeEndian) -> Result<gimli::Dwarf<EndianSlice<'a, RunTimeEndian>>> {
    let load_section = |section_name: &str| -> &'a [u8] {
        for section in &goblin_elf.section_headers {
            if let Some(name) = goblin_elf.shdr_strtab.get_at(section.sh_name) {
                if name == section_name {
                    let start = section.sh_offset as usize;
                    let end = start + section.sh_size as usize;
                    return &buf[start..end];
                }
            }
        }
        &[]
    };

    // load all possible sections
    let debug_abbrev = gimli::DebugAbbrev::new(load_section(".debug_abbrev"), endian);
    let debug_addr = gimli::DebugAddr::from(EndianSlice::new(load_section(".debug_addr"), endian));
    let debug_aranges = gimli::DebugAranges::new(load_section(".debug_aranges"), endian);
    let debug_info = gimli::DebugInfo::new(load_section(".debug_info"), endian);
    let debug_line = gimli::DebugLine::new(load_section(".debug_line"), endian);
    let debug_line_str = gimli::DebugLineStr::from(EndianSlice::new(load_section(".debug_line_str"), endian));
    let debug_str = gimli::DebugStr::new(load_section(".debug_str"), endian);
    let debug_str_offsets = gimli::DebugStrOffsets::from(EndianSlice::new(load_section(".debug_str_offsets"), endian));
    let debug_types = gimli::DebugTypes::new(load_section(".debug_types"), endian);

    // Location and range sections
    let debug_loc = gimli::DebugLoc::from(EndianSlice::new(load_section(".debug_loc"), endian));
    let debug_loclists = gimli::DebugLocLists::from(EndianSlice::new(load_section(".debug_loclists"), endian));
    let debug_ranges = gimli::DebugRanges::new(load_section(".debug_ranges"), endian);
    let debug_rnglists = gimli::DebugRngLists::new(load_section(".debug_rnglists"), endian);
    
    let locations = gimli::LocationLists::new(debug_loc, debug_loclists);
    let ranges = gimli::RangeLists::new(debug_ranges, debug_rnglists);

    Ok(gimli::Dwarf {
        debug_abbrev,
        debug_addr,
        debug_aranges,
        debug_info,
        debug_line,
        debug_line_str,
        debug_str,
        debug_str_offsets,
        debug_types,
        locations,
        ranges,
        ..Default::default()
    })
}

fn parse_dwarf_functions(dwarf: &gimli::Dwarf<EndianSlice<RunTimeEndian>>, base_address: VA) -> Result<Vec<DwarfFunction>> {
    let mut functions = Vec::new();
    
    let mut units = dwarf.units();
    while let Some(header) = units.next()? {
        let unit = dwarf.unit(header)?;
        let mut entries = unit.entries();
        while let Some((_, entry)) = entries.next_dfs()? {
            if entry.tag() == gimli::DW_TAG_subprogram {
                if let Some(func) = parse_function_entry(dwarf, &unit, entry, base_address)? {
                    functions.push(func);
                }
            }
        }
    }
    
    Ok(functions)
}

fn parse_function_entry(dwarf: &gimli::Dwarf<EndianSlice<RunTimeEndian>>, unit: &gimli::Unit<EndianSlice<RunTimeEndian>>, entry: &gimli::DebuggingInformationEntry<EndianSlice<RunTimeEndian>>, base_address: VA) -> Result<Option<DwarfFunction>> {
    let mut low_pc: Option<u64> = None;
    let mut high_pc: Option<u64> = None;
    let mut high_pc_is_offset = false;
    let mut name: Option<String> = None;

    let mut attrs = entry.attrs();
    while let Some(attr) = attrs.next()? {
        match attr.name() {
            gimli::DW_AT_low_pc => {
                if let gimli::AttributeValue::Addr(addr) = attr.value() {
                    low_pc = Some(addr);
                }
            }
            gimli::DW_AT_high_pc => {
                match attr.value() {
                    gimli::AttributeValue::Addr(addr) => {
                        high_pc = Some(addr);
                        high_pc_is_offset = false;
                    }
                    gimli::AttributeValue::Udata(offset) => {
                        high_pc = Some(offset);
                        high_pc_is_offset = true;
                    }
                    _ => {}
                }
            }
            gimli::DW_AT_name => {
                if let Ok(s) = dwarf.attr_string(unit, attr.value()) {
                    if let Ok(s_str) = s.to_string() {
                        name = Some(s_str.to_string());
                    }
                }
            }
            _ => {}
        }
    }
    
    if let Some(addr) = low_pc {
        let actual_address = addr + base_address;
        let size = if let Some(hp) = high_pc {
            if high_pc_is_offset {
                hp
            } else {
                hp.saturating_sub(addr)
            }
        } else {
            0
        };
        
        debug!("dwarf: found function at {:#x} (size: {:#x})", actual_address, size);
        if let Some(ref n) = name {
            debug!("  name: {}", n);
        }
        
        Ok(Some(DwarfFunction {
            address: actual_address,
            size,
            name,
        }))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rsrc::*;

    #[test]
    fn test_nop_elf_no_dwarf() -> Result<()> {
        let buf = get_buf(Rsrc::NOPELF);
        let elf = crate::loader::elf::ELF::from_bytes(&buf)?;
        
        let result = find_dwarf_function_starts(&elf)?;
        assert_eq!(0, result.len());
        
        Ok(())
    }

    #[test]
    fn test_dwarf_functions() -> Result<()> {
        let buf = get_buf(Rsrc::TESTDWARF);
        let elf = crate::loader::elf::ELF::from_bytes(&buf)?;
        
        let function_starts = find_dwarf_function_starts(&elf)?;
        assert_eq!(2, function_starts.len());
        
        Ok(())
    }
}
