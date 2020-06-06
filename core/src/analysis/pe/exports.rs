//! Parse the PE export table (if present) to find entries in find exports in executable sections.
//!
//! PEs may export data, which we'll assume isn't in an executable section.
use anyhow::Result;

use crate::VA;
use crate::loader::pe::PE;

pub fn find_pe_exports(pe: &PE) -> Result<Vec<VA>> {
    let executable_sections = pe.get_pe_executable_sections()?;

    let base_address = match pe.pe.header.optional_header {
        Some(opt) => opt.windows_fields.image_base,
        _ => {
            0x40_000
        }
    };

    let exports: Vec<VA> = pe
        .pe
        .exports
        .iter()
        // re-exports are simply strings that point to a `DLL.export_name` ASCII string.
        // therefore, they're not functions/code.
        .filter(|&exp| exp.reexport.is_none())
        .map(|exp| base_address + exp.rva as u64)
        .filter(|&va| {
            // PE may export data, so ensure the exports we track are executable (functions).
            executable_sections
                .iter()
                .find(|&sec| sec.contains(&va))
                .is_some()
        })
        .collect();

    Ok(exports)
}