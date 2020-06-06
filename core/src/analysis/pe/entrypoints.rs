//! Parse the PE header for the entry point (if present).
//!
//! All PEs should have an entry point, unless they don't have any code.
use anyhow::Result;

use crate::VA;
use crate::loader::pe::PE;

pub fn find_pe_entrypoint(pe: &PE) -> Result<Vec<VA>> {
    if let Some(optional_header) = pe.pe.header.optional_header {
        let entry_point = optional_header.standard_fields.address_of_entry_point;
        if entry_point == 0 {
            return Ok(vec![]);
        }
        Ok(vec![optional_header.windows_fields.image_base + entry_point])
    } else {
        Ok(vec![])
    }
}
