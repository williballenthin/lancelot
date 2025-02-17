//! Parse the PE header for the entry point (if present).
//!
//! All PEs should have an entry point, unless they don't have any code.
use anyhow::Result;
use log::debug;

use crate::{loader::pe::PE, VA};

pub fn find_pe_entrypoint(pe: &PE) -> Result<Vec<VA>> {
    if let Some(optional_header) = pe.optional_header {
        let entry_point = optional_header.standard_fields.address_of_entry_point;
        if entry_point == 0 {
            return Ok(vec![]);
        }
        let entry_point = optional_header.windows_fields.image_base + entry_point;
        debug!("entry point: {entry_point:#x}");
        Ok(vec![entry_point])
    } else {
        Ok(vec![])
    }
}

#[cfg(test)]
mod tests {
    use crate::rsrc::*;
    use anyhow::Result;

    #[test]
    fn k32() -> Result<()> {
        let buf = get_buf(Rsrc::K32);
        let pe = crate::loader::pe::PE::from_bytes(&buf)?;

        let fns = crate::analysis::pe::entrypoints::find_pe_entrypoint(&pe)?;
        assert_eq!(1, fns.len());

        Ok(())
    }

    #[test]
    fn tiny() -> Result<()> {
        let buf = get_buf(Rsrc::TINY);
        let pe = crate::loader::pe::PE::from_bytes(&buf)?;

        let fns = crate::analysis::pe::entrypoints::find_pe_entrypoint(&pe)?;
        assert_eq!(0, fns.len());

        Ok(())
    }

    #[test]
    fn nop() -> Result<()> {
        let buf = get_buf(Rsrc::NOP);
        let pe = crate::loader::pe::PE::from_bytes(&buf)?;

        let fns = crate::analysis::pe::entrypoints::find_pe_entrypoint(&pe)?;
        assert_eq!(1, fns.len());

        Ok(())
    }

    #[test]
    fn mimi() -> Result<()> {
        let buf = get_buf(Rsrc::MIMI);
        let pe = crate::loader::pe::PE::from_bytes(&buf)?;

        let fns = crate::analysis::pe::entrypoints::find_pe_entrypoint(&pe)?;
        assert_eq!(1, fns.len());

        Ok(())
    }
}
