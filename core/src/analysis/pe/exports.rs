//! Parse the PE export table (if present) to find entries in find exports in
//! executable sections.
//!
//! PEs may export data, which we'll assume isn't in an executable section.
use anyhow::Result;
use log::debug;

use crate::{loader::pe::PE, module::Permissions, VA};

pub fn find_pe_exports(pe: &PE) -> Result<Vec<VA>> {
    let base_address = match pe.optional_header {
        Some(opt) => opt.windows_fields.image_base,
        _ => 0x40_0000,
    };

    let exports: Vec<VA> = pe
        .pe()?
        .exports
        .iter()
        // re-exports are simply strings that point to a `DLL.export_name` ASCII string.
        // therefore, they're not functions/code.
        .filter(|&exp| exp.reexport.is_none())
        .map(|exp| base_address + exp.rva as u64)
        .filter(|&va| {
            // PE may export data, so ensure the exports we track are executable
            // (functions).
            pe.module.probe_va(va, Permissions::X)
        })
        .collect();

    for export in exports.iter() {
        debug!("export: {export:#x}");
    }
    if exports.is_empty() {
        debug!("exports: none");
    }

    Ok(exports)
}

#[cfg(test)]
mod tests {
    use crate::rsrc::*;
    use anyhow::Result;

    #[test]
    fn k32() -> Result<()> {
        let buf = get_buf(Rsrc::K32);
        let pe = crate::loader::pe::PE::from_bytes(&buf)?;

        let fns = crate::analysis::pe::exports::find_pe_exports(&pe)?;
        assert_eq!(1445, fns.len());

        Ok(())
    }

    #[test]
    fn tiny() -> Result<()> {
        let buf = get_buf(Rsrc::TINY);
        let pe = crate::loader::pe::PE::from_bytes(&buf)?;

        let fns = crate::analysis::pe::exports::find_pe_exports(&pe)?;
        assert_eq!(0, fns.len());

        Ok(())
    }

    #[test]
    fn nop() -> Result<()> {
        let buf = get_buf(Rsrc::NOP);
        let pe = crate::loader::pe::PE::from_bytes(&buf)?;

        let fns = crate::analysis::pe::exports::find_pe_exports(&pe)?;
        assert_eq!(0, fns.len());

        Ok(())
    }

    #[test]
    fn mimi() -> Result<()> {
        let buf = get_buf(Rsrc::MIMI);
        let pe = crate::loader::pe::PE::from_bytes(&buf)?;

        let fns = crate::analysis::pe::exports::find_pe_exports(&pe)?;
        assert_eq!(0, fns.len());

        Ok(())
    }
}
