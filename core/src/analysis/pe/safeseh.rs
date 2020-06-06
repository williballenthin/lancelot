//! Parse the PE SafeSEH table for references to valid exception handler functions.
//!
//! This table referenced by the Load Config directory.
//! The reference consists of: (offset: VA, count: u32/u64).
//! The table is simply an array of RVAs to function start addresses.
//!
//! Therefore, we can follow the table reference and walk the array, pulling out functions.
//!
//! Bail if the table reference, table, or any of its entries don't make sense.
//!
//! references:
//!   - https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_load_config_directory32
//!   - https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_load_config_directory64

use anyhow::Result;
use log::debug;

use crate::aspace::AddressSpace;
use crate::loader::pe::PE;
use crate::module::Arch;
use crate::{RVA, VA};

pub fn find_pe_safeseh_handlers(pe: &PE) -> Result<Vec<VA>> {
    let mut ret = vec![];

    let executable_sections = pe.get_pe_executable_sections()?;
    let is_valid_target =
        |target: VA| -> bool { executable_sections.iter().find(|&sec| sec.contains(&target)).is_some() };

    let load_config_directory_rva: RVA = {
        let opt_header = match pe.pe.header.optional_header {
            Some(opt_header) => opt_header,
            _ => return Ok(ret),
        };

        let load_config_directory = match opt_header.data_directories.get_load_config_table() {
            Some(load_config_directory) => load_config_directory,
            _ => return Ok(ret),
        };

        load_config_directory.virtual_address as RVA
    };

    debug!(
        "load config directory: {:#x}",
        pe.module.address_space.base_address + load_config_directory_rva
    );

    // offsets defined here:
    // https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#load-configuration-directory

    // according to IDA, the first DWORD is `Size` not `Characteristics` (unused).
    let size = pe.module.address_space.relative.read_u32(load_config_directory_rva)?;

    // max offset into the config directory that we'll read.
    let max_config_directory_offset = match pe.module.arch {
        // CFG flags
        Arch::X32 => 0x48,
        Arch::X64 => 0x70,
    };

    if max_config_directory_offset > size {
        debug!("no SafeSEH table: load config directory too small");
        return Ok(ret);
    }

    let sehandler_table_va: VA = match pe.module.arch {
        Arch::X32 => pe.module.read_va_at_rva(load_config_directory_rva + 0x40)?,
        Arch::X64 => pe.module.read_va_at_rva(load_config_directory_rva + 0x60)?,
    };
    if sehandler_table_va == 0 {
        debug!("SafeSEH table empty");
        return Ok(ret);
    };
    debug!("SafeSEH table: {:#x}", sehandler_table_va);

    let sehandler_table_count = match pe.module.arch {
        Arch::X32 => pe
            .module
            .address_space
            .relative
            .read_u32(load_config_directory_rva + 0x44)? as u64,
        Arch::X64 => pe
            .module
            .address_space
            .relative
            .read_u64(load_config_directory_rva + 0x68)? as u64,
    };
    debug!("SafeSEH table count: {:#x}", sehandler_table_count);

    let mut offset = sehandler_table_va;
    for _ in 0..sehandler_table_count {
        let target = pe.module.read_rva_at_va(offset)?;
        let target = target as u64 + pe.module.address_space.base_address;

        if is_valid_target(target) {
            ret.push(target);
        } else {
            debug!("unexpected non-executable SafeSEH target: {:#x}", target);
            break;
        }
        offset = offset + pe.module.arch.pointer_size() as u64
    }

    Ok(ret)
}

#[cfg(test)]
mod tests {
    use crate::aspace::AddressSpace;
    use crate::rsrc::*;
    use anyhow::Result;

    #[test]
    fn k32() -> Result<()> {
        let buf = get_buf(Rsrc::K32);
        let pe = crate::loader::pe::load_pe(&buf)?;

        let fns = crate::analysis::pe::safeseh::find_pe_safeseh_handlers(&pe)?;
        assert_eq!(0, fns.len());

        Ok(())
    }

    #[test]
    fn tiny() -> Result<()> {
        let buf = get_buf(Rsrc::TINY);
        let pe = crate::loader::pe::load_pe(&buf)?;

        // no optional header
        assert!(crate::analysis::pe::call_targets::find_pe_call_targets(&pe).is_err());

        Ok(())
    }

    #[test]
    fn nop() -> Result<()> {
        let buf = get_buf(Rsrc::NOP);
        let pe = crate::loader::pe::load_pe(&buf)?;

        let fns = crate::analysis::pe::safeseh::find_pe_safeseh_handlers(&pe)?;
        assert_eq!(2, fns.len());

        Ok(())
    }

    #[test]
    fn mimi() -> Result<()> {
        let buf = get_buf(Rsrc::MIMI);
        let pe = crate::loader::pe::load_pe(&buf)?;

        let fns = crate::analysis::pe::safeseh::find_pe_safeseh_handlers(&pe)?;
        assert_eq!(0, fns.len());

        Ok(())
    }
}
