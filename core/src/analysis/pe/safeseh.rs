//! Parse the PE SafeSEH table for references to valid exception handler
//! functions.
//!
//! This table referenced by the Load Config directory.
//! The reference consists of: (offset: VA, count: u32/u64).
//! The table is simply an array of RVAs to function start addresses.
//!
//! Therefore, we can follow the table reference and walk the array, pulling out
//! functions.
//!
//! Bail if the table reference, table, or any of its entries don't make sense.
//!
//! references:
//!   - https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_load_config_directory32
//!   - https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_load_config_directory64

use anyhow::Result;
use log::debug;

use crate::{
    arch::Arch,
    aspace::AddressSpace,
    loader::{pe, pe::PE},
    module::Permissions,
    VA,
};

pub fn find_pe_safeseh_handlers(pe: &PE) -> Result<Vec<VA>> {
    let mut ret = vec![];

    if let Ok(Some(load_config_directory)) = pe.get_data_directory(pe::IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG) {
        debug!("load config directory: {:#x}", load_config_directory.address);

        // offsets defined here:
        // https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#load-configuration-directory

        // according to IDA, the first DWORD is `Size` not `Characteristics` (unused).
        let size = pe.module.address_space.read_u32(load_config_directory.address)?;

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
            Arch::X32 => pe.module.read_va_at_va(load_config_directory.address + 0x40)?,
            Arch::X64 => pe.module.read_va_at_va(load_config_directory.address + 0x60)?,
        };
        if sehandler_table_va == 0 {
            debug!("SafeSEH table empty");
            return Ok(ret);
        };
        debug!("SafeSEH table: {:#x}", sehandler_table_va);

        let sehandler_table_count = match pe.module.arch {
            Arch::X32 => pe.module.address_space.read_u32(load_config_directory.address + 0x44)? as u64,
            Arch::X64 => pe.module.address_space.read_u64(load_config_directory.address + 0x68)?,
        };
        debug!("SafeSEH table count: {:#x}", sehandler_table_count);

        let mut offset = sehandler_table_va;
        for _ in 0..sehandler_table_count {
            let target = match pe.module.read_rva_at_va(offset) {
                Ok(target) => target,
                Err(_) => {
                    debug!("failed to read SafeSEH table entry: {:#x}", offset);
                    break;
                }
            };
            let target = target + pe.module.address_space.base_address;

            if pe.module.probe_va(target, Permissions::X) {
                ret.push(target);
            } else {
                debug!("unexpected non-executable SafeSEH target: {:#x}", target);
                break;
            }
            offset += pe.module.arch.pointer_size() as u64
        }
    }

    Ok(ret)
}

#[cfg(test)]
mod tests {
    use crate::rsrc::*;
    use anyhow::Result;

    #[test]
    fn k32() -> Result<()> {
        let buf = get_buf(Rsrc::K32);
        let pe = crate::loader::pe::PE::from_bytes(&buf)?;

        let fns = crate::analysis::pe::safeseh::find_pe_safeseh_handlers(&pe)?;
        assert_eq!(0, fns.len());

        Ok(())
    }

    #[test]
    fn tiny() -> Result<()> {
        let buf = get_buf(Rsrc::TINY);
        let pe = crate::loader::pe::PE::from_bytes(&buf)?;

        let fns = crate::analysis::pe::safeseh::find_pe_safeseh_handlers(&pe)?;
        assert_eq!(0, fns.len());

        Ok(())
    }

    #[test]
    fn nop() -> Result<()> {
        let buf = get_buf(Rsrc::NOP);
        let pe = crate::loader::pe::PE::from_bytes(&buf)?;

        let fns = crate::analysis::pe::safeseh::find_pe_safeseh_handlers(&pe)?;
        assert_eq!(2, fns.len());

        Ok(())
    }

    #[test]
    fn mimi() -> Result<()> {
        let buf = get_buf(Rsrc::MIMI);
        let pe = crate::loader::pe::PE::from_bytes(&buf)?;

        let fns = crate::analysis::pe::safeseh::find_pe_safeseh_handlers(&pe)?;
        assert_eq!(0, fns.len());

        Ok(())
    }
}
