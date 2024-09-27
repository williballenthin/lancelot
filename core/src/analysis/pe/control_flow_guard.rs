//! Parse the PE Control Flow Guard function table.
//!
//! This table contains an entry for each function that may be invoked
//! dynamically. When present, it tends to cover a large percentage of the
//! functions in a module.
//!
//! This table referenced by the Load Config directory.
//! The reference consists of: (flags: u32, offset: VA, count: u32/u64).
//! The table is an array of entries that consist of:
//!   u32       RVA (both x32 and x64)
//!   variable  data
//! The flags in the table reference describe how big the entry data is (the
//! "stride").
//!
//! The Load Config Control Flow Guard metadata also references:
//!   - function pointer to indirect call check routine (supported)
//!   - function pointer to indirect call dispatch routine (supported)
//!   - IAT entry table (not supported here)
//!   - LongJump entry table (not supported here)
//!
//! references:
//!   - https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#load-configuration-directory
//!   - https://lucasg.github.io/2017/02/05/Control-Flow-Guard/

use anyhow::Result;
use byteorder::{ByteOrder, LittleEndian};
use log::debug;

use crate::{
    arch::Arch,
    aspace::AddressSpace,
    loader::{pe, pe::PE},
    module::Permissions,
    VA,
};

const IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK: u32 = 0xF000_0000;
const IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT: u32 = 28;
const IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT: u32 = 0x400;

pub fn find_pe_cfguard_functions(pe: &PE) -> Result<Vec<VA>> {
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
            Arch::X32 => 0x58,
            Arch::X64 => 0x94,
        };

        // in `d3d11sdklayers.dll` for example, the config size is 0x70,
        // which is much too small to read the CFG table options.
        if max_config_directory_offset > size {
            debug!("no CF Guard table: load config directory too small");
            return Ok(vec![]);
        }

        let load_config = pe.module.address_space.slice(load_config_directory.address)?;

        let cfg_flags: u32 = match pe.module.arch {
            Arch::X32 => load_config.read_u32(0x58)?,
            Arch::X64 => load_config.read_u32(0x90)?,
        };
        debug!("CF guard flags: {:#x}", cfg_flags);

        if cfg_flags & IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT > 0 {
            let stride = ((cfg_flags & IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK)
                >> IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT) as usize;
            if stride > 8 {
                // stride should really be 1, but we'll accept up to 8 for future compatibility.
                debug!("unexpected CF guard stride: {:#x}", stride);
                return Ok(vec![]);
            }

            let cfg_table_va: VA = match pe.module.arch {
                Arch::X32 => load_config.read_pointer(pe.module.arch, 0x50)?,
                Arch::X64 => load_config.read_pointer(pe.module.arch, 0x80)?,
            };
            if cfg_table_va == 0 {
                debug!("CF guard table empty");
                return Ok(vec![]);
            };
            debug!("CF Guard table: {:#x}", cfg_table_va);

            let cfg_table_count = match pe.module.arch {
                Arch::X32 => load_config.read_u32(0x54)? as u64,
                Arch::X64 => load_config.read_u64(0x88)?,
            };
            debug!("CF Guard table count: {:#x}", cfg_table_count);

            // read the table buffer once up front, then iterate slices over it with
            // windows. this is at the expense of one allocation for the table.
            // it be faster than doing pe.module.with_va().read_i32() on each offset, on
            // large tables.
            //
            // 4 == sizeof(i32) RVA to function start, both x32 and x64
            let cfg_table_entry_size: usize = 4 + stride;
            let cfg_table = pe
                .module
                .address_space
                .read_bytes(cfg_table_va, cfg_table_count as usize * cfg_table_entry_size);
            let cfg_table = match cfg_table {
                Ok(cfg_table) => cfg_table,
                Err(_) => {
                    debug!("failed to read CF Guard table");
                    return Ok(vec![]);
                }
            };

            for entry_buf in cfg_table.chunks_exact(cfg_table_entry_size) {
                let target = pe.module.address_space.base_address + LittleEndian::read_i32(entry_buf) as u64;

                if pe.module.probe_va(target, Permissions::X) {
                    ret.push(target);
                } else {
                    debug!("unexpected non-executable CFG target: {:#x}", target);
                    break;
                }
            }

            // add function pointed to by GuardCFCheckFunctionPointer
            let guard_check_icall_fptr: VA = match pe.module.arch {
                Arch::X32 => load_config.read_pointer(pe.module.arch, 0x48)?,
                Arch::X64 => load_config.read_pointer(pe.module.arch, 0x70)?,
            };
            if guard_check_icall_fptr != 0 {
                debug!(
                    "CF Guard check indirect call function pointer: {:#x}",
                    guard_check_icall_fptr
                );

                if let Ok(guard_check_icall) = pe.module.read_va_at_va(guard_check_icall_fptr) {
                    if pe.module.probe_va(guard_check_icall, Permissions::X) {
                        debug!("CF Guard check icall: {:#x}", guard_check_icall);
                        ret.push(guard_check_icall);
                    }
                }
            }

            // add function pointed to by GuardCFDispatchFunctionPointer
            //
            // set to 0x0 when not used, as is often the case on 32-bit Windows DLLs.
            let guard_dispatch_icall_fptr: VA = match pe.module.arch {
                Arch::X32 => load_config.read_pointer(pe.module.arch, 0x4C)?,
                Arch::X64 => load_config.read_pointer(pe.module.arch, 0x78)?,
            };
            if guard_dispatch_icall_fptr != 0 {
                debug!(
                    "CF Guard dispatch indirect call function pointer: {:#x}",
                    guard_dispatch_icall_fptr
                );

                if let Ok(guard_dispatch_icall) = pe.module.read_va_at_va(guard_dispatch_icall_fptr) {
                    if pe.module.probe_va(guard_dispatch_icall, Permissions::X) {
                        debug!("CF Guard dispatch icall: {:#x}", guard_dispatch_icall);
                        ret.push(guard_dispatch_icall);
                    }
                }
            }
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

        let fns = crate::analysis::pe::control_flow_guard::find_pe_cfguard_functions(&pe)?;
        assert_eq!(1502, fns.len());

        Ok(())
    }

    #[test]
    fn tiny() -> Result<()> {
        let buf = get_buf(Rsrc::TINY);
        let pe = crate::loader::pe::PE::from_bytes(&buf)?;

        let fns = crate::analysis::pe::control_flow_guard::find_pe_cfguard_functions(&pe)?;
        assert_eq!(0, fns.len());

        Ok(())
    }

    #[test]
    fn nop() -> Result<()> {
        let buf = get_buf(Rsrc::NOP);
        let pe = crate::loader::pe::PE::from_bytes(&buf)?;

        let fns = crate::analysis::pe::control_flow_guard::find_pe_cfguard_functions(&pe)?;
        assert_eq!(0, fns.len());

        Ok(())
    }

    #[test]
    fn mimi() -> Result<()> {
        let buf = get_buf(Rsrc::MIMI);
        let pe = crate::loader::pe::PE::from_bytes(&buf)?;

        let fns = crate::analysis::pe::control_flow_guard::find_pe_cfguard_functions(&pe)?;
        assert_eq!(0, fns.len());

        Ok(())
    }
}
