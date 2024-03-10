#![allow(clippy::nonstandard_macro_braces)] // clippy bug, see https://github.com/rust-lang/rust-clippy/issues/7434

/// > Table-based exception handling requires a table entry for all functions
/// > that allocate stack space or call another function (for example, nonleaf
/// > functions). The RUNTIME_FUNCTION structure must be DWORD aligned in
/// > memory. All addresses are image relative, that is, they're 32-bit offsets
/// > from the starting address of the image that contains the function table
/// > entry. These entries are sorted, and put in the .pdata section of a PE32+
/// > image.
///
/// ref: https://docs.microsoft.com/en-us/cpp/build/exception-handling-x64
/// ref: https://stackoverflow.com/questions/19808172/struct-runtime-function
use anyhow::Result;
use log::debug;
use thiserror::Error;

use crate::{
    arch::Arch,
    aspace::AddressSpace,
    loader::{pe, pe::PE},
    module::Permissions,
    RVA, VA,
};
use byteorder::ByteOrder;

#[derive(Debug, Error)]
pub enum RuntimeFunctionError {
    #[error("Invalid RUNTIME_FUNCTION")]
    InvalidRuntimeFunction,
    #[error("Unsupported UNWIND_INFO version")]
    UnsupportedUnwindInfoVersion,
    #[error("Invalid UNWIND_INFO")]
    InvalidUnwindInfo,
}

#[allow(dead_code)]
enum UnwindInfoData {
    ExceptionHandler { rva: RVA },
    ChainedUnwindInfo(RuntimeFunction),
}

#[allow(dead_code)]
struct UnwindInfo {
    version:               u8,
    flags:                 u8,
    prologue_size:         u8,
    code_count:            u8,
    frame_register:        u8,
    frame_register_offset: u8,
    unwind_codes:          Vec<u16>,
    data:                  UnwindInfoData,
}

#[allow(dead_code)]
struct RuntimeFunction {
    function_start:      VA,
    function_end:        VA,
    unwind_info_address: VA,
}

/// Read the RUNTIME_FUNCTION structure at the given address,
/// validate it, and return it.
fn read_runtime_function(pe: &PE, offset: VA) -> Result<Option<RuntimeFunction>> {
    let function_start = pe.module.address_space.read_u32(offset)? as RVA;
    let function_end = pe.module.address_space.read_u32(offset + 4)? as RVA;
    let unwind_info_rva = pe.module.address_space.read_u32(offset + 8)? as RVA;

    if function_start == 0x0 || function_end == 0x0 || unwind_info_rva == 0x0 {
        return Ok(None);
    }

    if !pe.module.probe_rva(function_start, Permissions::X) {
        return Err(RuntimeFunctionError::InvalidRuntimeFunction.into());
    }

    if !pe.module.probe_rva(unwind_info_rva, Permissions::R) {
        return Err(RuntimeFunctionError::InvalidRuntimeFunction.into());
    }

    let base_address = pe.module.address_space.base_address;

    Ok(Some(RuntimeFunction {
        function_start:      base_address + function_start,
        function_end:        base_address + function_end,
        unwind_info_address: base_address + unwind_info_rva,
    }))
}

fn read_unwind_info(pe: &PE, offset: VA) -> Result<UnwindInfo> {
    let hdr = pe.module.address_space.read_bytes(offset, 4)?;
    let version = hdr[0] & 0b0000_0111;
    let flags = (hdr[0] & 0b1111_1000) >> 3;

    // version 2 is not documented by microsoft,
    // but referenced and explained here:
    // https://sourceware.org/legacy-ml/gdb-patches/2013-12/msg00097.html
    if version != 0x1 && version != 0x2 {
        return Err(RuntimeFunctionError::UnsupportedUnwindInfoVersion.into());
    }

    let prologue_size = hdr[1];
    let code_count = hdr[2];
    let frame_register = hdr[3] & 0b0000_1111;
    let frame_register_offset = (hdr[3] & 0b1111_0000) >> 4;

    let unwind_codes = pe
        .module
        .address_space
        .read_bytes(offset + 4, 2 * code_count as usize)?
        .windows(2)
        .map(byteorder::LittleEndian::read_u16)
        .collect();

    // https://docs.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-rtlvirtualunwind
    const UNW_FLAG_CHAININFO: u8 = 0x4;

    let data_address = offset + 4 + 2 * code_count as RVA;
    let data = if flags == UNW_FLAG_CHAININFO {
        // > If the UNW_FLAG_CHAININFO flag is set,
        // > then an unwind info structure is a secondary one,
        // > and the shared exception-handler/chained-info
        // > address field contains the primary unwind information.
        //
        // > An UNWIND_INFO item that has UNW_FLAG_CHAININFO set
        // > can contain a RUNTIME_FUNCTION entry whose UNWIND_INFO
        // > item also has UNW_FLAG_CHAININFO set, sometimes called
        // > multiple shrink-wrapping. Eventually, the chained
        // > unwind info pointers arrive at an UNWIND_INFO item that
        // > has UNW_FLAG_CHAININFO cleared. This item is the
        // > primary UNWIND_INFO item, which points to the actual
        // > procedure entry point.
        //
        // https://docs.microsoft.com/en-us/cpp/build/exception-handling-x64?view=vs-2019#chained-unwind-info-structures
        match read_runtime_function(pe, data_address)? {
            Some(runtime_function) => UnwindInfoData::ChainedUnwindInfo(runtime_function),
            None => return Err(RuntimeFunctionError::InvalidUnwindInfo.into()),
        }
    } else {
        UnwindInfoData::ExceptionHandler {
            rva: pe.module.address_space.read_u32(data_address)? as RVA,
        }
    };

    Ok(UnwindInfo {
        version,
        flags,
        prologue_size,
        code_count,
        frame_register,
        frame_register_offset,
        unwind_codes,
        data,
    })
}

pub fn find_pe_runtime_functions(pe: &PE) -> Result<Vec<VA>> {
    let mut ret = vec![];

    if !matches!(pe.module.arch, Arch::X64) {
        return Ok(ret);
    }

    if let Ok(Some(exception_directory)) = pe.get_data_directory(pe::IMAGE_DIRECTORY_ENTRY_EXCEPTION) {
        #[allow(non_upper_case_globals)]
        const sizeof_RUNTIME_FUNCTION: usize = 4 * 3;

        for va in (exception_directory.address..exception_directory.address + exception_directory.size)
            .step_by(sizeof_RUNTIME_FUNCTION)
        {
            if let Some(runtime_function) = read_runtime_function(pe, va)? {
                debug!("pdata: found RUNTIME_FUNCTION@{:#x}", va);
                let mut unwind_info = read_unwind_info(pe, runtime_function.unwind_info_address)?;

                debug!(
                    "pdata: RUNTIME_FUNCTION@{:#x} with UNWIND_INFO@{:#x}",
                    va, runtime_function.unwind_info_address
                );

                // if the UNWIND_INFO is chained,
                // keep following it until it reaches the "primary entry".
                let mut function_start = runtime_function.function_start;
                let mut unwind_info_address = runtime_function.unwind_info_address;
                while let UnwindInfoData::ChainedUnwindInfo(runtime_function) = unwind_info.data {
                    debug!(
                        "pdata: UNWIND_INFO@{:#x} chained to {:#x}",
                        unwind_info_address, runtime_function.unwind_info_address
                    );

                    unwind_info = read_unwind_info(pe, runtime_function.unwind_info_address)?;

                    function_start = runtime_function.function_start;
                    unwind_info_address = runtime_function.unwind_info_address
                }

                if !pe.module.probe_va(function_start, Permissions::X) {
                    return Err(RuntimeFunctionError::InvalidRuntimeFunction.into());
                }

                debug!(
                    "pdata: RUNTIME_FUNCTION@{:#x} points to function {:#x}",
                    va, function_start
                );

                ret.push(function_start);
            } else {
                // just read an entry filled with zeros.
                // assume this means we reached the end of the table.
                break;
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

        let fns = crate::analysis::pe::runtime_functions::find_pe_runtime_functions(&pe)?;
        assert_eq!(1800, fns.len());

        assert_eq!(fns[0], 0x180001010);

        Ok(())
    }

    #[test]
    fn tiny() -> Result<()> {
        let buf = get_buf(Rsrc::TINY);
        let pe = crate::loader::pe::PE::from_bytes(&buf)?;

        let fns = crate::analysis::pe::runtime_functions::find_pe_runtime_functions(&pe)?;
        assert_eq!(0, fns.len());

        Ok(())
    }

    #[test]
    fn nop() -> Result<()> {
        let buf = get_buf(Rsrc::NOP);
        let pe = crate::loader::pe::PE::from_bytes(&buf)?;

        let fns = crate::analysis::pe::runtime_functions::find_pe_runtime_functions(&pe)?;
        assert_eq!(0, fns.len());

        Ok(())
    }

    #[test]
    fn mimi() -> Result<()> {
        let buf = get_buf(Rsrc::MIMI);
        let pe = crate::loader::pe::PE::from_bytes(&buf)?;

        let fns = crate::analysis::pe::runtime_functions::find_pe_runtime_functions(&pe)?;
        assert_eq!(0, fns.len());

        Ok(())
    }
}
