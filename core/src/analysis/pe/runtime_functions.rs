/// > Table-based exception handling requires a table entry for all functions
/// >  that allocate stack space or call another function (for example, nonleaf
/// functions). > The RUNTIME_FUNCTION structure must be DWORD aligned in
/// memory. > All addresses are image relative, that is, they're 32-bit offsets
/// from > the starting address of the image that contains the function table
/// entry. > These entries are sorted, and put in the .pdata section of a PE32+
/// image.
///
/// ref: https://docs.microsoft.com/en-us/cpp/build/exception-handling-x64
/// ref: https://stackoverflow.com/questions/19808172/struct-runtime-function
use anyhow::Result;
use log::debug;

use crate::{
    aspace::AddressSpace,
    loader::pe::PE,
    module::{Arch, Permissions},
    RVA, VA,
};

pub fn find_pe_runtime_functions(pe: &PE) -> Result<Vec<VA>> {
    let mut ret = vec![];

    if !matches!(pe.module.arch, Arch::X64) {
        return Ok(ret);
    }

    let (exception_directory_rva, exception_directory_size) = {
        let opt_header = match pe.header.optional_header {
            Some(opt_header) => opt_header,
            _ => return Ok(ret),
        };

        let exception_directory = match opt_header.data_directories.get_exception_table() {
            Some(exception_directory) => exception_directory,
            _ => return Ok(ret),
        };

        (
            exception_directory.virtual_address as RVA,
            exception_directory.size as RVA,
        )
    };

    debug!(
        "exception directory: {:#x}",
        pe.module.address_space.base_address + exception_directory_rva
    );

    #[allow(non_upper_case_globals)]
    const sizeof_RUNTIME_FUNCTION: usize = 4 * 3;

    for offset in (0..exception_directory_size).step_by(sizeof_RUNTIME_FUNCTION) {
        let function_start = pe
            .module
            .address_space
            .relative
            .read_u32(exception_directory_rva + offset)? as RVA;
        let function_end = pe
            .module
            .address_space
            .relative
            .read_u32(exception_directory_rva + offset + 4)? as RVA;
        let unwind_info = pe
            .module
            .address_space
            .relative
            .read_u32(exception_directory_rva + offset + 8)? as RVA;

        if function_start == 0x0 || function_end == 0x0 || unwind_info == 0x0 {
            break;
        }

        if !pe.module.probe_rva(function_start, Permissions::X) {
            break;
        }

        ret.push(pe.module.address_space.base_address + function_start);
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
