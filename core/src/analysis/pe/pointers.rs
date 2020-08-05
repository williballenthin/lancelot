//! Scan the file looking for pointer-sized values that fall within an
//! executable section. Then, step backwards and ensure that the target
//! looks like either:
//!
//!   1. the end of a function, or
//!   2. filler between functions
//!
//! This analysis pass should be particularly useful for finding callbacks,
//! such as the start address passed to `CreateThread`.
//!
//! TODO: but doesn't help find callbacks referenced relatively - need
//! disassembly for this.
//!
//! This analysis pass is also good at handling global vtables.
//! Its especially important when CFGuard metadata is not present.
//!
//! Assumes:
//!   - pointers are 32-bits on x32 and 64-bits on x64 (*not* 32-bits on x64)

use anyhow::Result;
use byteorder::ByteOrder;

use crate::{aspace::AddressSpace, loader::pe::PE, module::Permissions, VA};

pub fn find_pe_nonrelocated_executable_pointers(pe: &PE) -> Result<Vec<VA>> {
    let mut candidates: Vec<VA> = vec![];

    // look for hardcoded pointers into the executable section of the PE.
    // note: this often finds jump tables, too. more filtering is below.
    // note: also finds many exception handlers. see filtering below.
    // TODO: within code, global pointers may not be pointer-aligned?
    for section in pe.module.sections.iter() {
        let vstart: VA = section.virtual_range.start;
        let vsize = (section.virtual_range.end - section.virtual_range.start) as usize;
        let sec_buf = pe.module.address_space.read_buf(vstart, vsize)?;

        if pe.pe.header.coff_header.machine == goblin::pe::header::COFF_MACHINE_X86_64 {
            candidates.extend(
                sec_buf
                    .windows(8)
                    .map(|b| byteorder::LittleEndian::read_u64(b) as VA)
                    .filter(|&va| pe.module.probe_va(va, Permissions::X)),
            )
        } else {
            candidates.extend(
                sec_buf
                    .windows(4)
                    .map(|b| byteorder::LittleEndian::read_u32(b) as VA)
                    .filter(|&va| pe.module.probe_va(va, Permissions::X)),
            )
        }
    }

    // CC debug filler, x86win_patterns.xml#L4
    const CC: u8 = 0xCC;
    // NOP filler, x86win_patterns.xml#L6
    const NOP: u8 = 0x90;
    // RET(N) of prior function, x86win_patterns.xml#L7
    const RET: u8 = 0xC3;

    // now, assert that the prior byte must be a either a RET or filler byte.
    // this should filter out almost all jump tables, etc.
    // should also filter out almost all exception handlers, too.
    Ok(candidates
        .into_iter()
        .filter(|&va| {
            if let Ok(b) = pe.module.address_space.read_u8(va - 1) {
                matches!(b, CC | NOP | RET)
            } else {
                false
            }
        })
        .collect())
}
