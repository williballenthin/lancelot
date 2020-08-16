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
use log::debug;

use crate::{aspace::AddressSpace, loader::pe::PE, module::Permissions, VA};

pub fn find_pe_nonrelocated_executable_pointers(pe: &PE) -> Result<Vec<VA>> {
    let mut candidates: Vec<VA> = vec![];

    let min_addr = pe.module.address_space.base_address;
    let max_addr = pe
        .module
        .sections
        .iter()
        .map(|section| section.virtual_range.end)
        .max()
        .unwrap();

    // look for hardcoded pointers into the executable section of the PE.
    // note: this often finds jump tables, too. more filtering is below.
    // note: also finds many exception handlers. see filtering below.
    for section in pe.module.sections.iter() {
        let vstart: VA = section.virtual_range.start;
        let vsize = (section.virtual_range.end - section.virtual_range.start) as usize;
        let sec_buf = pe.module.address_space.read_bytes(vstart, vsize)?;

        debug!(
            "pointers: scanning section {:#x}-{:#x}",
            section.virtual_range.start, section.virtual_range.end
        );

        if let crate::module::Arch::X64 = pe.module.arch {
            candidates.extend(
                sec_buf
                    // using windows for unaligned pointers
                    .windows(8)
                    .map(|b| byteorder::LittleEndian::read_u64(b) as VA)
                    // naive range filter that is very fast
                    .filter(|&va| va >= min_addr && va < max_addr)
                    .filter(|&va| pe.module.probe_va(va, Permissions::X)),
            )
        } else {
            candidates.extend(
                sec_buf
                    // using windows for unaligned pointers
                    .windows(4)
                    .map(|b| byteorder::LittleEndian::read_u32(b) as VA)
                    // naive range filter that is very fast
                    .filter(|&va| va >= min_addr && va < max_addr)
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
    // should not be an ASCII string (as seen in 32-bit kernel32)
    Ok(candidates
        .into_iter()
        .filter(|&va| {
            if let Ok(b) = pe.module.address_space.read_u8(va - 1) {
                matches!(b, CC | NOP | RET)
            } else {
                false
            }
        })
        .filter(|&va| {
            if let Ok(ptr) = pe.module.read_va_at_va(va) {
                // the candidate is valid pointer, so its probably not an instruction.
                !pe.module.probe_va(ptr, Permissions::R)
            } else {
                true
            }
        })
        .filter(|&va| matches!(pe.module.address_space.read_ascii(va), Err(_)))
        .collect())
}
