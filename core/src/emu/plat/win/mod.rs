use std::collections::BTreeMap;

use anyhow::Result;
use log::debug;

use crate::{arch::Arch, emu::Emulator, loader::pe::PE, RVA, VA};

pub mod api;
pub mod win32;
pub mod win64;

pub fn link_imports(emu: &mut Emulator, pe: &PE) -> Result<BTreeMap<VA, String>> {
    use crate::loader::pe::imports::*;

    // for a call to an import,
    // the compiler will emit something like `call ds:[0x406008]`
    // where 0x406008 is the first thunk (FT)/IAT entry.
    // so, it contains a pointer to the function implementation.
    //
    // the windows loader will have updated this pointer as it resolved imports.
    // it now points to the address space of some other module.
    //
    // on disk, this entry will typically mirror the original first thunk (OFT)
    // entry, which contains either:
    //   - an ordinal, or
    //   - an ordinal hint and pointer to symbol name
    //
    // as we load our emulator, we'll set the FT entry to point to the OFT entry
    // address. then we can catch invalid fetches and resolve which API was
    // being called.

    let base_address = pe.module.address_space.base_address;
    let psize = pe.module.arch.pointer_size();

    let mut imports: BTreeMap<VA, String> = Default::default();

    if let Some(import_directory) = get_import_directory(pe)? {
        for import_descriptor in read_import_descriptors(pe, import_directory) {
            let dll = import_descriptor.read_name(pe)?.to_lowercase();
            let original_thunk_array = base_address + import_descriptor.original_first_thunk;
            let first_thunk_array = base_address + import_descriptor.first_thunk;

            for i in 0..usize::MAX {
                let first_thunk_addr = first_thunk_array + (i * psize) as RVA;
                let thunk = read_image_thunk_data(pe, first_thunk_addr);
                if matches!(thunk, Err(_) | Ok(IMAGE_THUNK_DATA::Function(0x0))) {
                    break;
                }

                let original_thunk_addr = original_thunk_array + (i * psize) as RVA;

                let name = match read_image_thunk_data(pe, original_thunk_addr)? {
                    IMAGE_THUNK_DATA::Ordinal(n) => format!("{dll}!#{n}"),
                    IMAGE_THUNK_DATA::Function(rva) => {
                        read_image_import_by_name(pe, pe.module.address_space.base_address + rva)?.name
                    }
                };
                debug!("emu: plat: win: link import {original_thunk_addr:#x} -> {dll}!{name} ");
                imports.insert(original_thunk_addr, format!("{dll}!{name}"));

                match pe.module.arch {
                    Arch::X32 => {
                        emu.mem.poke_u32(first_thunk_addr, original_thunk_addr as u32)?;
                    }
                    Arch::X64 => {
                        emu.mem.poke_u64(first_thunk_addr, original_thunk_addr)?;
                    }
                }
            }
        }
    }

    Ok(imports)
}

pub trait WindowsEmulator {
    fn load_pe(&mut self, pe: &PE) -> Result<()>;

    fn mem(&mut self) -> &mut crate::emu::mmu::MMU;

    fn set_pc(&mut self, addr: VA);

    fn pc(&self) -> VA;

    fn set_sp(&mut self, addr: VA);

    fn sp(&self) -> VA;

    /// push an arch-width value onto the stack.
    /// truncates if the given value is too big.
    ///
    /// Errors:
    ///   - WriteError::AddressNotMapped when stack is not mapped.
    ///   - WriteError::AccessViolation when stack is not writable.
    fn push(&mut self, value: u64) -> Result<()>;

    /// pops an arch-width value from the stack.
    /// extends the value to u64, if its smaller (e.g. u32).
    ///
    /// Errors:
    ///   - ReadError::AddressNotMapped when stack is not mapped.
    ///   - ReadError::AccessViolation when stack is not readable.
    fn pop(&mut self) -> Result<u64>;

    fn set_bp(&mut self, addr: VA);

    fn bp(&self) -> VA;

    fn set_fsbase(&mut self, addr: VA);

    // TODO: sketching this out
    fn resolve_address(&self, addr: VA) -> Option<String>;
}
