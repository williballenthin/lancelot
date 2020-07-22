use anyhow::Result;
use bitflags::bitflags;
use thiserror::Error;

use crate::{
    aspace::{AbsoluteAddressSpace, AddressSpace},
    pagemap::PageMapError::NotMapped,
    RVA, VA,
};

#[derive(Error, Debug)]
pub enum ModuleError {
    #[error("invalid address: {0:#x}")]
    InvalidAddress(u64),
}

#[derive(Copy, Clone, Debug)]
pub enum Arch {
    X32,
    X64,
}

impl Arch {
    pub fn pointer_size(&self) -> usize {
        match self {
            Arch::X32 => 4,
            Arch::X64 => 8,
        }
    }
}

bitflags! {
    pub struct Permissions: u8 {
        const R = 0b0000_0001;
        const W = 0b0000_0010;
        const X = 0b0000_0100;
        const RW = Self::R.bits | Self::W.bits;
        const RX =  Self::R.bits | Self::X.bits;
        const WX =  Self::W.bits | Self::X.bits;
        const RWX =  Self::R.bits | Self::W.bits | Self::X.bits;
    }
}

#[derive(Debug, Clone)]
pub struct Section {
    // source data, from the PE file, relative to file start.
    pub physical_range: std::ops::Range<RVA>,
    // as mapped into memory with absolute addresses.
    pub virtual_range:  std::ops::Range<VA>,
    pub perms:          Permissions,
    pub name:           String,
}

/// An address space, as a file would be loaded into memory.
/// This has an associated architecture (e.g. x32 or x64),
/// base address, and collection of sections.
/// This is the information that we'd expect to be common across formats.
#[derive(Clone)]
pub struct Module {
    pub arch:          Arch,
    pub sections:      Vec<Section>,
    pub address_space: AbsoluteAddressSpace,
}

impl Module {
    pub fn read_va_at_rva(&self, offset: RVA) -> Result<VA> {
        match self.arch {
            Arch::X32 => Ok(self.address_space.relative.read_u32(offset)? as VA),
            Arch::X64 => Ok(self.address_space.relative.read_u64(offset)? as VA),
        }
    }

    pub fn read_rva_at_rva(&self, offset: RVA) -> Result<RVA> {
        match self.arch {
            Arch::X32 => Ok(self.address_space.relative.read_u32(offset)? as RVA),
            Arch::X64 => Ok(self.address_space.relative.read_u64(offset)? as RVA),
        }
    }

    pub fn read_va_at_va(&self, offset: VA) -> Result<VA> {
        match self.arch {
            Arch::X32 => Ok(self.address_space.read_u32(offset)? as VA),
            Arch::X64 => Ok(self.address_space.read_u64(offset)? as VA),
        }
    }

    pub fn read_rva_at_va(&self, offset: VA) -> Result<RVA> {
        match self.arch {
            Arch::X32 => Ok(self.address_space.read_u32(offset)? as RVA),
            Arch::X64 => Ok(self.address_space.read_u64(offset)? as RVA),
        }
    }

    pub fn probe_va(&self, offset: VA, perm: Permissions) -> bool {
        self.sections
            .iter()
            .any(|section| section.virtual_range.contains(&offset) && section.perms.intersects(perm))
    }

    pub fn probe_rva(&self, offset: RVA, perm: Permissions) -> bool {
        let va = self.address_space.base_address + offset;
        self.probe_va(va, perm)
    }

    pub fn file_offset(&self, va: VA) -> Result<usize> {
        if let Some(sec) = self.sections.iter().find(|&sec| sec.virtual_range.contains(&va)) {
            let offset = va - sec.virtual_range.start;
            Ok((offset + sec.physical_range.start) as usize)
        } else {
            Err(NotMapped.into())
        }
    }

    pub fn virtual_address(&self, file_offset: u64) -> Result<VA> {
        self.sections
            .iter()
            .find(|&sec| sec.physical_range.contains(&(file_offset as u64)))
            .map(|sec| {
                let section_offset = file_offset as u64 - sec.physical_range.start;
                sec.virtual_range.start + section_offset
            })
            .ok_or(NotMapped.into())
    }
}
