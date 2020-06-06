use anyhow::Result;
use bitflags::bitflags;
use thiserror::Error;

use crate::aspace::AddressSpace;
use crate::{aspace::AbsoluteAddressSpace, RVA, VA};

#[derive(Error, Debug)]
pub enum ModuleError {
    #[error("invalid address: {0:#x}")]
    InvalidAddress(u64),
}

#[derive(Copy, Clone)]
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

#[derive(Debug)]
pub struct Section {
    // source data, from the PE file, relative to file start.
    pub physical_range: std::ops::Range<RVA>,
    // as mapped into memory, relative to load address.
    pub virtual_range: std::ops::Range<RVA>,
    pub perms: Permissions,
    pub name: String,
}

/// An address space, as a file would be loaded into memory.
/// This has an associated architecture (e.g. x32 or x64),
/// base address, and collection of sections.
/// This is the information that we'd expect to be common across formats.
pub struct Module {
    pub arch: Arch,
    pub sections: Vec<Section>,
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
}
