// we use identifier names from the C headers for PE structures,
// which don't match the Rust style guide.
// example: `IMAGE_DOS_HEADER`
// don't show compiler warnings when encountering these names.
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

use anyhow::Result;
use byteorder::{ByteOrder, LittleEndian};
use log::debug;
use thiserror::Error;

use crate::{
    aspace::{AddressSpace, WritableAddressSpace},
    loader::pe::PE,
    RVA, VA,
};

#[derive(Debug, Error)]
pub enum RelocError {
    #[error("Buffer is too small")]
    BufferTooSmall,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ImageRelocationType {
    /// The base relocation is skipped. This type can be used to pad a block.
    IMAGE_REL_BASED_ABSOLUTE = 0,
    /// The base relocation adds the high 16 bits of the difference to the
    /// 16-bit field at offset. The 16-bit field represents the high value of a
    /// 32-bit word.
    IMAGE_REL_BASED_HIGH = 1,
    /// The base relocation adds the low 16 bits of the difference to the 16-bit
    /// field at offset. The 16-bit field represents the low half of a 32-bit
    /// word.
    IMAGE_REL_BASED_LOW  = 2,
    /// The base relocation applies all 32 bits of the difference to the 32-bit
    /// field at offset.
    IMAGE_REL_BASED_HIGHLOW = 3,
    /// The base relocation adds the high 16 bits of the difference to the
    /// 16-bit field at offset. The 16-bit field represents the high value of a
    /// 32-bit word. The low 16 bits of the 32-bit value are stored in the
    /// 16-bit word that follows this base relocation. This means that this base
    /// relocation occupies two slots.
    IMAGE_REL_BASED_HIGHADJ = 4,
    /// The base relocation applies the difference to the 64-bit field at
    /// offset.
    IMAGE_REL_BASED_DIR64 = 10,
}

impl From<u16> for ImageRelocationType {
    fn from(value: u16) -> Self {
        match value {
            0 => Self::IMAGE_REL_BASED_ABSOLUTE,
            1 => Self::IMAGE_REL_BASED_HIGH,
            2 => Self::IMAGE_REL_BASED_LOW,
            3 => Self::IMAGE_REL_BASED_HIGHLOW,
            4 => Self::IMAGE_REL_BASED_HIGHADJ,
            10 => Self::IMAGE_REL_BASED_DIR64,

            _ => panic!("Invalid ImageRelocationType value: {}", value),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Relocation {
    type_:   ImageRelocationType,
    address: VA,
}

pub struct RelocSectionData {
    base_address: VA,
    buf:          Vec<u8>,
}

impl RelocSectionData {
    #[allow(clippy::unnecessary_wraps)]
    fn read_u16(&self, offset: usize) -> Result<u16> {
        if offset + 2 > self.buf.len() {
            return Err(RelocError::BufferTooSmall.into());
        }
        let buf = &self.buf[offset..offset + 2];
        Ok(LittleEndian::read_u16(buf))
    }

    #[allow(clippy::unnecessary_wraps)]
    fn read_u32(&self, offset: usize) -> Result<u32> {
        if offset + 4 > self.buf.len() {
            return Err(RelocError::BufferTooSmall.into());
        }
        let buf = &self.buf[offset..offset + 4];
        Ok(LittleEndian::read_u32(buf))
    }

    pub fn relocations(&self) -> Result<Vec<Relocation>> {
        let mut relocations = vec![];
        let mut offset = 0x0;
        while offset < self.buf.len() {
            let rva = self.read_u32(offset)? as u64;
            let size = self.read_u32(offset + 4)? as usize;

            debug!("reloc: block: {rva:x} {size:x}");

            const header_size: usize = 8;
            const entry_size: usize = 2;

            let entry_count = (size - header_size) / entry_size;
            for entry_index in 0..entry_count {
                let entry = self.read_u16(offset + header_size + (entry_index * entry_size))?;

                let entry_type = ImageRelocationType::from(entry >> 12);
                let entry_value = (entry & 0x0FFF) as u64;

                let address = self.base_address + rva + entry_value;
                debug!("reloc: reloc: {address:x} {entry_type:?}");
                relocations.push(Relocation {
                    type_: entry_type,
                    address,
                });
            }

            offset += size;
        }

        Ok(relocations)
    }

    pub fn from_pe(pe: &PE) -> Result<Option<RelocSectionData>> {
        let opt_header = match pe.optional_header {
            None => return Ok(None),
            Some(opt_header) => opt_header,
        };

        let reloc_table = match opt_header.data_directories.get_base_relocation_table() {
            None => return Ok(None),
            Some(reloc_table) => reloc_table,
        };

        debug!(
            "reloc: table at {:#x}-{:#x}",
            pe.module.address_space.base_address + reloc_table.virtual_address as RVA,
            pe.module.address_space.base_address + reloc_table.virtual_address as RVA + reloc_table.size as RVA
        );

        let buf = pe.module.address_space.read_bytes(
            // goblin calls this a "virtual address", but its actually an RVA.
            pe.module.address_space.base_address + reloc_table.virtual_address as RVA,
            reloc_table.size as usize,
        )?;

        Ok(Some(RelocSectionData {
            base_address: pe.module.address_space.base_address,
            buf,
        }))
    }
}

pub fn apply_relocations(pe: &mut PE) -> Result<()> {
    let opt_header = match pe.optional_header {
        None => return Ok(()),
        Some(opt_header) => opt_header,
    };

    let wanted = opt_header.windows_fields.image_base;
    let found = pe.module.address_space.base_address;
    if wanted == found {
        debug!("reloc: no relocations necessary");
        return Ok(());
    }

    let relocations = if let Ok(Some(reloc_data)) = RelocSectionData::from_pe(pe) {
        reloc_data.relocations()?
    } else {
        debug!("reloc: no relocations found");
        return Ok(());
    };

    let delta = (found as i64) - (wanted as i64);

    debug!("reloc: applying {} relocations", relocations.len());

    for relocation in relocations.iter() {
        match relocation.type_ {
            // https://github.com/abhisek/Pe-Loader-Sample/blob/9aed4b3f6cd33ef75a0e01c21ea9f81608bf96cf/src/PeLdr.cpp#L44
            ImageRelocationType::IMAGE_REL_BASED_ABSOLUTE => continue,
            ImageRelocationType::IMAGE_REL_BASED_DIR64 => {
                debug!("reloc: applying DIR64 at {:x}", relocation.address);
                let existing = pe.module.address_space.read_u64(relocation.address)?;
                let updated = existing as i64 + delta;
                pe.module.address_space.write_u64(relocation.address, updated as u64)?;
            }
            ImageRelocationType::IMAGE_REL_BASED_HIGHLOW => {
                let existing = pe.module.address_space.read_u32(relocation.address)?;
                let updated = existing + (delta & 0xFFFF_FFFF) as u32;
                pe.module.address_space.write_u32(relocation.address, updated)?;
            }
            ImageRelocationType::IMAGE_REL_BASED_HIGH => {
                let existing = pe.module.address_space.read_u16(relocation.address)?;
                let updated = existing + (((delta >> 16) & 0xFFFF) as u16);
                pe.module.address_space.write_u16(relocation.address, updated)?;
            }
            ImageRelocationType::IMAGE_REL_BASED_LOW => {
                let existing = pe.module.address_space.read_u16(relocation.address)?;
                let updated = existing + ((delta & 0xFFFF) as u16);
                pe.module.address_space.write_u16(relocation.address, updated)?;
            }
            _ => unimplemented!(),
        };
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::identity_op)]

    use crate::rsrc::*;
    use anyhow::Result;

    #[test]
    fn parse_relocations() -> Result<()> {
        // init_logging();

        let buf = get_buf(Rsrc::CPP1);
        let pe = crate::loader::pe::PE::from_bytes(&buf)?;

        use crate::loader::pe::reloc;
        use log::debug;

        let mut reloc_count = 0;
        if let Ok(Some(reloc_data)) = reloc::RelocSectionData::from_pe(&pe) {
            for relocation in reloc_data.relocations()?.iter() {
                debug!("relocation: {:#?}", relocation);
                reloc_count += 1;
            }
        }

        assert_eq!(reloc_count, 66, "expected some relocations");

        Ok(())
    }

    #[test]
    fn apply_relocations() -> Result<()> {
        // haven't tested a mapping at the non-preferred base address yet.
        Ok(())
    }
}
