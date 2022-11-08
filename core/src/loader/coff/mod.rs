use anyhow::Result;
use log::debug;
use object::{Object, ObjectSection};
use thiserror::Error;

use crate::{
    arch::Arch,
    aspace::RelativeAddressSpace,
    module::{Module, Permissions, Section},
    VA,
};

#[derive(Error, Debug)]
pub enum COFFError {
    #[error("format not supported: {0}")]
    FormatNotSupported(String),

    #[error("malformed COFF file: {0}")]
    MalformedCOFFFile(String),
}

/// A parsed and loaded COFF file.
/// The `buf` field contains the raw data.
/// The `module` field contains an address space as the COFF would be loaded.
pub struct COFF {
    pub buf:    Vec<u8>,
    pub module: Module,
}

impl COFF {
    pub fn from_bytes(buf: &[u8]) -> Result<COFF> {
        load_coff(buf)
    }
}

// TODO:
//   - only load sections that aren't SCN_LNK_REMOVE nor SCN_MEM_DISCARDABLE
//   - place these sections into their own pages
//     - requires map from physical range -> virtual range
//   - apply relocations to link references to symbols/functions

/// The section can be executed as code.
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

/// The section can be read.
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;

/// The section can be written to.
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

/// translate the given COFF section into a section.
/// blindly map the physical address to the virtual address.
fn load_coff_section(base_address: VA, section: &object::read::Section) -> Result<Section> {
    let section_name = String::from_utf8_lossy(&section.name_bytes()?[..]).into_owned();

    let trimmed_name = section_name.trim_end_matches('\u{0}').trim_end();

    let name = trimmed_name
        .split_once('\u{0}')
        .map(|(name, _)| name)
        .unwrap_or_else(|| trimmed_name)
        .to_string();

    let mut perms = Permissions::empty();

    if let object::SectionFlags::Coff { characteristics } = section.flags() {
        if characteristics & IMAGE_SCN_MEM_READ > 0 {
            perms.insert(Permissions::R);
        }
        if characteristics & IMAGE_SCN_MEM_WRITE > 0 {
            perms.insert(Permissions::W);
        }
        if characteristics & IMAGE_SCN_MEM_EXECUTE > 0 {
            perms.insert(Permissions::X);
        }
    }

    // virtual address is zero for the sample data i'm working with right
    // now. since we map the file directly to memory, we don't support virtual
    // mappings.
    assert_eq!(section.address(), 0);

    // object parses the physical size as virtual size?
    // im not exactly sure where this comes from, but we cannot do the following:
    // assert_eq!(section.size(), 0);

    let physical_range = if let Some((start, size)) = section.file_range() {
        std::ops::Range {
            start,
            end: start + size,
        }
    } else {
        std::ops::Range { start: 0, end: 0 }
    };

    debug!("coff: section: {} at {:#x}", name, base_address + physical_range.start);

    Ok(Section {
        physical_range: physical_range.clone(),
        // map the physical range to the virtual range.
        // since virtual mapping is zero'd out.
        virtual_range: physical_range,
        permissions: perms,
        name,
    })
}

/// loads the given COFF file.
/// maps the entire COFF file into memory at the base address (0x0).
/// sections are not aligned and physical addresses === virtual addresses.
fn load_coff(buf: &[u8]) -> Result<COFF> {
    let obj = object::File::parse(buf)?;

    if let object::BinaryFormat::Coff = obj.format() {
        // ok
    } else {
        return Err(COFFError::FormatNotSupported("foo".to_string()).into());
    }

    // > Windows COFF is always 32-bit, even for 64-bit architectures. This could be
    // > confusing.
    // ref: https://docs.rs/object/0.29.0/src/object/read/coff/file.rs.html#87
    //
    // so we use the magic header to determine arch/bitness
    let arch = match obj.architecture() {
        object::Architecture::X86_64_X32 => Arch::X32,
        object::Architecture::X86_64 => Arch::X64,
        _ => {
            return Err(COFFError::FormatNotSupported(format!("{:?}", obj.architecture())).into());
        }
    };
    debug!("coff: arch: {:?}", arch);

    // always 0
    let base_address = obj.relative_address_base();

    debug!("coff: base address: {:#x}", base_address);

    let mut sections = Vec::new();
    for section in obj.sections() {
        sections.push(load_coff_section(base_address, &section)?);
    }

    let max_address = base_address + buf.len() as u64;
    let mut address_space = RelativeAddressSpace::with_capacity(max_address);
    debug!("coff: address space: capacity: {:#x}", max_address);

    address_space.map.writezx(base_address, buf)?;

    // TODO: don't load REMOVE/DISCARDABLE sections
    // ref: https://github.com/ghc/ghc/blob/3c0e379322965aa87b14923f6d8e1ef5cd677925/rts/linker/PEi386.c#L1468-L1469

    // TODO: apply relocations

    let module = Module {
        arch,
        sections,
        address_space: address_space.into_absolute(base_address)?,
    };

    debug!("coff: loaded");
    Ok(COFF {
        buf: buf.to_vec(),
        module,
    })
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use crate::{arch, aspace::AddressSpace, rsrc::*};

    #[test]
    fn base_address() -> Result<()> {
        //crate::test::init_logging();

        let buf = get_buf(Rsrc::ALTSVC);
        let coff = crate::loader::coff::COFF::from_bytes(&buf)?;

        assert_eq!(0x0, coff.module.address_space.base_address);

        Ok(())
    }

    #[test]
    fn altsvc() -> Result<()> {
        let buf = get_buf(Rsrc::ALTSVC);
        let coff = crate::loader::coff::COFF::from_bytes(&buf)?;

        assert!(matches!(coff.module.arch, arch::Arch::X64));

        // .text$mn:0000000000000000                         public Curl_alpnid2str
        // .text$mn:0000000000000000                         Curl_alpnid2str proc near
        // .text$mn:0000000000000000 83 F9 08                cmp     ecx, 8
        assert_eq!(0x83, coff.module.address_space.relative.read_u8(0x9243)?);
        assert_eq!(0xF9, coff.module.address_space.relative.read_u8(0x9244)?);
        assert_eq!(0x08, coff.module.address_space.relative.read_u8(0x9245)?);

        Ok(())
    }

    // this demonstrates that the COFF will be loaded and sections padded out to
    // their virtual range.
    #[test]
    fn read_each_section() -> Result<()> {
        let buf = get_buf(Rsrc::ALTSVC);
        let coff = crate::loader::coff::COFF::from_bytes(&buf)?;

        for section in coff.module.sections.iter() {
            let start = section.virtual_range.start;
            let size = section.virtual_range.end - section.virtual_range.start;
            coff.module
                .address_space
                .read_bytes(start, size as usize)
                .expect(&format!("read section {} {:#x} {:#x}", section.name, start, size));
        }

        Ok(())
    }
}
