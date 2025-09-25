#![allow(clippy::nonstandard_macro_braces)] // clippy bug, see https://github.com/rust-lang/rust-clippy/issues/7434

use anyhow::Result;
use log::debug;
use thiserror::Error;

pub mod imports;
pub mod reloc;
pub mod rsrc;

use crate::{
    arch::Arch,
    aspace::{self, RelativeAddressSpace},
    module::{Module, Permissions, Section},
    util, RVA, VA,
};

#[derive(Error, Debug)]
pub enum PEError {
    #[error("format not supported: {0}")]
    FormatNotSupported(String),

    #[error("malformed PE file: {0}")]
    MalformedPEFile(String),
}

// ref: https://docs.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-imagedirectoryentrytodata#parameters
pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
pub const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
pub const IMAGE_DIRECTORY_ENTRY_RESOURCE: usize = 2;
pub const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
pub const IMAGE_DIRECTORY_ENTRY_SECURITY: usize = 4;
pub const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
pub const IMAGE_DIRECTORY_ENTRY_DEBUG: usize = 6;
pub const IMAGE_DIRECTORY_ENTRY_ARCHITECTURE: usize = 7;
pub const IMAGE_DIRECTORY_ENTRY_GLOBALPTR: usize = 8;
pub const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;
pub const IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG: usize = 10;
pub const IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT: usize = 11;
pub const IMAGE_DIRECTORY_ENTRY_IAT: usize = 12;
pub const IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT: usize = 13;
pub const IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR: usize = 14;
pub const IMAGE_DIRECTORY_MAX: usize = IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR;

pub struct DataDirectory {
    pub address: VA,
    pub size:    RVA,
}

/// A parsed and loaded PE file.
/// The `buf` field contains the raw data.
/// The `module` field contains an address space as the PE would be loaded.
pub struct PE {
    pub buf:             Vec<u8>,
    pub module:          Module,
    /// Shortcut to Goblin's PE optional header structure.
    ///
    /// Access other PE fields via `PE.pe()`.
    /// Can't inline many of them here due to circular lifetimes referencing
    /// `buf`.
    pub optional_header: Option<goblin::pe::optional_header::OptionalHeader>,
}

impl PE {
    pub fn from_bytes(buf: &[u8]) -> Result<PE> {
        load_pe(buf)
    }

    pub fn executable_sections<'b>(&'b self) -> Box<dyn Iterator<Item = &'b Section> + 'b> {
        Box::new(
            self.module
                .sections
                .iter()
                .filter(|section| section.permissions.intersects(Permissions::X)),
        )
    }

    pub fn pe(&self) -> Result<goblin::pe::PE<'_>> {
        get_pe(&self.buf)
    }

    pub fn get_data_directory(&self, data_directory: usize) -> Result<Option<DataDirectory>> {
        assert!(data_directory <= IMAGE_DIRECTORY_MAX);

        let opt_header = match self.optional_header {
            Some(opt_header) => opt_header,
            _ => return Ok(None),
        };

        match opt_header.data_directories.data_directories[data_directory] {
            Some((_, directory)) => Ok(Some(DataDirectory {
                address: self.module.address_space.base_address + directory.virtual_address as VA,
                size:    directory.size as RVA,
            })),
            _ => Ok(None),
        }
    }
}

fn get_pe(buf: &[u8]) -> Result<goblin::pe::PE<'_>> {
    let pe = match goblin::pe::PE::parse(buf) {
        Ok(pe) => pe,
        Err(e) => {
            // goblin failed to parse the PE file
            // so we won't be able to do any analysis.
            //
            // the alternative here would be to write our own PE parser,
            // which is not very attractive...
            return Err(PEError::MalformedPEFile(e.to_string()).into());
        }
    };

    if let Some(opt) = pe.header.optional_header {
        if opt.data_directories.get_clr_runtime_header().is_some() {
            return Err(PEError::FormatNotSupported(".NET assembly".to_string()).into());
        }
    }
    Ok(pe)
}

#[allow(clippy::unnecessary_wraps)]
fn load_pe_header(buf: &[u8], pe: &goblin::pe::PE, base_address: VA) -> Result<Section> {
    let hdr_raw_size = match pe.header.optional_header {
        Some(opt) => opt.windows_fields.size_of_headers,
        // assumption: header is at most 0x200 bytes.
        _ => 0x200,
    };

    //   on disk:
    //
    // ```
    //   +---------------------------------+
    //   |   header        |  sections...  |
    //   +---------------------------------+
    //   .                  \
    //   .  in memory:       \
    //   .                    \
    //   +-----------------+---+        +-------------
    //   |   header        |   |        |  sections...
    //   +-----------------+---+        +-------------
    //                     ^   ^
    //                     |   +--- virtual size
    //                     |        aligned to 0x200
    //                     +-- raw size
    //                         no alignment
    // ```

    let hdr_raw_size = std::cmp::min(hdr_raw_size as usize, buf.len());
    let hdr_virt_size = util::align(hdr_raw_size as u64, 0x200);

    Ok(Section {
        physical_range: std::ops::Range {
            start: 0x0,
            end:   hdr_raw_size as u64,
        },
        virtual_range:  std::ops::Range {
            start: base_address,
            end:   base_address + hdr_virt_size,
        },
        permissions:    Permissions::R,
        name:           "header".to_string(),
    })
}

/// The section can be executed as code.
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

/// The section can be read.
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;

/// The section can be written to.
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

const PAGE_SIZE: u64 = 0x1000;

#[allow(clippy::unnecessary_wraps)]
fn load_pe_section(
    base_address: VA,
    section_alignment: u64,
    section: &goblin::pe::section_table::SectionTable,
) -> Result<Section> {
    let section_name = String::from_utf8_lossy(&section.name[..]).into_owned();

    let trimmed_name = section_name.trim_end_matches('\u{0}').trim_end();

    let name = trimmed_name
        .split_once('\u{0}')
        .map(|(name, _)| name)
        .unwrap_or_else(|| trimmed_name)
        .to_string();

    let virtual_size = util::align(section.virtual_size as u64, section_alignment);

    let mut perms = Permissions::empty();
    if section.characteristics & IMAGE_SCN_MEM_READ > 0 {
        perms.insert(Permissions::R);
    }
    if section.characteristics & IMAGE_SCN_MEM_WRITE > 0 {
        perms.insert(Permissions::W);
    }
    if section.characteristics & IMAGE_SCN_MEM_EXECUTE > 0 {
        perms.insert(Permissions::X);
    }

    debug!(
        "pe: section: {} at {:#x}",
        name,
        base_address + section.virtual_address as u64
    );

    Ok(Section {
        physical_range: std::ops::Range {
            start: section.pointer_to_raw_data as u64,
            end:   (section.pointer_to_raw_data + section.size_of_raw_data) as u64,
        },
        virtual_range: std::ops::Range {
            start: base_address + section.virtual_address as u64,
            end:   base_address + section.virtual_address as u64 + virtual_size,
        },
        permissions: perms,
        name,
    })
}

// lots of further detail here: https://github.com/corkami/docs/blob/master/PE/PE.md
fn load_pe(buf: &[u8]) -> Result<PE> {
    let pe = get_pe(buf)?;

    let arch = match pe.is_64 {
        false => Arch::X32,
        true => Arch::X64,
    };
    debug!("pe: arch: {:?}", arch);

    let (base_address, section_alignment) = match pe.header.optional_header {
        Some(opt) => (
            opt.windows_fields.image_base,
            opt.windows_fields.section_alignment as u64,
        ),
        _ => {
            debug!("pe: base address: using default: 0x40:000");
            (0x40_0000, PAGE_SIZE)
        }
    };
    debug!("pe: base address: {:#x}", base_address);

    let mut sections = vec![load_pe_header(buf, &pe, base_address)?];
    for section in pe.sections.iter() {
        sections.push(load_pe_section(base_address, section_alignment, section)?);
    }

    let max_address = sections.iter().map(|sec| sec.virtual_range.end).max().unwrap();
    let max_page_address = util::align(max_address, PAGE_SIZE) - base_address;
    debug!("pe: address space: capacity: {:#x}", max_page_address);

    let mut address_space = RelativeAddressSpace::with_capacity(max_page_address);

    for section in sections.iter() {
        let pstart = section.physical_range.start as usize;
        let pend = section.physical_range.end as usize;

        let (psize, pbuf) = if pstart >= buf.len() {
            (0, &[] as &[u8])
        } else if pend > buf.len() {
            (buf.len() - pstart, &buf[pstart..])
        } else {
            let psize = pend - pstart;
            let pbuf = &buf[pstart..pend];
            (psize, pbuf)
        };

        // the section range contains VAs,
        // while we're writing to the RelativeAddressSpace.
        // so shift down by `base_address`.
        let vstart = section.virtual_range.start;
        let rstart = vstart - base_address;
        let vsize = util::align(
            section.virtual_range.end - section.virtual_range.start,
            section_alignment,
        );
        let vend = vstart + vsize;
        let mut vbuf = vec![0u8; vsize as usize];

        if vsize as usize >= psize {
            // vsize > psize, so there will be NULL bytes padding the physical data.
            let dest = &mut vbuf[0..psize];
            dest.copy_from_slice(pbuf);
        } else {
            // psize > vsize, but vsize wins, so we only read a subset of physical data.
            let src = &pbuf[0..vsize as usize];
            vbuf.copy_from_slice(src);
        }

        if aspace::page_offset(rstart) != 0 {
            // see discussion in #66
            // Microsoft says its ok to have non-page aligned sections in memory.
            // but this would require a lot of work to support here.
            // so... we bail.
            return Err(PEError::FormatNotSupported("non-page aligned section".to_string()).into());
        }

        address_space.map.writezx(rstart, &vbuf)?;

        // We are tempted to use the PE section's pointer_to_relocations and
        // number_of_relocations but these don't apply to PE files (but they do
        // apply to COFF files). Instead, we have to parse the base relocation
        // table, found in the .reloc section.
        {}

        debug!(
            "pe: address space: mapped {:#x} - {:#x} {:?}",
            vstart, vend, section.permissions
        );
    }

    let module = Module {
        arch,
        sections,
        address_space: address_space.into_absolute(base_address)?,
    };

    debug!("pe: loaded");
    Ok(PE {
        buf: buf.to_vec(),
        module,
        optional_header: pe.header.optional_header,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::identity_op)]

    use anyhow::Result;

    use crate::{aspace::AddressSpace, rsrc::*};

    #[test]
    fn base_address() -> Result<()> {
        let buf = get_buf(Rsrc::K32);
        let pe = crate::loader::pe::PE::from_bytes(&buf)?;

        assert_eq!(0x1_8000_0000, pe.module.address_space.base_address);

        Ok(())
    }

    #[test]
    fn mz_header() -> Result<()> {
        let buf = get_buf(Rsrc::K32);
        let pe = crate::loader::pe::PE::from_bytes(&buf)?;

        // relative read
        assert_eq!(0x4d, pe.module.address_space.relative.read_u8(0x0)?);
        assert_eq!(0x5a, pe.module.address_space.relative.read_u8(0x1)?);

        // absolute read
        assert_eq!(0x4d, pe.module.address_space.read_u8(0x1_8000_0000 + 0x0)?);
        assert_eq!(0x5a, pe.module.address_space.read_u8(0x1_8000_0000 + 0x1)?);

        Ok(())
    }

    #[test]
    fn k32() -> Result<()> {
        let buf = get_buf(Rsrc::K32);
        let pe = crate::loader::pe::PE::from_bytes(&buf)?;

        assert_eq!(0x4d, pe.module.address_space.relative.read_u8(0x0)?);
        assert_eq!(0x5a, pe.module.address_space.relative.read_u8(0x1)?);

        Ok(())
    }

    #[test]
    fn tiny() -> Result<()> {
        let buf = get_buf(Rsrc::TINY);
        let pe = crate::loader::pe::PE::from_bytes(&buf)?;

        assert_eq!(0x4d, pe.module.address_space.relative.read_u8(0x0)?);
        assert_eq!(0x5a, pe.module.address_space.relative.read_u8(0x1)?);

        Ok(())
    }

    #[test]
    fn nop() -> Result<()> {
        let buf = get_buf(Rsrc::NOP);
        let pe = crate::loader::pe::PE::from_bytes(&buf)?;

        assert_eq!(0x4d, pe.module.address_space.relative.read_u8(0x0)?);
        assert_eq!(0x5a, pe.module.address_space.relative.read_u8(0x1)?);

        Ok(())
    }

    #[test]
    fn mimi() -> Result<()> {
        let buf = get_buf(Rsrc::MIMI);
        let pe = crate::loader::pe::PE::from_bytes(&buf)?;

        assert_eq!(0x4d, pe.module.address_space.relative.read_u8(0x0)?);
        assert_eq!(0x5a, pe.module.address_space.relative.read_u8(0x1)?);

        Ok(())
    }

    // this demonstrates that the PE will be loaded and sections padded out to their
    // virtual range.
    #[test]
    fn read_each_section() -> Result<()> {
        let buf = get_buf(Rsrc::K32);
        let pe = crate::loader::pe::PE::from_bytes(&buf)?;

        for section in pe.module.sections.iter() {
            let start = section.virtual_range.start;
            let size = section.virtual_range.end - section.virtual_range.start;
            pe.module
                .address_space
                .read_bytes(start, size as usize)
                .unwrap_or_else(|_| panic!("read section {} {:#x} {:#x}", section.name, start, size));
        }

        Ok(())
    }
}
