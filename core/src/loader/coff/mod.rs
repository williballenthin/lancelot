// this file is a mess: functions are way too long.

use anyhow::Result;
use log::{debug, warn};
use object::{Object, ObjectSection, ObjectSymbol, ObjectSymbolTable};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

use crate::{
    arch::Arch,
    aspace::{AddressSpace, RelativeAddressSpace, WritableAddressSpace},
    module::{Module, Permissions, Section},
    util, RVA, VA,
};

#[derive(Error, Debug)]
pub enum COFFError {
    #[error("format not supported: {0}")]
    FormatNotSupported(String),

    #[error("malformed COFF file: {0}")]
    MalformedCOFFFile(String),
}

// duplicated from object
#[derive(Clone, Copy, Debug)]
pub enum SymbolKind {
    Unknown,
    Null,
    Text,
    Data,
    Section,
    File,
    Label,
    Tls,
}

#[derive(Clone, Debug)]
pub struct Symbol {
    pub name:    String,
    pub address: VA,
    pub kind:    SymbolKind,
}

#[derive(Default)]
pub struct Symbols {
    pub by_name:    BTreeMap<String, Symbol>,
    pub by_address: BTreeMap<VA, Vec<Symbol>>,
}

/// A parsed and loaded COFF file.
/// The `buf` field contains the raw data.
/// The `module` field contains an address space as the COFF would be loaded.
pub struct COFF {
    pub buf:     Vec<u8>,
    pub module:  Module,
    pub symbols: Symbols,
    pub externs: BTreeMap<String, VA>,
}

impl COFF {
    pub fn from_bytes(buf: &[u8]) -> Result<COFF> {
        load_coff(buf)
    }
}

/// The section will not become part of the image. This is valid only for object
/// files.
const IMAGE_SCN_LNK_REMOVE: u32 = 0x800;

/// The section can be discarded as needed.
const IMAGE_SCN_MEM_DISCARDABLE: u32 = 0x200_0000;

/// The section can be executed as code.
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

/// The section can be read.
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;

/// The section can be written to.
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

const PAGE_SIZE: u64 = 0x1000;

/// translate the given COFF section into a section.
/// the section should be mapped starting at `vstart`.
fn load_coff_section(section: &object::read::Section, vstart: VA) -> Result<Section> {
    let section_name = String::from_utf8_lossy(section.name_bytes()?).into_owned();
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
    } else {
        panic!("unexpected flags type");
    }

    // virtual address is zero for the sample data i'm working with right
    // now. since we map the file directly to memory, we don't support virtual
    // mappings.
    assert_eq!(section.address(), 0);

    let vsize = if section.align() > 1 {
        util::align(section.size(), section.align())
    } else {
        section.size()
    };

    let virtual_range = std::ops::Range {
        start: vstart,
        end:   vstart + vsize,
    };

    let physical_range = if let Some((start, size)) = section.file_range() {
        std::ops::Range {
            start,
            end: start + size,
        }
    } else {
        std::ops::Range { start: 0, end: 0 }
    };

    Ok(Section {
        physical_range,
        virtual_range,
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
        object::Architecture::X86_64 => Arch::X64,
        // seen in msvcrt libcpmt.lib 0a783ea78e08268f9ead780da0368409
        object::Architecture::I386 => Arch::X32,
        _ => {
            return Err(COFFError::FormatNotSupported(format!("{:?}", obj.architecture())).into());
        }
    };
    debug!("coff: arch: {:?}", arch);

    // object file COFF base address is always 0:
    //
    //    let base_address = obj.relative_address_base();
    //
    // so let's pick something non-zero to find bugs.
    // note: COFF is only 32-bit, so don't pick an address too high here.
    let base_address = 0x2000_0000u64;
    debug!("coff: base address: {:#x}", base_address);

    let mut vstart = base_address;
    let mut sections = Vec::new();
    for section in obj.sections() {
        if let object::SectionFlags::Coff { characteristics } = section.flags() {
            // these sections should be ignored while loading.
            // ref: https://github.com/ghc/ghc/blob/3c0e379322965aa87b14923f6d8e1ef5cd677925/rts/linker/PEi386.c#L1468-L1469

            if characteristics & IMAGE_SCN_LNK_REMOVE > 0 {
                // sections like .drectve or .chks64
                continue;
            }

            if characteristics & IMAGE_SCN_MEM_DISCARDABLE > 0 {
                // sections like .debug$T or .debug$S
                continue;
            }
        } else {
            panic!("unexpected flags type");
        }

        let section = load_coff_section(&section, vstart)?;

        vstart = util::align(section.virtual_range.end, PAGE_SIZE);

        sections.push(section);
    }

    let max_address = sections
        .iter()
        .map(|section| util::align(section.virtual_range.end, PAGE_SIZE))
        .max()
        .unwrap_or(base_address);

    sections.push(Section {
        physical_range: std::ops::Range { start: 0, end: 0 },
        virtual_range:  std::ops::Range {
            start: max_address,
            end:   max_address + PAGE_SIZE,
        },
        permissions:    Permissions::R,
        name:           "UNDEF".to_string(),
    });

    let max_address = sections
        .iter()
        .map(|section| util::align(section.virtual_range.end, PAGE_SIZE))
        .max();

    let mut module = if let Some(max_address) = max_address {
        let mut address_space = RelativeAddressSpace::with_capacity(max_address);

        for section in sections.iter() {
            let vstart = section.virtual_range.start;
            let vend = section.virtual_range.end;
            let vsize = vend - vstart;

            let pstart = section.physical_range.start as usize;
            let pend = section.physical_range.end as usize;
            let psize = pend - pstart;
            // if virtual size is less than physical size, truncate.
            let psize = std::cmp::min(psize, vsize as usize);
            let pbuf = &buf[pstart..pstart + psize];

            // the section range contains VAs,
            // while we're writing to the RelativeAddressSpace.
            // so shift down by `base_address`.
            let rstart = vstart - base_address;

            let mut vbuf = vec![0u8; vsize as usize];
            let dest = &mut vbuf[0..psize];
            dest.copy_from_slice(pbuf);

            address_space.map.writezx(rstart, &vbuf)?;

            debug!(
                "coff: address space: mapped {:#x} - {:#x} {:?} {}",
                vstart, vend, section.permissions, section.name
            );
        }

        Module {
            arch,
            sections,
            address_space: address_space.into_absolute(base_address)?,
        }
    } else {
        Module {
            arch,
            sections: vec![],
            address_space: RelativeAddressSpace::with_capacity(0x0).into_absolute(base_address)?,
        }
    };

    let mut symbols: Symbols = Default::default();

    if let Some(symtab) = obj.symbol_table() {
        for symbol in symtab.symbols() {
            let name = match symbol.name() {
                Ok(name) => name,
                Err(_) => {
                    continue;
                }
            };

            let secindex = match symbol.section() {
                object::SymbolSection::Section(secindex @ object::SectionIndex(_)) => secindex,
                _ => {
                    continue;
                }
            };

            let target_section = obj.section_by_index(secindex).expect("invalid section index");

            let mapped_section = match module
                .sections
                .iter()
                .find(|s| s.physical_range.start == target_section.file_range().unwrap_or_default().0)
            {
                Some(mapped_section) => mapped_section,
                None => {
                    continue;
                }
            };

            let address = mapped_section.virtual_range.start + symbol.address();

            let s = Symbol {
                address,
                name: name.to_string(),
                kind: match symbol.kind() {
                    object::SymbolKind::Unknown => SymbolKind::Unknown,
                    object::SymbolKind::Null => SymbolKind::Null,
                    object::SymbolKind::Text => SymbolKind::Text,
                    object::SymbolKind::Data => SymbolKind::Data,
                    object::SymbolKind::Section => SymbolKind::Section,
                    object::SymbolKind::File => SymbolKind::File,
                    object::SymbolKind::Label => SymbolKind::Label,
                    object::SymbolKind::Tls => SymbolKind::Tls,
                    _ => panic!("unexpected symbol type"),
                },
            };

            symbols.by_address.entry(address).or_default().push(s.clone());
            symbols.by_name.insert(name.to_string(), s.clone());
        }
    }

    // symbols not defined within this module.
    let mut externs: BTreeSet<String> = Default::default();

    if let Some(symtab) = obj.symbol_table() {
        for section in obj.sections() {
            for (_, reloc) in section.relocations() {
                let object::RelocationEncoding::Generic = reloc.encoding() else {
                    continue;
                };

                let object::RelocationTarget::Symbol(symindex @ object::SymbolIndex(_)) = reloc.target() else {
                    continue;
                };

                let Ok(symbol) = symtab.symbol_by_index(symindex) else {
                    continue;
                };

                let (object::SymbolKind::Data | object::SymbolKind::Text) = symbol.kind() else {
                    continue;
                };

                let (object::SymbolSection::Undefined | object::SymbolSection::Common) = symbol.section() else {
                    continue;
                };

                let name = match symbol.name() {
                    Ok(name) => name,
                    Err(_) => {
                        continue;
                    }
                };

                if let object::RelocationKind::Relative = reloc.kind() {
                    externs.insert(name.to_string());
                } else if let object::RelocationKind::ImageOffset = reloc.kind() {
                    externs.insert(name.to_string());
                } else if let object::RelocationKind::Absolute = reloc.kind() {
                    externs.insert(name.to_string());
                } else {
                    continue;
                }
            }
        }
    }

    let extern_section_size = util::align((externs.len() * std::mem::size_of::<u32>()) as u64, PAGE_SIZE);
    assert!(extern_section_size <= PAGE_SIZE);

    // extern section found directly after section data
    let extern_section_va = max_address.expect("no sections") - PAGE_SIZE;

    let mut extern_page = [0u8; PAGE_SIZE as usize];
    for i in 0..externs.len() {
        let entry_offset = i * std::mem::size_of::<u32>();
        let entry_va = extern_section_va + entry_offset as u64;
        extern_page[entry_offset..entry_offset + std::mem::size_of::<u32>()]
            .copy_from_slice(&(entry_va as u32).to_le_bytes());
    }

    module
        .address_space
        .relative
        .map
        .write(extern_section_va - base_address, &extern_page)?;

    let externs = externs
        .into_iter()
        .enumerate()
        .map(|(i, name)| (name, extern_section_va + i as u64 * std::mem::size_of::<u32>() as u64))
        .collect::<BTreeMap<String, VA>>();

    if let Some(symtab) = obj.symbol_table() {
        // we're only able to apply relocations if we can resolve symbols.

        fn get_section_by_file_rva(module: &Module, rva: RVA) -> Option<&Section> {
            module.sections.iter().find(|s| s.physical_range.start == rva)
        }

        fn get_section_by_coff_section<'a>(module: &'a Module, section: &object::Section) -> Option<&'a Section> {
            get_section_by_file_rva(module, section.file_range().unwrap_or_default().0)
        }

        enum FixupSize {
            _32,
            _64,
        }

        struct Fixup {
            address: VA,
            size:    FixupSize,
            addend:  i64,
        }

        // we need to collect all the fixups
        // because we'll need exclusive access to the `module`
        // to write them back.
        let mut fixups: Vec<Fixup> = Default::default();

        for (i, section) in obj.sections().enumerate() {
            let Some(current_section) = get_section_by_coff_section(&module, &section) else {
                continue;
            };

            for (reloc_rva, reloc) in section.relocations() {
                // virtual address of the place that needs to be fixed up.
                let reloc_va: VA = current_section.virtual_range.start + reloc_rva;

                let object::RelocationEncoding::Generic = reloc.encoding() else {
                    warn!("unexpected relocation encoding: {:?}", reloc.encoding());
                    continue;
                };

                // index of the symbol that the relocation is referencing.
                let object::RelocationTarget::Symbol(symindex @ object::SymbolIndex(_)) = reloc.target() else {
                    warn!("unexpected relocation target: {:?}", reloc.target());
                    continue;
                };

                let Ok(symbol) = symtab.symbol_by_index(symindex) else {
                    warn!("failed to find symbol: {:?}", symindex);
                    continue;
                };

                let target: i64 = match (symbol.kind(), symbol.section()) {
                    (
                        // a relative offset to a code/data symbol found in a section.
                        object::SymbolKind::Data | object::SymbolKind::Text | object::SymbolKind::Label,
                        object::SymbolSection::Section(secindex @ object::SectionIndex(_)),
                    ) => {
                        // COFF section
                        let Ok(target_section) = obj.section_by_index(secindex) else {
                            warn!("failed to find section: {:?}", secindex);
                            continue;
                        };

                        // section in memory
                        let Some(target_section) = get_section_by_coff_section(&module, &target_section) else {
                            warn!("failed to find section: {:?}", secindex);
                            continue;
                        };

                        debug!(
                            "coff: reloc: relative: {}([{}])+0x{:02x}: 0x{:08x} -> {}",
                            current_section.name,
                            i,
                            reloc_rva,
                            target_section.virtual_range.start,
                            symbol.name()?,
                        );

                        // the amount to increment the fixup location.
                        target_section
                            .virtual_range
                            .start
                            .try_into()
                            .expect("64-bit section address")
                    }
                    (
                        // relative offset to an extern symbol.
                        // we place these extern symbols in a fake section named "UNDEF".
                        object::SymbolKind::Data | object::SymbolKind::Text,
                        object::SymbolSection::Undefined | object::SymbolSection::Common,
                    ) => {
                        debug!(
                            "coff: reloc: relative: {}([{}])+0x{:02x}: [extern]   -> {}",
                            current_section.name,
                            i,
                            reloc_rva,
                            symbol.name()?
                        );

                        let Ok(name) = symbol.name() else {
                            continue;
                        };

                        let Some(extern_) = externs.get(name) else {
                            warn!("failed to find extern: {:?}", name);
                            continue;
                        };

                        *extern_ as i64
                    }
                    (object::SymbolKind::Unknown, _) => {
                        warn!(
                            "coff: reloc: unknown: {}([{}])+0x{:02x}: ??? -> {} (unknown)",
                            current_section.name,
                            i,
                            reloc_rva,
                            symbol.name()?
                        );

                        // this is a relocation with unknown kind.
                        // so what can we do?
                        // maybe it points to an extern, but we haven't extracted it above.
                        // at most we can just log here.

                        continue;
                    }
                    _ => {
                        unimplemented!("unsupported symbol: {:?}", symbol);
                    }
                };

                let mut addend = target;

                match reloc.kind() {
                    object::RelocationKind::Relative => {
                        addend -= reloc_va as i64;
                    }
                    object::RelocationKind::ImageOffset => {
                        // the image is assumed to be loaded at 0
                        // (though we load it elsewhere)
                        // so no adjustment needed here.
                    }
                    object::RelocationKind::Absolute => {
                        // pass
                    }
                    _ => unimplemented!("relocation kind: {:?}", reloc.kind()),
                }

                if reloc.has_implicit_addend() {
                    addend += reloc.addend();
                }

                match reloc.size() {
                    32 => {
                        fixups.push(Fixup {
                            address: reloc_va,
                            size: FixupSize::_32,
                            addend,
                        });
                    }
                    64 => {
                        fixups.push(Fixup {
                            address: reloc_va,
                            size: FixupSize::_64,
                            addend,
                        });
                    }
                    _ => unimplemented!("relocation size: {}", reloc.size()),
                }
            }
        }

        {
            let module = &mut module;

            for fixup in fixups.into_iter() {
                match fixup.size {
                    FixupSize::_32 => {
                        let existing = module.address_space.read_u32(fixup.address)?;

                        let new = existing as i32 + fixup.addend as i32;

                        module.address_space.write_u32(fixup.address, new as u32)?;
                    }
                    FixupSize::_64 => {
                        let existing = module.address_space.read_u64(fixup.address)?;

                        let new = existing as i64 + fixup.addend;

                        module.address_space.write_u64(fixup.address, new as u64)?;
                    }
                }
            }
        }
    }

    debug!("coff: loaded");
    Ok(COFF {
        buf: buf.to_vec(),
        module,
        symbols,
        externs,
    })
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use crate::{arch, aspace::AddressSpace, emu::mmu::PAGE_SIZE, rsrc::*};

    #[test]
    fn base_address() -> Result<()> {
        //crate::test::init_logging();

        let buf = get_buf(Rsrc::ALTSVC);
        let coff = crate::loader::coff::COFF::from_bytes(&buf)?;

        assert_eq!(0x2000_0000, coff.module.address_space.base_address);

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
        assert_eq!(0x83, coff.module.address_space.relative.read_u8(0x0)?);
        assert_eq!(0xF9, coff.module.address_space.relative.read_u8(0x1)?);
        assert_eq!(0x08, coff.module.address_space.relative.read_u8(0x2)?);

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

    #[test]
    fn symbols() -> Result<()> {
        let buf = get_buf(Rsrc::ALTSVC);
        let coff = crate::loader::coff::COFF::from_bytes(&buf)?;

        assert_eq!(
            coff.symbols.by_name.get("Curl_alpnid2str").unwrap().address,
            coff.module.address_space.base_address
        );
        assert_eq!(
            coff.symbols.by_name.get("Curl_altsvc_cleanup").unwrap().address,
            coff.module.address_space.base_address + PAGE_SIZE as u64
        );

        Ok(())
    }

    #[test]
    fn relocs() -> Result<()> {
        let buf = get_buf(Rsrc::ALTSVC);
        let coff = crate::loader::coff::COFF::from_bytes(&buf)?;

        assert_eq!(
            coff.module.address_space.relative.read_u32(0x10).unwrap() as u64,
            0x00072FEC
        );
        assert_eq!(
            coff.module.address_space.relative.read_u32(0x17).unwrap() as u64,
            0x00071FE5
        );

        // image relocation
        let pdata = coff.symbols.by_name.get("$pdata$2$altsvc_flush").unwrap().address;
        let altsvc_flush = coff.symbols.by_name.get("altsvc_flush").unwrap().address;
        assert_eq!(
            coff.module.address_space.read_u32(pdata).unwrap() as u64,
            altsvc_flush + 0xDB
        );

        Ok(())
    }
}
