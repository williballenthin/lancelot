use anyhow::Result;
use log::debug;
use object::{Object, ObjectSection, ObjectSymbol, ObjectSymbolTable};
use std::collections::BTreeMap;
use thiserror::Error;

use crate::{
    arch::Arch,
    aspace::{AddressSpace, RelativeAddressSpace, WritableAddressSpace},
    module::{Module, Permissions, Section},
    util, VA,
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
    pub buf:               Vec<u8>,
    pub module:            Module,
    pub symbols:           Symbols,
    // all the unresolved references that aren't found in this object file.
    pub undefined_symbols: BTreeMap<String, Vec<VA>>,
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
        object::Architecture::X86_64_X32 => Arch::X32,
        object::Architecture::X86_64 => Arch::X64,
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

    let mut undefined_symbols: BTreeMap<String, Vec<VA>> = Default::default();

    if let Some(symtab) = obj.symbol_table() {
        // we're only able to apply relocations if we can resolve symbols.

        // operation to be performed on the module.
        // add the `addend` to the u32 fetched from `address`, writing it back to
        // `address`. we only support u32 fixups at the moment (all thats needed
        // for COFF?).
        struct RelocationFixup {
            address: VA,
            addend:  u32,
        }

        // all the collected fixups that we need to perform.
        let mut operations: Vec<RelocationFixup> = Default::default();

        for (i, section) in obj.sections().enumerate() {
            if let Some(mapped_section) = module
                .sections
                .iter()
                .find(|s| s.physical_range.start == section.file_range().unwrap_or_default().0)
            {
                for (location_offset, reloc) in section.relocations() {
                    // virtual address of the place that needs to be fixed up.
                    let vlocation: VA = mapped_section.virtual_range.start + location_offset;

                    match (
                        reloc.kind(),
                        reloc.encoding(),
                        reloc.size(),
                        reloc.target(),
                        reloc.addend(),
                        reloc.has_implicit_addend(),
                    ) {
                        (
                            object::RelocationKind::Relative,
                            object::RelocationEncoding::Generic,
                            32,
                            object::RelocationTarget::Symbol(symindex @ object::SymbolIndex(_)),
                            -4,
                            true,
                        ) => {
                            let symbol = symtab.symbol_by_index(symindex)?;

                            match (symbol.kind(), symbol.section(), symbol.flags()) {
                                (
                                    object::SymbolKind::Data | object::SymbolKind::Text | object::SymbolKind::Label,
                                    object::SymbolSection::Section(secindex @ object::SectionIndex(_)),
                                    object::SymbolFlags::None,
                                ) => {
                                    let target_section = obj.section_by_index(secindex)?;
                                    let target_section = module
                                        .sections
                                        .iter()
                                        .find(|s| {
                                            s.physical_range.start == target_section.file_range().unwrap_or_default().0
                                        })
                                        .expect("target section not mapped");

                                    debug!(
                                        "coff: reloc: relative: {}([{}])+0x{:02x}: 0x{:08x} -> {}",
                                        mapped_section.name,
                                        i,
                                        location_offset,
                                        target_section.virtual_range.start,
                                        symbol.name()?,
                                    );

                                    // the amount to increment the fixup location.
                                    let addend = target_section
                                        .virtual_range
                                        .start
                                        .try_into()
                                        .expect("64-bit section address");

                                    operations.push(RelocationFixup {
                                        address: vlocation,
                                        addend,
                                    })
                                }
                                (
                                    object::SymbolKind::Data | object::SymbolKind::Text,
                                    object::SymbolSection::Undefined | object::SymbolSection::Common,
                                    object::SymbolFlags::None,
                                ) => {
                                    debug!(
                                        "coff: reloc: relative: {}([{}])+0x{:02x}: [extern]   -> {}",
                                        mapped_section.name,
                                        i,
                                        location_offset,
                                        symbol.name()?
                                    );

                                    undefined_symbols
                                        .entry(mapped_section.name.clone())
                                        .or_default()
                                        .push(vlocation);
                                }
                                _ => {
                                    panic!("unsupported symbol: {:?}", symbol);
                                }
                            }
                        }
                        (
                            object::RelocationKind::ImageOffset,
                            object::RelocationEncoding::Generic,
                            32,
                            object::RelocationTarget::Symbol(symindex @ object::SymbolIndex(_)),
                            0,
                            true,
                        ) => {
                            let symbol = symtab.symbol_by_index(symindex)?;

                            match (symbol.kind(), symbol.section(), symbol.flags()) {
                                (
                                    object::SymbolKind::Data | object::SymbolKind::Text | object::SymbolKind::Label,
                                    object::SymbolSection::Section(secindex @ object::SectionIndex(_)),
                                    object::SymbolFlags::None,
                                ) => {
                                    let target_section = obj.section_by_index(secindex)?;
                                    let target_section = module
                                        .sections
                                        .iter()
                                        .find(|s| {
                                            s.physical_range.start == target_section.file_range().unwrap_or_default().0
                                        })
                                        .expect("target section not mapped");

                                    debug!(
                                        "coff: reloc: image offset: {}([{}])+0x{:02x}: 0x{:08x} -> {}",
                                        mapped_section.name,
                                        i,
                                        location_offset,
                                        target_section.virtual_range.start,
                                        symbol.name()?,
                                    );

                                    // the amount to increment the fixup location.
                                    let addend = target_section
                                        .virtual_range
                                        .start
                                        .try_into()
                                        .expect("64-bit section address");

                                    operations.push(RelocationFixup {
                                        address: vlocation,
                                        addend,
                                    })
                                }
                                (
                                    object::SymbolKind::Data | object::SymbolKind::Text,
                                    object::SymbolSection::Undefined | object::SymbolSection::Common,
                                    object::SymbolFlags::None,
                                ) => {
                                    debug!(
                                        "coff: reloc: image offset: {}([{}])+0x{:02x}: [extern]   -> {}",
                                        mapped_section.name,
                                        i,
                                        location_offset,
                                        symbol.name()?
                                    );

                                    undefined_symbols
                                        .entry(mapped_section.name.clone())
                                        .or_default()
                                        .push(vlocation);
                                }
                                _ => {
                                    panic!("unsupported symbol: {:?}", symbol);
                                }
                            }
                        }
                        _ => {
                            panic!("unsupported relocation: {:?}", reloc);
                        }
                    }
                }
            }
        }

        for operation in operations.iter() {
            debug!(
                "coff: fixup: *0x{:08x} += 0x{:08x}",
                operation.address, operation.addend
            );

            let symbol_address = operation.addend as u64;
            if let Some(symbols) = symbols.by_address.get(&symbol_address) {
                for symbol in symbols.iter() {
                    if matches!(symbol.kind, SymbolKind::Text | SymbolKind::Data) {
                        debug!("                         += &{}", symbol.name)
                    }
                }
            }

            let existing = module.address_space.read_u32(operation.address)?;
            module
                .address_space
                .write_u32(operation.address, existing + operation.addend)?;

            debug!(
                "              0x{:08x} -> 0x{:08x}",
                existing,
                existing + operation.addend
            );
        }
    }

    debug!("coff: loaded");
    Ok(COFF {
        buf: buf.to_vec(),
        module,
        symbols,
        undefined_symbols,
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

        // .text$mn:0000000000000000                         Curl_alpnid2str proc near
        // .text$mn:0000000000000000 83 F9 08                cmp     ecx, 8
        // .text$mn:0000000000000003 74 23                   jz      short loc_28
        // .text$mn:0000000000000005 83 F9 10                cmp     ecx, 10h
        // .text$mn:0000000000000008 74 16                   jz      short loc_20
        // .text$mn:000000000000000A 83 F9 20                cmp     ecx, 20h ; ' '
        // .text$mn:000000000000000D 48 8D 15 84 1D 00 00    lea     rdx,
        // ??_C@_00CNPNBAHC@@ ; `string' .text$mn:0000000000000014 48 8D 05 75
        // 1D 00 00    lea     rax, ??_C@_02LCBBNJEF@h3@ ; `string'
        // .text$mn:000000000000001B 48 0F 45 C2             cmovnz  rax, rdx
        // .text$mn:000000000000001F C3                      retn

        let a1 = coff.symbols.by_name.get("??_C@_00CNPNBAHC@@").unwrap().address;
        assert_eq!(coff.module.address_space.relative.read_u32(0x10).unwrap() as u64, a1);

        let a2 = coff.symbols.by_name.get("??_C@_02LCBBNJEF@h3@").unwrap().address;
        assert_eq!(coff.module.address_space.relative.read_u32(0x17).unwrap() as u64, a2);

        // .pdata:0000000000001D70
        // _pdata          segment dword public 'DATA' use64
        // .pdata:0000000000001D70
        // assume cs:_pdata .pdata:0000000000001D70
        // ;org 1D70h .pdata:0000000000001D70
        // ; COMDAT (pick associative to section at 1200)
        // .pdata:0000000000001D70 DB 12 00 00 F0 12 00 00 60 1D 00 00
        // $pdata$2$altsvc_flush RUNTIME_FUNCTION <rva loc_12DB, rva locret_12EF+1, \
        // .pdata:0000000000001D70
        // rva $chain$2$altsvc_flush> .pdata:0000000000001D7C ?? ?? ?? ??
        // align 20h .pdata:0000000000001D7C
        // _pdata          ends

        let pdata = coff.symbols.by_name.get("$pdata$2$altsvc_flush").unwrap().address;
        let altsvc_flush = coff.symbols.by_name.get("altsvc_flush").unwrap().address;
        assert_eq!(
            coff.module.address_space.read_u32(pdata).unwrap() as u64,
            altsvc_flush + 0xDB
        );

        // altsvc_flush+0xDB
        // .text$mn:00000000000012DB 48 8B 74 24 50
        // mov     rsi, [rsp+38h+arg_10] .text$mn:00000000000012E0 48 8B 7C 24
        // 58                                                  mov     rdi,
        // [rsp+38h+arg_18] .text$mn:00000000000012E5 48 83 C4 20
        // add     rsp, 20h .text$mn:00000000000012E9 41 5F
        // pop     r15 .text$mn:00000000000012EB 41 5E
        // pop     r14 .text$mn:00000000000012ED 41 5C

        Ok(())
    }
}
