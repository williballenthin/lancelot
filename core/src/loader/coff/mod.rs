// this file is a mess: functions are way too long.

use anyhow::Result;
use log::{debug, warn};
use object::{Object, ObjectSection, ObjectSymbol, ObjectSymbolTable};
use std::{
    collections::{BTreeMap, BTreeSet},
    unimplemented,
};
use thiserror::Error;

use crate::{
    arch::Arch,
    aspace::{RelativeAddressSpace, WritableAddressSpace},
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

fn load_coff_sections(obj: &object::File, base_address: VA) -> Result<Vec<Section>, anyhow::Error> {
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

    Ok(sections)
}

fn load_coff_module(
    buf: &[u8],
    arch: Arch,
    base_address: u64,
    sections: Vec<Section>,
) -> Result<Module, anyhow::Error> {
    let max_address = sections
        .iter()
        .map(|section| util::align(section.virtual_range.end, PAGE_SIZE))
        .max();

    let module = if let Some(max_address) = max_address {
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

    Ok(module)
}

fn get_coff_symbols(obj: &object::File, module: &Module) -> Symbols {
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
    symbols
}

fn get_coff_extern_names(obj: &object::File) -> BTreeSet<String> {
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

                let Ok(name) = symbol.name() else {
                    warn!("coff: reloc: no name: {:?}", symbol);
                    continue;
                };

                match (symbol.kind(), symbol.section()) {
                    (
                        object::SymbolKind::Data | object::SymbolKind::Text,
                        object::SymbolSection::Undefined | object::SymbolSection::Common,
                    ) => {
                        debug!("coff: reloc: extern: symbol: {}", name);
                        externs.insert(name.to_string());
                    }
                    (object::SymbolKind::Section, object::SymbolSection::Common) => {
                        if obj.section_by_name(name).is_none() {
                            debug!("coff: reloc: extern: section: {}", name);
                            externs.insert(name.to_string());
                        };
                    }
                    (object::SymbolKind::Unknown, object::SymbolSection::Common) => {
                        debug!("coff: reloc: extern: unknown: {}", name);
                        externs.insert(name.to_string());
                    }
                    (_, _) => continue,
                }
            }
        }
    }
    externs
}

fn load_coff_extern_section(
    module: &mut Module,
    extern_names: BTreeSet<String>,
) -> Result<BTreeMap<String, u64>, anyhow::Error> {
    let max_address = module
        .sections
        .iter()
        .map(|section| util::align(section.virtual_range.end, PAGE_SIZE))
        .max();

    let extern_section_size = util::align((extern_names.len() * std::mem::size_of::<u32>()) as u64, PAGE_SIZE);
    assert!(extern_section_size <= PAGE_SIZE);

    let extern_section_va = max_address.expect("no sections") - PAGE_SIZE;
    let mut extern_page = [0u8; PAGE_SIZE as usize];
    for i in 0..extern_names.len() {
        let entry_offset = i * std::mem::size_of::<u32>();
        let entry_va = extern_section_va + entry_offset as u64;
        extern_page[entry_offset..entry_offset + std::mem::size_of::<u32>()]
            .copy_from_slice(&(entry_va as u32).to_le_bytes());
    }

    module
        .address_space
        .relative
        .map
        .write(extern_section_va - module.address_space.base_address, &extern_page)?;

    let externs = extern_names
        .into_iter()
        .enumerate()
        .map(|(i, name)| (name, extern_section_va + i as u64 * std::mem::size_of::<u32>() as u64))
        .collect::<BTreeMap<String, VA>>();

    Ok(externs)
}

enum FixupSize {
    _32,
    _64,
}

struct Fixup {
    // the location to change
    address: VA,
    // the size to change, either 4 or 8 bytes
    size:    FixupSize,
    // the value to write at the location
    value:   i64,
}

fn get_section_by_file_rva(module: &Module, rva: RVA) -> Option<&Section> {
    module.sections.iter().find(|s| s.physical_range.start == rva)
}

fn get_section_by_coff_section<'a>(module: &'a Module, section: &object::Section) -> Option<&'a Section> {
    get_section_by_file_rva(module, section.file_range().unwrap_or_default().0)
}

fn get_section_by_name<'a>(module: &'a Module, name: &str) -> Option<&'a Section> {
    module.sections.iter().find(|s| s.name == name)
}

fn get_coff_fixups(
    module: &mut Module,
    obj: &object::File,
    symtab: object::SymbolTable,
    externs: &BTreeMap<String, u64>,
) -> Result<Vec<Fixup>, anyhow::Error> {
    let mut fixups: Vec<Fixup> = Default::default();
    for (i, section) in obj.sections().enumerate() {
        let Some(current_section) = get_section_by_coff_section(&*module, &section) else {
            continue;
        };

        // reloc_rva: the place that needs to be updated.
        // reloc: the thing to be done at that place.
        for (reloc_rva, reloc) in section.relocations() {
            // reloc_va: the place that needs to be updated.
            let reloc_va: VA = current_section.virtual_range.start + reloc_rva;

            let object::RelocationEncoding::Generic = reloc.encoding() else {
                // other encodings are not yet supported/tested.
                unimplemented!("unexpected relocation encoding: {:?}", reloc.encoding());
            };

            // see LLVM implementation for reference:
            // https://github.com/llvm/llvm-project/blob/3bc1ea5b0ac90e04e7b935a5d964613f8fbad4bf/llvm/lib/ExecutionEngine/RuntimeDyld/Targets/RuntimeDyldCOFFI386.h#L43

            // index of the symbol that the relocation is referencing.
            //
            //    auto Symbol = RelI->getSymbol();
            let object::RelocationTarget::Symbol(symindex @ object::SymbolIndex(_)) = reloc.target() else {
                // other targets are not yet supported/tested.
                unimplemented!("unexpected relocation target: {:?}", reloc.target());
            };

            // the name of the symbol that the relocation is referencing.
            //
            //     Expected<StringRef> TargetNameOrErr = Symbol->getName();
            let Ok(symbol) = symtab.symbol_by_index(symindex) else {
                // while we're not sure why we'd hit this case,
                // that the relocation target symbol is not available,
                // we can limp along by not applying the relocation.
                warn!("coff: reloc: failed to find symbol: {:?}", symindex);
                continue;
            };

            // the address of the thing that the relocation is referencing.
            //
            // there are three supported cases today:
            //   1. code/data found in a section target is address of the section.
            //   2. code/data found in an external symbol, target is the address of
            //      thesymbol (in UNDEF section).
            //   3. a known section, like .text, target is ??TODO??.
            let target: i64 = match (symbol.kind(), symbol.section()) {
                (
                    object::SymbolKind::Data
                    | object::SymbolKind::Text
                    | object::SymbolKind::Label
                    | object::SymbolKind::Section,
                    object::SymbolSection::Section(secindex @ object::SectionIndex(_)),
                ) => {
                    // convert from the section index in the relocation
                    // to our module's section.
                    let Ok(target_section) = obj.section_by_index(secindex) else {
                        warn!("coff: reloc: failed to find section: {:?}", secindex);
                        continue;
                    };
                    let Some(target_section) = get_section_by_coff_section(&*module, &target_section) else {
                        warn!("coff: reloc: failed to find section: {:?}", secindex);
                        continue;
                    };

                    // we've resolved the section in which the target symbol is found,
                    // so we can apply the fixup by computing the delta between current section and
                    // target section, and adding this to the existing value
                    // found at reloc_rva (reloc.addend()).
                    //
                    // when each COFF section contains exactly one symbol,
                    // then the addend is 0x0, and we can easily resolve the symbol name here.
                    // but this is not always the case.

                    debug!(
                        "coff: reloc: sections[{}]: {}+0x{:02x} -> {} in section {} (0x{:08x})",
                        i,
                        current_section.name,
                        reloc_rva,
                        symbol.name()?,
                        target_section.name,
                        target_section.virtual_range.start,
                    );

                    target_section
                        .virtual_range
                        .start
                        .try_into()
                        .expect("64-bit section address")
                }
                (
                    // we place these extern symbols in a fake section named "UNDEF".
                    object::SymbolKind::Data | object::SymbolKind::Text,
                    object::SymbolSection::Undefined | object::SymbolSection::Common,
                ) => {
                    let Ok(name) = symbol.name() else {
                        warn!("coff: reloc: no name: {:?}", symbol);
                        continue;
                    };

                    let Some(extern_) = externs.get(name) else {
                        warn!("coff: reloc: failed to find extern: {:?}", name);
                        continue;
                    };

                    debug!(
                        "coff: reloc: sections[{}]: {}+0x{:02x} -> {} (extern, 0x{:08x})",
                        i, current_section.name, reloc_rva, name, extern_
                    );

                    *extern_ as i64
                }
                (object::SymbolKind::Section, object::SymbolSection::Common) => {
                    let Ok(name) = symbol.name() else {
                        warn!("coff: reloc: no name: {:?}", symbol);
                        continue;
                    };

                    if let Some(target_section) = get_section_by_name(module, name) {
                        debug!(
                            "coff: reloc: sections[{}]: {}+0x{:02x} -> {} (section, 0x{:08x})",
                            i, current_section.name, reloc_rva, name, target_section.virtual_range.start,
                        );

                        target_section
                            .virtual_range
                            .start
                            .try_into()
                            .expect("64-bit section address")
                    } else {
                        // extern section
                        let Some(extern_) = externs.get(name) else {
                            warn!("coff: reloc: failed to find extern: {:?}", name);
                            continue;
                        };

                        debug!(
                            "coff: reloc: sections[{}]: {}+0x{:02x} -> {} (extern, section, 0x{:08x})",
                            i, current_section.name, reloc_rva, name, extern_
                        );

                        *extern_ as i64
                    }
                }
                (object::SymbolKind::Unknown, _) => {
                    let Ok(name) = symbol.name() else {
                        warn!("coff: reloc: no name: {:?}", symbol);
                        continue;
                    };

                    // assume its an extern.
                    let Some(extern_) = externs.get(name) else {
                        warn!("coff: reloc: failed to find extern: {:?}", name);
                        continue;
                    };

                    debug!(
                        "coff: reloc: sections[{}]: {}+0x{:02x} -> {} (extern, unknown, 0x{:08x})",
                        i, current_section.name, reloc_rva, name, extern_
                    );

                    *extern_ as i64
                }
                _ => {
                    unimplemented!("unsupported symbol: {:?}", symbol);
                }
            };

            // resolved_address: the address that we'll write into the relocation address.
            // that takes into account the location of the relocation symbol, any value
            // currently at the relocation address (addend), etc.
            let resolved_address = match (reloc.kind(), reloc.has_implicit_addend()) {
                (object::RelocationKind::Relative, true) => {
                    // S + A - P
                    //
                    // * S - The address of the symbol.
                    // * A - The value of the addend.
                    // * P - The address of the place of the relocation.
                    //
                    // add in the current offset encoded at the relocation address,
                    // such as within a call instruction's operand.
                    //
                    // when a COFF section contains more than one symbol,
                    // then this added can be non-zero.
                    (target + reloc.addend()) - reloc_va as i64
                }
                (object::RelocationKind::ImageOffset, true) => {
                    // S + A - Image
                    //
                    // * S - The address of the symbol.
                    // * A - The value of the addend.
                    //
                    // note: the image is assumed to be loaded at 0
                    // (though we load it elsewhere)
                    // so no adjustment needed here.

                    target + reloc.addend()
                }
                (object::RelocationKind::Absolute, true) => {
                    // S + A
                    //
                    // * S - The address of the symbol.
                    // * A - The value of the addend.
                    target + reloc.addend()
                }
                (object::RelocationKind::SectionOffset, true) => {
                    // S + A - Section
                    //
                    // * S - The address of the symbol.
                    // * A - The value of the addend.
                    // * Section - The address of the section containing the symbol.
                    //
                    // the computation of the target above includes the section address.
                    // so we don't need to include it here, as suggested.
                    //
                    // this makes me think there might be a bug lurking around.
                    target + reloc.addend()
                }
                (object::RelocationKind::Unknown, _) => {
                    if let object::RelocationFlags::Coff { typ } = reloc.flags() {
                        warn!("coff: reloc: unsupported kind: COFF({:?})", typ);
                        continue;
                    } else {
                        unimplemented!("relocation kind: {:?}", reloc.kind());
                    }
                }
                _ => unimplemented!("relocation kind: {:?}", reloc.kind()),
            };

            match reloc.size() {
                32 => {
                    fixups.push(Fixup {
                        address: reloc_va,
                        size:    FixupSize::_32,
                        value:   resolved_address,
                    });
                }
                64 => {
                    fixups.push(Fixup {
                        address: reloc_va,
                        size:    FixupSize::_64,
                        value:   resolved_address,
                    });
                }
                _ => unimplemented!("relocation size: {}", reloc.size()),
            }
        }
    }
    Ok(fixups)
}

fn apply_coff_fixups(module: &mut Module, fixups: Vec<Fixup>) -> Result<(), anyhow::Error> {
    for fixup in fixups.into_iter() {
        match fixup.size {
            FixupSize::_32 => {
                module.address_space.write_i32(fixup.address, fixup.value as i32)?;
            }
            FixupSize::_64 => {
                module.address_space.write_i64(fixup.address, fixup.value)?;
            }
        }
    }

    Ok(())
}

fn load_coff_relocations(
    module: &mut Module,
    obj: &object::File,
    externs: &BTreeMap<String, u64>,
) -> Result<(), anyhow::Error> {
    if let Some(symtab) = obj.symbol_table() {
        // we're only able to apply relocations if we can resolve symbols.

        let fixups = get_coff_fixups(module, obj, symtab, externs)?;
        apply_coff_fixups(module, fixups)?;
    }

    Ok(())
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

    let sections = load_coff_sections(&obj, base_address)?;

    let mut module = load_coff_module(buf, arch, base_address, sections)?;

    let symbols = get_coff_symbols(&obj, &module);

    let extern_names = get_coff_extern_names(&obj);

    let externs = load_coff_extern_section(&mut module, extern_names)?;

    load_coff_relocations(&mut module, &obj, &externs)?;

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
    use std::assert_eq;

    use anyhow::Result;

    use crate::{arch, aspace::AddressSpace, emu::mmu::PAGE_SIZE, loader::coff::get_section_by_name, rsrc::*};

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
                .unwrap_or_else(|_| panic!("read section {} {:#x} {:#x}", section.name, start, size));
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
    fn reloc_relative() -> Result<()> {
        //crate::test::init_logging();

        // IDA shows:
        //
        //```ignore
        //  .text$mn:0F  6A FF              push    0FFFFFFFFh
        //  .text$mn:11  68 CC 00 00 00     push    offset __ehhandler...
        //  .text$mn:16  64 A1 00 00 00 00  mov     eax, large fs:0
        //```
        //
        // and IDA has loaded .text$mn at 0xC
        // and __ehhandler$___dyn_tls_init@12 in section .text$x:000000CC
        //
        // so we see the relocation applied as CC 00 00 00 at 0x12.

        let buf = get_buf(Rsrc::TLSDYN);
        let coff = crate::loader::coff::COFF::from_bytes(&buf)?;

        // we load .text$mn at 0x20003000
        let textmn = get_section_by_name(&coff.module, ".text$mn")
            .unwrap()
            .virtual_range
            .start;
        assert_eq!(textmn, 0x20003000);

        // and the instruction with the relocation is at +5
        let relocated_instruction = textmn + 5;

        // we load __ehhandler$___dyn_tls_init@12 in section .text$x at 0x20007000
        let textx = get_section_by_name(&coff.module, ".text$x")
            .unwrap()
            .virtual_range
            .start;
        assert_eq!(textx, 0x20007000);
        let ehandler = coff
            .symbols
            .by_name
            .get("__ehhandler$___dyn_tls_init@12")
            .unwrap()
            .address;
        assert_eq!(ehandler, 0x20007000);

        // so we see the relocation applied as 00 70 00 20 at 0x20003006
        let v = coff.module.address_space.read_bytes(relocated_instruction, 0x5)?;
        assert_eq!(v, &[0x68, 0x00, 0x70, 0x00, 0x20]);

        // our instruction formatter renders this as:
        //   .text$mn:20003005  68 00 70 00 20  push    0x20007000
        // because its a push, so doesn't know its an address.
        let ws = crate::workspace::COFFWorkspace::from_coff(crate::workspace::config::empty(), coff)?;
        let insn = crate::test::read_insn(&ws.coff.module, relocated_instruction);
        let fmt = crate::workspace::formatter::Formatter::with_options()
            .with_colors(true)
            .with_hex_column_size(8)
            .build();

        log::debug!("{}", fmt.format_instruction(&ws, &insn, relocated_instruction).unwrap());

        Ok(())
    }

    #[test]
    fn reloc_extern() -> Result<()> {
        //crate::test::init_logging();

        // IDA shows:
        //
        //  .text$mn:1D  83 EC 08        sub esp, 8
        //  .text$mn:20  A1 40 01 00 00  mov eax, ds:___security_cookie
        //  .text$mn:25  33 C5           xor eax, ebp
        //
        // and IDA has loaded .text$mn at 0xC
        // and ___security_cookie in section UNDEF at 00000140
        //
        // so we see the relocation applied as 40 10 00 00 at 0x20.

        let buf = get_buf(Rsrc::TLSDYN);
        let coff = crate::loader::coff::COFF::from_bytes(&buf)?;

        // we load .text$mn at 0x20003000
        let textmn = get_section_by_name(&coff.module, ".text$mn")
            .unwrap()
            .virtual_range
            .start;
        assert_eq!(textmn, 0x20003000);

        // and the instruction with the relocation is at +14
        let relocated_instruction = textmn + 0x14;

        // we load ___security_cookie in section UNDEF at 0x2000C00C
        let undef = get_section_by_name(&coff.module, "UNDEF").unwrap().virtual_range.start;
        assert_eq!(undef, 0x2000C000);
        let cookie = coff.externs.get("___security_cookie").unwrap();
        assert_eq!(*cookie, 0x2000C00C);

        // so we see the relocation applied as 0C C0 00 20 at 0x20003014
        let v = coff.module.address_space.read_bytes(relocated_instruction, 0x5)?;
        assert_eq!(v, &[0xA1, 0x0C, 0xC0, 0x00, 0x20]);

        // our instruction formatter renders this as:
        //  .text$mn:2000303a  0F B6 82 00 00           mov     eax,
        // [___security_cookie]
        let ws = crate::workspace::COFFWorkspace::from_coff(crate::workspace::config::empty(), coff)?;
        let insn = crate::test::read_insn(&ws.coff.module, relocated_instruction);
        let fmt = crate::workspace::formatter::Formatter::with_options()
            .with_colors(true)
            .with_hex_column_size(8)
            .build();

        log::debug!("{}", fmt.format_instruction(&ws, &insn, relocated_instruction).unwrap());

        Ok(())
    }

    #[test]
    fn reloc_section() -> Result<()> {
        //crate::test::init_logging();

        // IDA shows:
        //
        //  .text$mn:43  8B 14 81              mov   edx, [ecx+eax*4]
        //  .text$mn:46  0F B6 82 00 00 00 00  movzx eax, _volmd[edx]
        //  .text$mn:4D  83 F8 01              cmp   eax, 1
        //
        // and IDA has loaded .text$mn at 0xC
        // and .tls$ at 00000000
        //
        // so we see the relocation applied as 00 00 00 00 at 0x46.

        let buf = get_buf(Rsrc::TLSDYN);
        let coff = crate::loader::coff::COFF::from_bytes(&buf)?;

        // we load .text$mn at 0x20003000
        let textmn = get_section_by_name(&coff.module, ".text$mn")
            .unwrap()
            .virtual_range
            .start;
        assert_eq!(textmn, 0x20003000);

        // and the instruction with the relocation is at +3A
        let relocated_instruction = textmn + 0x3A;

        // we load section .tls$ at 0x20000000
        let tls = get_section_by_name(&coff.module, ".tls$").unwrap().virtual_range.start;
        assert_eq!(tls, 0x20000000);

        // so we see the relocation applied as 00 00 00 20 at 0x2000303C
        let v = coff.module.address_space.read_bytes(relocated_instruction, 0x7)?;
        assert_eq!(v, &[0x0F, 0xB6, 0x82, 0x00, 0x00, 0x00, 0x20]);

        // our instruction formatter renders this as:
        //  .text$mn:2000303a  0F B6 82 00 00           mov     eax,
        // [___security_cookie]
        let ws = crate::workspace::COFFWorkspace::from_coff(crate::workspace::config::empty(), coff)?;
        let insn = crate::test::read_insn(&ws.coff.module, relocated_instruction);
        let fmt = crate::workspace::formatter::Formatter::with_options()
            .with_colors(true)
            .with_hex_column_size(8)
            .build();

        log::debug!("{}", fmt.format_instruction(&ws, &insn, relocated_instruction).unwrap());

        Ok(())
    }

    #[test]
    fn reloc_imageoffset() -> Result<()> {
        //crate::test::init_logging();

        // IDA shows:
        //
        //  .pdata:001710  A8 0C 00 00 01 0D 00 00  F8 16 00 00
        //
        //  .pdata:001710   $pdata$_vsscanf_l RUNTIME_FUNCTION
        //                  <rva _vsscanf_l,
        //                   rva algn_D01,
        //                   rva $unwind$_vsscanf_l>
        //
        // and IDA has loaded .pdata (section 47) at 0x1710
        // and _vsscanf_l at section .text$mn at 0000000000000CA8
        //
        // so we see the relocation applied as A8 0C 00 00 at 0x1710.

        let buf = get_buf(Rsrc::ALTSVC);
        let coff = crate::loader::coff::COFF::from_bytes(&buf)?;

        // we load .pdata (section 47) at 0x20017000
        let pdata = coff.symbols.by_name.get("$pdata$_vsscanf_l").unwrap().address;
        assert_eq!(pdata, 0x20017000);

        // we load _vsscanf_l in section .text$mn at 0x20009000
        let vsscanf = coff.symbols.by_name.get("_vsscanf_l").unwrap().address;
        assert_eq!(vsscanf, 0x20009000);

        // so we see the relocation applied as 00 90 00 20 at 0x20017000
        let v = coff.module.address_space.read_bytes(pdata, 0x4)?;
        assert_eq!(v, &[0x00, 0x90, 0x00, 0x20]);

        Ok(())
    }

    #[test]
    fn reloc_extern_section() -> Result<()> {
        //crate::test::init_logging();

        let buf = get_buf(Rsrc::_1MFCM140);
        let coff = crate::loader::coff::COFF::from_bytes(&buf)?;

        // first dword of .idata$2 is the address of .idata$4
        // which doesn't exist in the module,
        // but is an extern section.

        let idata2 = coff.symbols.by_name.get(".idata$2").unwrap().address;
        assert_eq!(idata2, 0x20000000);

        let idata4 = coff.externs.get(".idata$4").unwrap();
        assert_eq!(*idata4, 0x20002000);

        assert_eq!(coff.module.address_space.read_u32(idata2)? as u64, *idata4);

        // dword at .idata$2+0x10 is the address of .idata$5
        // which doesn't exist in the module,
        // but is an extern section.
        let idata5 = coff.externs.get(".idata$5").unwrap();
        assert_eq!(*idata5, 0x20002004);
        assert_eq!(coff.module.address_space.read_u32(idata2 + 0x10)? as u64, *idata5);

        Ok(())
    }

    #[test]
    fn reloc_unknown() -> Result<()> {
        //crate::test::init_logging();

        let buf = get_buf(Rsrc::POSTDLLMAIN);
        crate::loader::coff::COFF::from_bytes(&buf)?;

        // there's a relocation with an unknown symbol kind,
        // this we can assume is an extern symbol and handle that.
        //
        // there's a relocation with an unknown kind,
        // this we *cannot* handle, so we skip it.
        //
        // we should be able to load, but we won't touch the relocations.

        Ok(())
    }
}
