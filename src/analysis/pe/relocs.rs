use num::{FromPrimitive, ToPrimitive};
use std::marker::PhantomData;

use byteorder::{ByteOrder, LittleEndian};
use log::{debug};
use goblin::{Object};
use failure::{Error, Fail};

use super::super::super::arch::Arch;
use super::super::super::workspace::Workspace;
use super::super::{Analyzer};


#[derive(Debug, Fail)]
pub enum RelocAnalyzerError {
    #[fail(display = "Invalid relocation type")]
    InvalidRelocType,
}

pub struct RelocAnalyzer<A: Arch> {
    // This Analyzer must have a type parameter for it
    //  to implement Analyzer<A>.
    // however, it doesn't actually use this type itself.
    // so, we use a phantom data marker which has zero type,
    //  to ensure there is not an unused type parameter,
    //  which is a compile error.
    _phantom: PhantomData<A>,
}

impl<A: Arch> RelocAnalyzer<A> {
    pub fn new() -> RelocAnalyzer<A> {
        RelocAnalyzer {
            _phantom: PhantomData {},
        }
    }
}

struct Section<A: Arch> {
    start: A::RVA,
    end: A::RVA,
}

fn is_in_insn<A: Arch + 'static>(ws: &Workspace<A>, rva: A::RVA) -> bool {
    let start: usize = rva.to_usize().unwrap();
    // TODO: remove harded max insn length
    // TODO: underflow
    let end: usize = rva.to_usize().unwrap() - 0x10;

    for i in (start..end).rev() {
        let i = A::RVA::from_usize(i).unwrap();
        if let Some(meta) = ws.get_meta(i) {
            if !meta.is_insn() {
                continue;
            }

            if let Ok(len) = meta.get_insn_length() {
                if i + A::RVA::from_u8(len).unwrap() > rva {
                    return true;
                }
            }
        }
    }
    return false;
}

fn is_ptr<A: Arch + 'static>(ws: &Workspace<A>, rva: A::RVA) -> bool {
    if let Ok(ptr) = ws.read_va(rva) {
        if let Some(ptr) = ws.rva(ptr) {
            return ws.probe(ptr, 1);
        }
    }
    return false;
}


pub enum RelocationType {
    ImageRelBasedAbsolute,
    ImageRelBasedHigh,
    ImageRelBasedLow,
    ImageRelBasedHighLow,
    ImageRelBasedHighAdj,

    // ImageRelBasedMIPS_JmpAddr,
    // ImageRelBasedARM_MOV32,
    // ImageRelBasedRiscV_High20,
    ImageRelArch1,

    ImageRelReserved,

    // ImageRelBasedTHUMB_MOV32,
    // ImageRelBasedRiscV_Low12I,
    ImageRelArch2,

    ImageRelBasedRiscVLow12S,
    ImageRelBasedMIPSJmpAddr16,
    ImageRelBasedDir64,
}

pub struct Reloc<A: Arch> {
    pub typ: RelocationType,
    pub offset: A::RVA,
}

fn parse_reloc<A: Arch>(base: A::RVA, entry: u16) -> Result<Reloc<A>, Error> {
    let reloc_type   = (entry & 0b1111000000000000) >> 12;
    let reloc_offset =  entry & 0b0000111111111111;

    // TODO: this should probably be on `RelocationType` as a `From` trait.
    let reloc_type = match reloc_type {
        0 => RelocationType::ImageRelBasedAbsolute,
        1 => RelocationType::ImageRelBasedHigh,
        2 => RelocationType::ImageRelBasedLow,
        3 => RelocationType::ImageRelBasedHighLow,
        4 => RelocationType::ImageRelBasedHighAdj,
        5 => RelocationType::ImageRelArch1,
        6 => RelocationType::ImageRelReserved,
        7 => RelocationType::ImageRelArch2,
        8 => RelocationType::ImageRelBasedRiscVLow12S,
        9 => RelocationType::ImageRelBasedMIPSJmpAddr16,
        10 => RelocationType::ImageRelBasedDir64,
        _ => return Err(RelocAnalyzerError::InvalidRelocType.into()),
    };

    Ok(Reloc {
        typ: reloc_type,
        offset: base + A::RVA::from_u16(reloc_offset).unwrap(),
    })
}

fn split_u32(e: u32) -> (u16, u16) {
    let m = ((e & 0x0000FFFF) >>  0) as u16;
    let n = ((e & 0xFFFF0000) >> 16) as u16;
    (m, n)
}


/// ```
/// use lancelot::rsrc::*;
/// use lancelot::arch::*;
/// use lancelot::workspace::Workspace;
/// use lancelot::analysis::pe::relocs;
///
/// let mut ws = Workspace::<Arch64>::from_bytes("k32.dll", &get_buf(Rsrc::K32))
///    .disable_analysis()
///    .load().unwrap();
/// let relocs = relocs::get_relocs(&ws).unwrap();
/// assert_eq!(relocs[0].offset,   0x76008);
/// assert_eq!(relocs[277].offset, 0xA8000);
/// ```
pub fn get_relocs<A: Arch + 'static>(ws: &Workspace<A>) -> Result<Vec<Reloc<A>>, Error> {
    let pe = match Object::parse(&ws.buf) {
        Ok(Object::PE(pe)) => pe,
        _ => return Ok(vec![]),
    };

    let opt_header = match pe.header.optional_header {
        Some(opt_header) => opt_header,
        _ => return Ok(vec![]),
    };

    let reloc_directory = match opt_header.data_directories.get_base_relocation_table() {
        Some(reloc_directory) => reloc_directory,
        _ => return Ok(vec![]),
    };

    let dir_start = A::RVA::from_u32(reloc_directory.virtual_address).unwrap();
    let buf = ws.read_bytes(dir_start, reloc_directory.size as usize)?;

    let entries: Vec<u32> = buf
        .chunks_exact(0x4)
        .map(|b| LittleEndian::read_u32(b))
        .collect();

    let mut ret = vec![];
    let mut index = 0;
    loop {
        // parse base relocation chunk
        // until there's no data left

        let page_rva = entries.get(index);
        let block_size = entries.get(index+1);
        let (page_rva, block_size) = match (page_rva, block_size) {
            (Some(0),        _               ) => break,
            (_,              Some(0)         ) => break,
            (Some(page_rva), Some(block_size)) => (A::RVA::from_u32(*page_rva).unwrap(), *block_size),
            _ => break,
        };

        // cast from u32 to usize
        let chunk_entries_count = ((block_size) / 4) as usize;

        for i in 2..chunk_entries_count {
            if let Some(&entry) = entries.get(index + i) {
                let (m, n) = split_u32(entry);

                let reloc1 = parse_reloc::<A>(page_rva, m)?;
                if !ws.probe(reloc1.offset, 4) {
                    break
                }
                ret.push(reloc1);

                let reloc2 = parse_reloc::<A>(page_rva, n)?;
                if !ws.probe(reloc2.offset, 4) {
                    break
                }
                ret.push(reloc2);
            } else {
                break
            }
        };

        index += chunk_entries_count;
    }

    Ok(ret)
}


impl<A: Arch + 'static> Analyzer<A> for RelocAnalyzer<A> {
    fn get_name(&self) -> String {
        "PE relocation analyzer".to_string()
    }

    /// ```
    /// use lancelot::rsrc::*;
    /// use lancelot::arch::*;
    /// use lancelot::analysis::Analyzer;
    /// use lancelot::workspace::Workspace;
    /// use lancelot::analysis::pe::RelocAnalyzer;
    ///
    /// let mut ws = Workspace::<Arch64>::from_bytes("k32.dll", &get_buf(Rsrc::K32))
    ///    .disable_analysis()
    ///    .load().unwrap();
    /// let anal = RelocAnalyzer::<Arch64>::new();
    /// anal.analyze(&mut ws).unwrap();
    /// let meta = ws.get_meta(0xC7F0).unwrap();
    /// assert!(meta.is_insn());
    /// ```
    fn analyze(&self, ws: &mut Workspace<A>)-> Result<(), Error> {
        let text_section = match ws.module.sections.iter()
            // currently limited to the text section.
            // TODO: accept any writable section.
            .filter(|&sec| sec.name == ".text")
            .next() {
                None => return Ok(()),
                Some(s) => s,
            };

        let text_bounds = Section::<A> {
            start: text_section.addr,
            end: text_section.addr + A::RVA::from_usize(text_section.buf.len()).unwrap(),
        };

        // scan the relocations
        // looking for pointers into the .text section
        // to things that
        //   1. are not already in an instruction
        //   2. don't appear to be a pointer
        // and assume this is code.
        let o: Vec<A::RVA> = get_relocs(ws)?
            .iter()
            .map(|reloc| reloc.offset)
            .map(|rva| ws.read_va(rva))
            .filter_map(Result::ok)
            .filter_map(|va| ws.rva(va))
            .filter(|&rva| text_bounds.start <= rva)
            .filter(|&rva| rva < text_bounds.end)
            .filter(|&rva| !is_in_insn(ws, rva))
            .filter(|&rva| !is_ptr(ws, rva))
            // TODO: maybe ensure that the insn decodes.
            .collect();

        o.iter().for_each(|&rva| {
            debug!("found ptr from .text section to .text section at {:#x}", rva);

            // TODO: consume result
            ws.make_insn(rva).unwrap();
            // TODO: consume result
            ws.analyze().unwrap();
        });
        Ok(())
    }
}
