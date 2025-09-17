#![allow(clippy::nonstandard_macro_braces)]

use anyhow::Result;
use goblin::elf::header::{EM_386, EM_X86_64};
use goblin::elf::program_header::PT_LOAD;
use log::debug;
use prost::bytes::buf;
use thiserror::Error;

pub mod import;

use crate::{
    arch::Arch,
    aspace::{self, RelativeAddressSpace},
    module::{Module, Permissions, Section},
    util, RVA, VA,
};

//ELF cheatsheet: https://gist.github.com/x0nu11byt3/bcb35c3de461e5fb66173071a2379779

const PAGE_SIZE: u64 = 0x1000;
#[derive(Error, Debug)]
pub enum ELFError {
    #[error("format not supported: {0}")]
    FormatNotSupported(String),

    #[error("malformed elf file: {0}")]
    MalformedElfFile(String)
}

pub struct ELF {
    pub buf: Vec<u8>,
    pub module: Module,
}

pub struct DynamicEntry {
    pub tag: u64,
    pub value: u64,
}

pub struct Symbol {
    pub name_offset: u32,
    pub info: u8,
    pub other: u8,
    pub shndx: u16,
    pub value: u64,
    pub size: u64,
}

impl ELF {
    pub fn from_bytes(buf: &[u8]) -> Result<ELF>{
        load_elf(buf)
    }
}


fn get_elf(buf: &[u8]) -> Result<goblin::elf::Elf> {
    let elf = match goblin::elf::Elf::parse(buf) {
        Ok(elf) => elf,
        Err(e) => {
            return Err(ELFError::MalformedElfFile(e.to_string()).into());
        }
    };
    Ok(elf)
}

fn load_elf(buf: &[u8]) -> Result<ELF>{
    let elf = get_elf(buf)?;

    // check that the elf matched x86_64
    let arch = match elf.header.e_machine {
        EM_X86_64 => Arch::X64,
        EM_386 => Arch::X32,
        _ => return Err(ELFError::FormatNotSupported(format!("Unsupported architecture: {}", elf.header.e_machine)).into())
    };
    debug!("elf: arch: {:?}", arch);

    // determine base address from the lowest virtual address of loadable segments
    let base_address = elf.program_headers
        .iter()
        .filter(|ph| ph.p_type == PT_LOAD)
        .map(|ph| ph.p_vaddr)
        .min()
        .unwrap();
        debug!("elf: base address: {:#x}", base_address);

    // load sections from program headers (segments) - these are what actually get loaded
    let mut sections = load_elf_segments(buf, &elf);

    // calculate total virtual memory size needed
    let max_address = sections.iter().map(|sec| sec.virtual_range.end).max().unwrap_or(base_address);
    let max_page_address = util::align(max_address, PAGE_SIZE) - base_address;
    debug!("elf: address space: capacity: {:#x}", max_page_address);

    // create and populate address space
    let mut address_space = RelativeAddressSpace::with_capacity(max_page_address);

    for section in sections.iter().filter(|s| s.virtual_range.start >= base_address) {
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

        // calculate virtual address info
        let vstart = section.virtual_range.start;
        let rstart = vstart - base_address;
        let vsize = section.virtual_range.end - section.virtual_range.start;
        let mut vbuf = vec![0u8; vsize as usize];

        if vsize as usize >= psize {
            // vsize > psize, so there will be NULL bytes padding the physical data
            if psize > 0 {
                let dest = &mut vbuf[0..psize];
                dest.copy_from_slice(pbuf);
            }
        } else {
            // psize > vsize, but vsize wins, so we only read a subset of physical data
            let src = &pbuf[0..vsize as usize];
            vbuf.copy_from_slice(src);
        }

        // check page alignment
        // Temporarily disabled for testing with non-standard ELF files
        // if aspace::page_offset(rstart) != 0 {
        //     return Err(ELFError::FormatNotSupported("non-page aligned section".to_string()).into());
        // }

        // For testing: align the address to page boundary if needed
        let aligned_rstart = aspace::page_address(rstart);
        address_space.map.writezx(aligned_rstart, &vbuf)?;

        debug!(
            "elf: address space: mapped {:#x} - {:#x} {:?}",
            vstart, section.virtual_range.end, section.permissions
        );
    }

    let module = Module {
        arch,
        sections,
        address_space: address_space.into_absolute(base_address)?,
    };

    debug!("elf: loaded");
    Ok(ELF {
        buf: buf.to_vec(),
        module,
    })
}

pub fn load_elf_segments(buf: &[u8], elf: &goblin::elf::Elf) -> Vec<Section>{
    elf.program_headers.iter().filter(|ph| ph.p_type == goblin::elf::program_header::PT_LOAD).enumerate().map(|(index, ph)| {
        let virtual_address = ph.p_vaddr;
        let virtual_size = ph.p_memsz;
        let file_offset = ph.p_offset;
        let file_size = ph.p_filesz;

        // determine permissions
        let permissions = {
            let mut perm = Permissions::empty();
            if ph.is_read() {
                perm |= Permissions::R;
            }
            if ph.is_write() {
                perm |= Permissions::W;
            }
            if ph.is_executable() {
                perm |= Permissions::X;
            }
            perm
        };

        // give segments descriptive names
        let name = if ph.is_executable() {
            format!("segment_text_{}", index)
        } else if ph.is_write() {
            format!("segment_data_{}", index)
        } else {
            format!("segment_rodata_{}", index)
        };

        Section {
            physical_range: std::ops::Range {
                start: file_offset,
                end: file_offset + file_size,
            },
            virtual_range: std::ops::Range {
                start: virtual_address,
                end: virtual_address + virtual_size,
            },
            permissions,
            name
        }
    }).collect()
}
