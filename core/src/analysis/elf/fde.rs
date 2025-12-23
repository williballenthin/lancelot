use anyhow::Result;
use byteorder::{BigEndian, ByteOrder, LittleEndian};
use gimli::{RunTimeEndian, UnwindSection};
use goblin::elf;
use log::debug;

use crate::{
    loader::elf::ELF,
    VA,
};

pub fn find_fde_function_starts(elf: &ELF, goblin_elf: &elf::Elf) -> Result<Vec<VA>> {
    let base_address = elf.module.address_space.base_address;
    let endian = if goblin_elf.header.endianness()? == goblin::container::Endian::Little {
        RunTimeEndian::Little
    } else {
        RunTimeEndian::Big
    };

    let mut function_starts = Vec::new();

    let Some((eh_frame_data, eh_frame_addr, eh_frame_offset)) =
        load_section(goblin_elf, &elf.buf, ".eh_frame")
    else {
        return Ok(function_starts);
    };

    let mut eh_frame_buf = eh_frame_data.to_vec();
    dyn_reloc(&mut eh_frame_buf, eh_frame_addr, goblin_elf, base_address, endian);

    let text_addr = load_section(goblin_elf, &elf.buf, ".text").map(|(_, addr, _)| addr);

    debug!(
        "elf: parsing .eh_frame section at offset {:#x}, size {:#x}, addr {:#x}",
        eh_frame_offset,
        eh_frame_data.len(),
        eh_frame_addr
    );

    function_starts.extend(parse_eh_frame_gimli(
        &eh_frame_buf,
        eh_frame_addr,
        text_addr,
        endian,
    )?);

    function_starts.sort();
    function_starts.dedup();
    Ok(function_starts)
}

fn load_section<'a>(
    goblin_elf: &goblin::elf::Elf,
    buf: &'a [u8],
    section_name: &str,
) -> Option<(&'a [u8], u64, usize)> {
    for section in &goblin_elf.section_headers {
        if let Some(name) = goblin_elf.shdr_strtab.get_at(section.sh_name) {
            if name == section_name {
                let start = section.sh_offset as usize;
                let end = start + section.sh_size as usize;
                if end <= buf.len() {
                    return Some((&buf[start..end], section.sh_addr, start));
                }
                return None;
            }
        }
    }
    None
}

fn parse_eh_frame_gimli( eh_frame_data: &[u8], eh_frame_addr: u64, text_addr: Option<u64>, endian: RunTimeEndian) -> Result<Vec<VA>> {
    let mut starts = Vec::new();

    let eh_frame = gimli::EhFrame::new(eh_frame_data, endian);

    let mut bases = gimli::BaseAddresses::default();
    bases = bases.set_eh_frame(eh_frame_addr);
    if let Some(text_addr) = text_addr {
        bases = bases.set_text(text_addr);
    }

    let mut entries = eh_frame.entries(&bases);
    while let Some(entry) = entries.next()? {
        match entry {
            gimli::CieOrFde::Cie(_) => {}
            gimli::CieOrFde::Fde(partial) => {
                let fde = partial.parse(|section, bases, offset| section.cie_from_offset(bases, offset))?;
                let pc_begin = fde.initial_address();
                let pc_range = fde.len();

                if pc_begin != 0 && pc_range != 0 {
                    starts.push(pc_begin as VA);
                    debug!(
                        "elf: gimli FDE - pc_begin: {:#x}, pc_range: {:#x}",
                        pc_begin, pc_range
                    );
                }
            }
        }
    }

    Ok(starts)
}

fn dyn_reloc(eh_frame_buf: &mut [u8], eh_frame_addr: u64, goblin_elf: &goblin::elf::Elf, base_address: VA, endian: RunTimeEndian) {
    let eh_len = eh_frame_buf.len() as u64;
    let eh_start = eh_frame_addr;
    let eh_end = eh_frame_addr.saturating_add(eh_len);
    let read_u64 = |buf: &[u8]| -> u64 {
        match endian {
            RunTimeEndian::Little => LittleEndian::read_u64(buf),
            RunTimeEndian::Big => BigEndian::read_u64(buf),
        }
    };
    let write_u64 = |buf: &mut [u8], value: u64| {
        match endian {
            RunTimeEndian::Little => LittleEndian::write_u64(buf, value),
            RunTimeEndian::Big => BigEndian::write_u64(buf, value),
        }
    };
    let read_u32 = |buf: &[u8]| -> u32 {
        match endian {
            RunTimeEndian::Little => LittleEndian::read_u32(buf),
            RunTimeEndian::Big => BigEndian::read_u32(buf),
        }
    };
    let write_u32 = |buf: &mut [u8], value: u32| {
        match endian {
            RunTimeEndian::Little => LittleEndian::write_u32(buf, value),
            RunTimeEndian::Big => BigEndian::write_u32(buf, value),
        }
    };

    for rela in goblin_elf.dynrelas.iter() {
        let place = rela.r_offset;
        if place < eh_start || place >= eh_end {
            continue;
        }
        let off = (place - eh_start) as usize;

        let addend_i64 = rela.r_addend.unwrap_or(0);

        if goblin_elf.is_64 {
            match rela.r_type {
                goblin::elf::reloc::R_X86_64_RELATIVE => {
                    if off + 8 <= eh_frame_buf.len() {
                        let value = base_address.wrapping_add(addend_i64 as u64);
                        write_u64(&mut eh_frame_buf[off..off + 8], value);
                    }
                }
                goblin::elf::reloc::R_X86_64_64 => {
                    if off + 8 <= eh_frame_buf.len() {
                        let sym = goblin_elf.dynsyms.get(rela.r_sym);
                        let s = sym.map(|s| s.st_value).unwrap_or(0);
                        let value = s.wrapping_add(addend_i64 as u64);
                        write_u64(&mut eh_frame_buf[off..off + 8], value);
                    }
                }
                goblin::elf::reloc::R_X86_64_PC32 => {
                    if off + 4 <= eh_frame_buf.len() {
                        let sym = goblin_elf.dynsyms.get(rela.r_sym);
                        let s = sym.map(|s| s.st_value).unwrap_or(0);
                        let p = place;
                        let value = (s as i64)
                            .wrapping_add(addend_i64)
                            .wrapping_sub(p as i64);
                        write_u32(&mut eh_frame_buf[off..off + 4], value as i32 as u32);
                    }
                }
                _ => {}
            }
        } else {
            match rela.r_type {
                goblin::elf::reloc::R_386_RELATIVE => {
                    if off + 4 <= eh_frame_buf.len() {
                        let value = (base_address as u32).wrapping_add(addend_i64 as u32);
                        write_u32(&mut eh_frame_buf[off..off + 4], value);
                    }
                }
                goblin::elf::reloc::R_386_32 => {
                    if off + 4 <= eh_frame_buf.len() {
                        let sym = goblin_elf.dynsyms.get(rela.r_sym);
                        let s = sym.map(|s| s.st_value as u32).unwrap_or(0);
                        let value = s.wrapping_add(addend_i64 as u32);
                        write_u32(&mut eh_frame_buf[off..off + 4], value);
                    }
                }
                goblin::elf::reloc::R_386_PC32 => {
                    if off + 4 <= eh_frame_buf.len() {
                        let sym = goblin_elf.dynsyms.get(rela.r_sym);
                        let s = sym.map(|s| s.st_value as u32).unwrap_or(0);
                        let p = place as u32;
                        let value = (s as i32)
                            .wrapping_add(addend_i64 as i32)
                            .wrapping_sub(p as i32);
                        write_u32(&mut eh_frame_buf[off..off + 4], value as u32);
                    }
                }
                _ => {}
            }
        }
    }

    for rel in goblin_elf.dynrels.iter() {
        let place = rel.r_offset;
        if place < eh_start || place >= eh_end {
            continue;
        }
        let off = (place - eh_start) as usize;
        if goblin_elf.is_64 {
            if off + 8 > eh_frame_buf.len() {
                continue;
            }
            let a = read_u64(&eh_frame_buf[off..off + 8]);
            match rel.r_type {
                goblin::elf::reloc::R_X86_64_RELATIVE => {
                    let value = base_address.wrapping_add(a);
                    write_u64(&mut eh_frame_buf[off..off + 8], value);
                }
                goblin::elf::reloc::R_X86_64_64 => {
                    let sym = goblin_elf.dynsyms.get(rel.r_sym);
                    let s = sym.map(|s| s.st_value).unwrap_or(0);
                    let value = s.wrapping_add(a);
                    write_u64(&mut eh_frame_buf[off..off + 8], value);
                }
                _ => {}
            }
        } else {
            if off + 4 > eh_frame_buf.len() {
                continue;
            }
            let a = read_u32(&eh_frame_buf[off..off + 4]);
            match rel.r_type {
                goblin::elf::reloc::R_386_RELATIVE => {
                    let value = (base_address as u32).wrapping_add(a);
                    write_u32(&mut eh_frame_buf[off..off + 4], value);
                }
                goblin::elf::reloc::R_386_32 => {
                    let sym = goblin_elf.dynsyms.get(rel.r_sym);
                    let s = sym.map(|s| s.st_value as u32).unwrap_or(0);
                    let value = s.wrapping_add(a);
                    write_u32(&mut eh_frame_buf[off..off + 4], value);
                }
                goblin::elf::reloc::R_386_PC32 => {
                    let sym = goblin_elf.dynsyms.get(rel.r_sym);
                    let s = sym.map(|s| s.st_value as u32).unwrap_or(0);
                    let p = place as u32;
                    let value = (s as i32).wrapping_add(a as i32).wrapping_sub(p as i32);
                    write_u32(&mut eh_frame_buf[off..off + 4], value as u32);
                }
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::rsrc::*;
    use anyhow::Result;
    use super::find_fde_function_starts;

    #[test]
    fn nop_elf() -> Result<()> {
        let buf = get_buf(Rsrc::NOPELF);
        let elf = crate::loader::elf::ELF::from_bytes(&buf)?;
        let goblin_elf = goblin::elf::Elf::parse(&elf.buf)?;

        let function_starts = find_fde_function_starts(&elf, &goblin_elf)?;
        print!("function_starts: {:?}", function_starts.len());
        for start in function_starts.iter() {
            print!("\n{start:#x}");
        }
        assert_eq!(3, function_starts.len());

        Ok(())
    }

    // will add a test for libc, but currently dont have an efficient way to count the base values
}
