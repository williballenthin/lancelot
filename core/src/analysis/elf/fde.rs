use anyhow::Result;
use goblin::{elf, pe::debug};
use log::debug;

use crate::{
    loader::elf::ELF,
    VA,
};

pub fn find_fde_function_starts(elf: &ELF, goblin_elf: &elf::Elf) -> Result<Vec<VA>> {
    use crate::analysis::{dis, heuristics};
    
    let mut function_starts = Vec::new();

    let eh_frame_section = goblin_elf.section_headers.iter()
        .find(|sh| {
            if let Some(name) = goblin_elf.shdr_strtab.get_at(sh.sh_name) {
                name == ".eh_frame"
            } else {
                false
            }
        });

    if let Some(eh_frame_sh) = eh_frame_section {
        let section_offset = eh_frame_sh.sh_offset as usize;
        let section_size = eh_frame_sh.sh_size as usize;
        let section_addr = eh_frame_sh.sh_addr;
        
        if section_offset + section_size <= elf.buf.len() {
            let eh_frame_data = &elf.buf[section_offset..section_offset + section_size];
            
            debug!("elf: parsing .eh_frame section at offset {:#x}, size {:#x}, addr {:#x}", 
                   section_offset, section_size, section_addr);

            if let Ok(fdes) = parse_eh_frame(eh_frame_data, section_addr, elf.module.address_space.base_address) {
                let decoder = dis::get_disassembler(&elf.module)?;
                
                for fde in fdes {
                    let pc_begin = fde.pc_begin;
                    function_starts.push(pc_begin);
                }
            }
        }
    }

    Ok(function_starts)
}



#[derive(Debug, Clone)]
struct FrameDescriptorEntry {
    pc_begin: VA,
    pc_range: u64,
}
// parsing .eh_frame to extract FDEs
fn parse_eh_frame(data: &[u8], section_addr: u64, base_address: VA) -> Result<Vec<FrameDescriptorEntry>> {
    let mut fdes = Vec::new();
    let mut offset = 0;

    while offset + 8 <= data.len() {
        let length = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as usize;
        if length == 0 {
            break;
        }
        if length == 0xffffffff {
            offset += 4;
            if offset + 8 > data.len() {
                break;
            }
            continue;
        }

        let record_start = offset;
        offset += 4;

        if offset + length > data.len() {
            break;
        }
        let cie_id = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        offset += 4;

        if cie_id == 0 {
            offset = record_start + 4 + length;
            continue;
        }

        if offset + 16 <= data.len() {
            let pc_begin_field_offset = offset;
            let pc_begin_relative = i32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]) as i64;
            offset += 4;
            let pc_range = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]) as u64;
            offset += 4;
            let field_addr = section_addr + pc_begin_field_offset as u64;
            let pc_begin_abs = (field_addr as i64 + pc_begin_relative) as u64;
            let pc_begin = pc_begin_abs + base_address;

            if pc_begin != 0 && pc_range != 0 {
                fdes.push(FrameDescriptorEntry {
                    pc_begin,
                    pc_range,
                });
                debug!("elf: parsed FDE - pc_begin: {:#x}, pc_range: {:#x}", pc_begin, pc_range);
            }
        }
        offset = record_start + 4 + length;
    }

    Ok(fdes)
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
