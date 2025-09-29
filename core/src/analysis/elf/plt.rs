use std::collections::BTreeSet;
use anyhow::Result;
use goblin::elf;
use log::debug;

use crate::{
    loader::elf::ELF,
    VA,
};

pub fn find_plt_function_starts(elf: &ELF, goblin_elf: &elf::Elf) -> Result<BTreeSet<VA>> {
    let mut function_starts: BTreeSet<VA> = Default::default();

    // add .plt entries
    if let Some(plt_section) = find_section_by_name(goblin_elf, ".plt") {
        let plt_start = plt_section.sh_addr;
        let plt_size = plt_section.sh_size;
        let entry_size = 16;
        let mut addr = plt_start;
        
        while addr < plt_start + plt_size {
            let final_addr = addr + elf.module.address_space.base_address;
            debug!("elf: found function start in .plt: {:#x}", final_addr);
            function_starts.insert(final_addr);
            addr += entry_size;
        }
    }

    // add .plt.got entries
    if let Some(plt_got_section) = find_section_by_name(goblin_elf, ".plt.got") {
        let plt_got_start = plt_got_section.sh_addr;
        let plt_got_size = plt_got_section.sh_size;
        let entry_size = 16;
        let mut addr = plt_got_start;
        
        while addr < plt_got_start + plt_got_size {
            let final_addr = addr + elf.module.address_space.base_address;
            debug!("elf: found function start in .plt.got: {:#x}", final_addr);
            function_starts.insert(final_addr);
            addr += entry_size;
        }
    }

    Ok(function_starts)
}

// helper function to find a section by name
fn find_section_by_name<'a>(elf: &'a elf::Elf<'a>, name: &'a str) -> Option<&'a elf::SectionHeader> {
    elf.section_headers.iter().find(|sh| {
        elf.shdr_strtab.get_at(sh.sh_name)
            .map(|section_name| section_name == name)
            .unwrap_or(false)
    })
}