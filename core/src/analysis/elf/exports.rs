use anyhow::Result;
use goblin::elf;
use log::debug;

use crate::{loader::elf::ELF, module::Permissions, VA};

pub fn find_elf_exports(elf: &ELF) -> Result<Vec<VA>> {
    // parse the ELF file
    let goblin_elf = elf::Elf::parse(&elf.buf)?;

    let mut exports: Vec<VA> = Vec::new();

    // add exported functions from dynsym
    for sym in goblin_elf.dynsyms.iter() {
        if sym.st_type() == elf::sym::STT_FUNC 
            && sym.st_shndx != elf::section_header::SHN_UNDEF as usize 
            && sym.st_value != 0 
        {
            let addr = sym.st_value + elf.module.address_space.base_address;

            if elf.module.probe_va(addr, Permissions::X) {
                debug!("elf: found exported function in dynsym: {:#x} (sym value: {:#x})", addr, sym.st_value);
                exports.push(addr);
            }
        }
    }

    // add exported functions from regular symbol table
    for sym in goblin_elf.syms.iter() {
        if sym.st_type() == elf::sym::STT_FUNC 
            && sym.st_shndx != elf::section_header::SHN_UNDEF as usize 
            && sym.st_value != 0 
            && sym.st_bind() == elf::sym::STB_GLOBAL
        {
            let addr = sym.st_value + elf.module.address_space.base_address;
            
            if elf.module.probe_va(addr, Permissions::X) {
                debug!("elf: found exported function in symtab: {:#x} (sym value: {:#x})", addr, sym.st_value);
                if !exports.contains(&addr) {
                    exports.push(addr);
                }
            }
        }
    }
    exports.sort();
    exports.dedup();

    for export in exports.iter() {
        debug!("elf export: {export:#x}");
    }
    if exports.is_empty() {
        debug!("elf exports: none");
    }

    Ok(exports)
}

#[cfg(test)]
mod tests {
    use crate::rsrc::*;
    use anyhow::Result;
    use super::find_elf_exports;
    use log::debug;

    #[test]
    fn nop_elf() -> Result<()> {
        let buf = get_buf(Rsrc::NOPELF);
        let elf = crate::loader::elf::ELF::from_bytes(&buf)?;

        let exports = find_elf_exports(&elf)?;
        assert_eq!(0, exports.len());
        Ok(())
    }

    #[test]
    fn tiny_elf() -> Result<()> {
        let buf = get_buf(Rsrc::TINYX64);
        let elf = crate::loader::elf::ELF::from_bytes(&buf)?;

        let exports = find_elf_exports(&elf)?;
        debug!("tiny_elf exports: {:?}", exports);
        assert_eq!(0, exports.len());
        Ok(())
    }

    #[test]
    fn libc_elf() -> Result<()> {
        let buf = get_buf(Rsrc::LIBCSO6);
        let elf = crate::loader::elf::ELF::from_bytes(&buf)?;

        let exports = find_elf_exports(&elf)?;
        // this value contains more symbols types causing the fail
        assert_eq!(2428, exports.len());
        Ok(())
    }
}