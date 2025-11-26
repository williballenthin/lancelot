use anyhow::Result;
use goblin::elf;
use log::debug;

use crate::{loader::elf::ELF, VA};

pub fn find_elf_entrypoint(elf: &ELF) -> Result<Vec<VA>> {
    // parse the ELF file
    let goblin_elf = elf::Elf::parse(&elf.buf)?;

    if goblin_elf.header.e_entry == 0 {
        debug!("elf: no entry point");
        return Ok(vec![]);
    }

    let entry_point = goblin_elf.header.e_entry + elf.module.address_space.base_address;
    debug!("elf: entry point: {entry_point:#x}");
    Ok(vec![entry_point])
}

#[cfg(test)]
mod tests {
    use crate::rsrc::*;
    use anyhow::Result;
    use super::find_elf_entrypoint;

    #[test]
    fn nop_elf() -> Result<()> {
        let buf = get_buf(Rsrc::NOPELF);
        let elf = crate::loader::elf::ELF::from_bytes(&buf)?;

        let entrypoints = find_elf_entrypoint(&elf)?;
        assert_eq!(1, entrypoints.len());

        Ok(())
    }

    #[test]
    fn tiny_elf() -> Result<()> {
        let buf = get_buf(Rsrc::TINYX64);
        let elf = crate::loader::elf::ELF::from_bytes(&buf)?;

        let entrypoints = find_elf_entrypoint(&elf)?;
        assert_eq!(0, entrypoints.len());

        Ok(())
    }

    #[test]
    fn libc_elf() -> Result<()> {
        let buf = get_buf(Rsrc::LIBCSO6);
        let elf = crate::loader::elf::ELF::from_bytes(&buf)?;

        let entrypoints = find_elf_entrypoint(&elf)?;
        assert_eq!(1, entrypoints.len());

        Ok(())
    }
}