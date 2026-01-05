use anyhow::Result;
use goblin::elf;
use log::debug;

use crate::{
    loader::elf::ELF,
    VA,
};

pub fn find_symtab_function_starts(elf: &ELF, goblin_elf: &elf::Elf) -> Result<Vec<VA>> {
    let mut function_starts = Vec::new();
    let base_address = elf.module.address_space.base_address;

    // parse .symtab
    for sym in &goblin_elf.syms {
        if is_function_symbol(&sym) && sym.st_value != 0 {
            let address = sym.st_value + base_address;
            function_starts.push(address);
            debug!("elf: found function symbol at {:#x} (size: {:#x})", address, sym.st_size);
        }
    }

    // parse .dynsym
    for sym in &goblin_elf.dynsyms {
        if is_function_symbol(&sym) && sym.st_value != 0 {
            let address = sym.st_value + base_address;
            function_starts.push(address);
            debug!("elf: found dynamic function symbol at {:#x} (size: {:#x})", address, sym.st_size);
        }
    }

    Ok(function_starts)
}

fn is_function_symbol(sym: &elf::Sym) -> bool {
    sym.st_type() == elf::sym::STT_FUNC
}

#[cfg(test)]
mod tests {
    use crate::rsrc::*;
    use anyhow::Result;
    use super::find_symtab_function_starts;

    #[test]
    fn nop_elf() -> Result<()> {
        let buf = get_buf(Rsrc::NOPELF);
        let elf = crate::loader::elf::ELF::from_bytes(&buf)?;
        let goblin_elf = goblin::elf::Elf::parse(&elf.buf)?;

        let function_starts = find_symtab_function_starts(&elf, &goblin_elf)?;
        println!("function_starts: {}", function_starts.len());
        for start in function_starts.iter() {
            println!("{start:#x}");
        }
        
        assert_eq!(0, function_starts.len());

        Ok(())
    }


    // based on this command: "readelf -s /lancelot/core/resources/test/libc | grep ' FUNC ' | grep -v ' UND ' | grep -v ' 0000000000000000 ' | wc -l"
    #[test]
    fn libc() -> Result<()> {
        let buf = get_buf(Rsrc::LIBCSO6);
        let elf = crate::loader::elf::ELF::from_bytes(&buf)?;
        let goblin_elf = goblin::elf::Elf::parse(&elf.buf)?;

        let function_starts = find_symtab_function_starts(&elf, &goblin_elf)?;
        println!("libc function_starts: {}", function_starts.len());
        
        assert_eq!(2856, function_starts.len());

        Ok(())
    }
}