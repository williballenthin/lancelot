use std::collections::BTreeMap;

use anyhow::Result;
use log::debug;

use crate::{
    arch::Arch,
    emu::{mmu::MMU, plat, Emulator},
    loader::pe::PE,
    VA,
};

use super::WindowsEmulator;

pub struct Win64Emulator {
    pub inner: Emulator,
    imports:   BTreeMap<VA, String>,
}

impl Default for Win64Emulator {
    fn default() -> Self {
        Win64Emulator {
            inner:   Emulator::with_arch(Arch::X64),
            imports: Default::default(),
        }
    }
}

impl WindowsEmulator for Win64Emulator {
    fn load_pe(&mut self, pe: &PE) -> Result<()> {
        debug!("emu: plat: win64: load pe");

        self.inner.load_module(&pe.module)?;

        let imports = plat::win::link_imports(&mut self.inner, pe)?;
        self.imports.extend(imports);

        Ok(())
    }

    fn mem(&mut self) -> &mut MMU {
        &mut self.inner.mem
    }

    fn set_pc(&mut self, addr: VA) {
        self.inner.reg.set_rip(addr);
    }

    fn pc(&self) -> VA {
        self.inner.reg.rip() as VA
    }

    fn set_sp(&mut self, addr: VA) {
        self.inner.reg.set_rsp(addr);
    }

    fn sp(&self) -> VA {
        self.inner.reg.rsp() as VA
    }

    /// Errors:
    ///   - WriteError::AddressNotMapped when stack is not mapped.
    ///   - WriteError::AccessViolation when stack is not writable.
    fn push(&mut self, value: u64) -> Result<()> {
        let old_sp = self.sp();
        let new_sp = old_sp - 8;

        // write to mem first, since it could fail.
        self.mem().write_u64(new_sp, value)?;
        self.set_sp(new_sp);

        Ok(())
    }

    /// Errors:
    ///   - ReadError::AddressNotMapped when stack is not mapped.
    ///   - ReadError::AccessViolation when stack is not readable.
    fn pop(&mut self) -> Result<u64> {
        let old_sp = self.sp();
        let new_sp = old_sp + 8;

        // write to mem first, since it could fail.
        let value = self.mem().read_u64(old_sp)?;
        self.set_sp(new_sp);

        Ok(value)
    }

    fn set_bp(&mut self, addr: VA) {
        self.inner.reg.set_rbp(addr);
    }

    fn bp(&self) -> VA {
        self.inner.reg.rsp() as VA
    }

    fn set_fsbase(&mut self, addr: VA) {
        self.inner.set_fsbase(addr);
    }

    // TODO: sketching this out
    fn resolve_address(&self, addr: VA) -> Option<String> {
        self.imports.get(&addr).cloned()
    }
}
