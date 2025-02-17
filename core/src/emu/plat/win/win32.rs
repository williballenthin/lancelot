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

pub struct Win32Emulator {
    pub inner: Emulator,
    imports:   BTreeMap<VA, String>,
}

impl Default for Win32Emulator {
    fn default() -> Self {
        Win32Emulator {
            inner:   Emulator::with_arch(Arch::X32),
            imports: Default::default(),
        }
    }
}

impl WindowsEmulator for Win32Emulator {
    fn load_pe(&mut self, pe: &PE) -> Result<()> {
        debug!("emu: plat: win32: load pe");

        self.inner.load_module(&pe.module)?;

        let imports = plat::win::link_imports(&mut self.inner, pe)?;
        self.imports.extend(imports);

        Ok(())
    }

    fn mem(&mut self) -> &mut MMU {
        &mut self.inner.mem
    }

    fn set_pc(&mut self, addr: VA) {
        self.inner.reg.set_eip(addr as u32);
    }

    fn pc(&self) -> VA {
        self.inner.reg.eip() as VA
    }

    fn set_sp(&mut self, addr: VA) {
        self.inner.reg.set_esp(addr as u32);
    }

    fn sp(&self) -> VA {
        self.inner.reg.esp() as VA
    }

    /// note: truncates `value` to u32.
    ///
    /// Errors:
    ///   - WriteError::AddressNotMapped when stack is not mapped.
    ///   - WriteError::AccessViolation when stack is not writable.
    fn push(&mut self, value: u64) -> Result<()> {
        let old_sp = self.sp();
        let new_sp = old_sp - 4;

        // write to mem first, since it could fail.
        self.mem().write_u32(new_sp, value as u32)?;
        self.set_sp(new_sp);

        Ok(())
    }

    /// note: returns u32 value.
    ///
    /// Errors:
    ///   - ReadError::AddressNotMapped when stack is not mapped.
    ///   - ReadError::AccessViolation when stack is not readable.
    fn pop(&mut self) -> Result<u64> {
        let old_sp = self.sp();
        let new_sp = old_sp + 4;

        // write to mem first, since it could fail.
        let value = self.mem().read_u32(old_sp)? as u64;
        self.set_sp(new_sp);

        Ok(value)
    }

    fn set_bp(&mut self, addr: VA) {
        self.inner.reg.set_ebp(addr as u32);
    }

    fn bp(&self) -> VA {
        self.inner.reg.esp() as VA
    }

    fn set_fsbase(&mut self, addr: VA) {
        self.inner.set_fsbase(addr);
    }

    // TODO: sketching this out
    fn resolve_address(&self, addr: VA) -> Option<String> {
        self.imports.get(&addr).cloned()
    }
}

impl Win32Emulator {
    pub fn handle_api(&mut self) -> Result<()> {
        use super::api::CallingConvention;

        if let Some(symbol) = self.resolve_address(self.pc()) {
            if let Some(api) = super::api::API.get(&symbol) {
                let ra = self.pop()?;
                self.set_pc(ra);

                if let CallingConvention::Stdcall = api.calling_convention {
                    for _ in 0..api.arguments.len() {
                        let _ = self.pop()?;
                    }
                }

                Ok(())
            } else {
                // we dont know anything about the API
                // its probably stdcall, but we dont know how many arguments.
                // TODO
                unimplemented!("unknown API");
            }
        } else {
            // we don't know what API this is.
            // TODO
            unimplemented!("unresolved API");
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        emu::{plat::win::win32::*, *},
        rsrc::*,
    };

    /// Errors:
    ///   - FetchError::InvalidInstruction for instructions that cannot be
    ///     decoded.
    ///   - FetchError::AddressNotMapped when the instruction address is not
    ///     mapped.
    ///   - FetchError::AccessViolation when the instruction address is not
    ///     executable.
    ///   - WriteError::AddressNotMapped when a memory address is not mapped.
    ///   - WriteError::AccessViolation when a memory address is not executable.
    ///   - ReadError::AddressNotMapped when a memory address is not mapped.
    ///   - ReadError::AccessViolation when a memory address is not readable.
    ///
    /// TODO: this routine should not be part of the base emulator.
    /// there are too many customizations to handle, like how to deal with
    /// imports, styles of breakpoints, etc.
    /// so, provide documentation/examples of `step` routines and remove this.
    fn step(emu: &mut Win32Emulator) -> Result<()> {
        let insn = emu.inner.fetch()?;
        emu.inner.execute(&insn)?;

        // example: https://github.com/williballenthin/viv-utils/blob/master/viv_utils/emulator_drivers.py

        Ok(())
    }

    #[test]
    fn nop() -> Result<()> {
        //init_logging();

        let pe = crate::loader::pe::PE::from_bytes(&get_buf(Rsrc::NOP))?;

        let mut emu: Win32Emulator = Default::default();
        emu.load_pe(&pe)?;

        let opt = pe.optional_header.unwrap();
        let ep = opt.windows_fields.image_base + opt.standard_fields.address_of_entry_point;
        emu.set_pc(ep);

        emu.mem().mmap(0x5000, 0x2000, Permissions::RW)?;
        emu.set_sp(0x6000);
        emu.set_bp(0x6000);

        emu.mem().mmap(0x7000, 0x1000, Permissions::RW)?;
        emu.set_fsbase(0x7000);

        // .text:00401081 push    18h
        // .text:00401083 push    offset stru_406160
        // .text:00401088 call    __SEH_prolog
        assert_eq!(emu.pc(), 0x401081);
        step(&mut emu)?; // push
        step(&mut emu)?; // push
        step(&mut emu)?; // call

        // .text:004027A0 __SEH_prolog proc near
        // .text:004027A0 push    offset __except_handler3
        // .text:004027A5 mov     eax, large fs:0
        // .text:004027AB push    eax
        // .text:004027AC mov     eax, [esp+8+arg_4]
        // .text:004027B0 mov     [esp+8+arg_4], ebp
        // .text:004027B4 lea     ebp, [esp+8+arg_4]
        // .text:004027B8 sub     esp, eax
        assert_eq!(emu.pc(), 0x4027A0);
        step(&mut emu)?; // push
        step(&mut emu)?; // mov
        step(&mut emu)?; // push
        step(&mut emu)?; // mov
        step(&mut emu)?; // mov
        step(&mut emu)?; // lea
        step(&mut emu)?; // sub

        while emu.pc() != 0x4027DA {
            step(&mut emu)?;
        }

        // .text:004027DA retn
        step(&mut emu)?; // retn
        assert_eq!(emu.pc(), 0x40108D);

        // .text:0040108D mov     edi, 94h ; '”'
        // .text:00401092 mov     eax, edi
        // .text:00401094 call    __alloca_probe
        step(&mut emu)?; // mov
        step(&mut emu)?; // mov
        step(&mut emu)?; // call
        assert_eq!(emu.pc(), 0x402900);

        // .text:00402900 cmp     eax, 1000h
        // .text:00402905 jnb     short probesetup
        step(&mut emu)?; // cmp
        step(&mut emu)?; // jnb
        assert_eq!(emu.pc(), 0x402907);

        // .text:00402907 neg     eax
        // .text:00402909 add     eax, esp
        // .text:0040290B add     eax, 4
        // .text:0040290E test    [eax], eax
        // .text:00402910 xchg    eax, esp
        // .text:00402911 mov     eax, [eax]
        // .text:00402913 push    eax
        // .text:00402914 retn
        step(&mut emu)?; // neg
        step(&mut emu)?; // add
        step(&mut emu)?; // add
        step(&mut emu)?; // test
        step(&mut emu)?; // xchg
        step(&mut emu)?; // mov
        step(&mut emu)?; // push
        step(&mut emu)?; // ret
        assert_eq!(emu.pc(), 0x401099);

        // .text:00401099 mov     [ebp+ms_exc.old_esp], esp
        // .text:0040109C mov     esi, esp
        // .text:0040109E mov     [esi], edi
        // .text:004010A0 push    esi             ; lpVersionInformation
        step(&mut emu)?; // mov
        step(&mut emu)?; // mov
        step(&mut emu)?; // mov
        step(&mut emu)?; // push

        // handling imports:
        //
        // next is call to import GetVersionExA.
        // .text:004010A1 call    ds:GetVersionExA
        assert_eq!(emu.pc(), 0x4010A1);
        step(&mut emu)?; // call ds:[0x406008]

        // we've mapped the IAT entry to point to the OFT.
        //
        //     FT          OFT
        //     0x406008 -> 0x406e88 (hint: 0x01DF, name: GetVersionExA)
        assert_eq!(emu.pc(), 0x406e88);

        // but this isn't a code segment,
        // so if we try to execute it, it will fail with a FetchError
        let e = step(&mut emu).unwrap_err(); // GetVersionExA impl

        // demonstrate how to recover the called imported API.
        if let Some(FetchError::AccessViolation { va, .. }) = e.downcast_ref::<FetchError>() {
            assert_eq!(emu.resolve_address(*va).unwrap(), "kernel32.dll!GetVersionExA");
        }

        emu.handle_api()?;
        assert_eq!(emu.pc(), 0x4010A7);

        Ok(())
    }
}
