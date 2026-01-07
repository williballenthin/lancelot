//! Helpers that are useful for tests and doctests.
use crate::{
    arch::Arch,
    aspace::{AddressSpace, RelativeAddressSpace},
    module::{Module, Permissions, Section},
    RVA, VA,
};

/// configure a global logger at level==DEBUG.
pub fn init_logging() {
    let log_level = log::LevelFilter::Debug;
    fern::Dispatch::new()
        .format(move |out, message, record| {
            out.finish(format_args!(
                "{} [{:5}] {} {}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.level(),
                if log_level == log::LevelFilter::Trace {
                    record.target()
                } else {
                    ""
                },
                message
            ))
        })
        .level(log_level)
        .chain(std::io::stderr())
        .filter(|metadata| !metadata.target().starts_with("goblin::pe"))
        .apply()
        .expect("failed to configure logging");
}

/// this is for testing, so will panic on error.
pub fn load_shellcode(arch: Arch, buf: &[u8]) -> Module {
    let mut address_space = RelativeAddressSpace::with_capacity(buf.len() as u64);
    address_space.map.writezx(0x0, buf).unwrap();

    Module {
        arch,
        sections: vec![Section {
            name:           "shellcode".to_string(),
            permissions:    Permissions::RWX,
            physical_range: std::ops::Range {
                start: 0x0,
                end:   buf.len() as RVA,
            },
            virtual_range:  std::ops::Range {
                start: 0x0,
                end:   buf.len() as RVA,
            },
        }],
        address_space: address_space.into_absolute(0x0).unwrap(),
    }
}

/// this is for testing, so will panic on error.
pub fn load_shellcode32(buf: &[u8]) -> Module {
    load_shellcode(Arch::X32, buf)
}

/// this is for testing, so will panic on error.
pub fn load_shellcode64(buf: &[u8]) -> Module {
    load_shellcode(Arch::X64, buf)
}

/// this is for testing, so will panic on error.
#[cfg(feature = "disassembler")]
pub fn read_insn(module: &Module, va: VA) -> zydis::DecodedInstruction {
    use crate::analysis::dis;

    let decoder = dis::get_disassembler(module).unwrap();
    let mut insn_buf = [0u8; 16];
    module.address_space.read_into(va, &mut insn_buf).unwrap();
    decoder.decode(&insn_buf).unwrap().unwrap()
}

pub fn emu_from_shellcode64(code: &[u8]) -> crate::emu::Emulator {
    let m = load_shellcode64(code);
    let mut emu = crate::emu::Emulator::from_module(&m);
    emu.reg.rip = m.address_space.base_address; // 0x0

    emu.mem.mmap(0x5000, 0x2000, Permissions::RW).unwrap();
    emu.reg.rsp = 0x6000;
    emu.reg.rbp = 0x6000;

    emu
}

pub fn emu_from_shellcode32(code: &[u8]) -> crate::emu::Emulator {
    let m = load_shellcode32(code);
    let mut emu = crate::emu::Emulator::from_module(&m);
    emu.reg.set_eip(m.address_space.base_address as u32); // 0x0

    emu.mem.mmap(0x5000, 0x2000, Permissions::RW).unwrap();
    emu.reg.set_esp(0x6000);
    emu.reg.set_ebp(0x6000);

    emu
}

#[cfg(test)]
pub mod uc {
    use byteorder::{ByteOrder, LittleEndian};
    use unicorn_engine::unicorn_const::{uc_error, Arch, Mode, Prot};

    use super::load_shellcode64;
    use crate::{
        aspace::AddressSpace,
        emu::{mmu::PAGE_SIZE, reg::STATUS_MASK},
        module::{Module, Permissions},
    };

    pub struct Uc<'a> {
        emu: unicorn_engine::Unicorn<'a, ()>,
    }

    impl<'a> Uc<'a> {
        pub fn from_module<'b>(m: &'b Module) -> Uc<'a> {
            let mut emu = match m.arch {
                crate::arch::Arch::X32 => unicorn_engine::Unicorn::new(Arch::X86, Mode::MODE_32).unwrap(),
                crate::arch::Arch::X64 => unicorn_engine::Unicorn::new(Arch::X86, Mode::MODE_64).unwrap(),
            };

            for section in m.sections.iter() {
                let mut page_addr = section.virtual_range.start;

                let section_size = section.virtual_range.end - section.virtual_range.start;
                emu.mem_map(
                    section.virtual_range.start,
                    crate::util::align(section_size, PAGE_SIZE as u64),
                    Prot::WRITE,
                )
                .unwrap();

                while page_addr < section.virtual_range.end {
                    let mut page = [0u8; PAGE_SIZE];

                    // AddressSpace currently allows non-page-aligned sizes.
                    let page_data = if page_addr + PAGE_SIZE as u64 > section.virtual_range.end {
                        &mut page[..(section.virtual_range.end - page_addr) as usize]
                    } else {
                        &mut page[..]
                    };

                    m.address_space.read_into(page_addr, page_data).unwrap();
                    emu.mem_write(page_addr, &page[..]).unwrap();
                    page_addr += PAGE_SIZE as u64;
                }

                let mut prot = Prot::NONE;
                if section.permissions.intersects(Permissions::W) {
                    prot = prot | Prot::WRITE;
                }
                if section.permissions.intersects(Permissions::R) {
                    prot = prot | Prot::READ;
                }
                if section.permissions.intersects(Permissions::X) {
                    prot = prot | Prot::EXEC;
                }

                emu.mem_protect(
                    section.virtual_range.start,
                    crate::util::align(section_size, PAGE_SIZE as u64),
                    prot,
                )
                .unwrap();
            }

            Uc { emu }
        }

        pub fn step(&mut self) -> Result<(), uc_error> {
            let rip = self.emu.reg_read(unicorn_engine::RegisterX86::RIP).unwrap();
            self.emu.emu_start(rip, u64::MAX, 0, 1)
        }

        pub fn mem_read_u64(&self, addr: u64) -> Result<u64, uc_error> {
            let mut buf = [0u8; 8];
            self.emu.mem_read(addr, &mut buf)?;
            Ok(LittleEndian::read_u64(&buf))
        }

        /// panics if the given emulator does have the same state as this.
        pub fn check(&self, other: &crate::emu::Emulator) {
            use unicorn_engine::RegisterX86::*;

            assert_eq!(
                self.emu.reg_read(RIP).unwrap(),
                other.reg.rip(),
                "register: rip, uc: {:#x} emu: {:#x}",
                self.emu.reg_read(RIP).unwrap(),
                other.reg.rip()
            );

            assert_eq!(
                self.emu.reg_read(RSP).unwrap(),
                other.reg.rsp(),
                "register: rsp, uc: {:#x} emu: {:#x}",
                self.emu.reg_read(RSP).unwrap(),
                other.reg.rsp()
            );

            assert_eq!(
                self.emu.reg_read(RBP).unwrap(),
                other.reg.rbp(),
                "register: rbp, uc: {:#x} emu: {:#x}",
                self.emu.reg_read(RBP).unwrap(),
                other.reg.rbp()
            );

            assert_eq!(
                self.emu.reg_read(RAX).unwrap(),
                other.reg.rax(),
                "register: rax, uc: {:#x} emu: {:#x}",
                self.emu.reg_read(RAX).unwrap(),
                other.reg.rax()
            );

            assert_eq!(
                self.emu.reg_read(RBX).unwrap(),
                other.reg.rbx(),
                "register: rbx, uc: {:#x} emu: {:#x}",
                self.emu.reg_read(RBX).unwrap(),
                other.reg.rbx()
            );

            assert_eq!(
                self.emu.reg_read(RCX).unwrap(),
                other.reg.rcx(),
                "register: rcx, uc: {:#x} emu: {:#x}",
                self.emu.reg_read(RCX).unwrap(),
                other.reg.rcx()
            );

            assert_eq!(
                self.emu.reg_read(RDX).unwrap(),
                other.reg.rdx(),
                "register: rdx, uc: {:#x} emu: {:#x}",
                self.emu.reg_read(RDX).unwrap(),
                other.reg.rdx()
            );

            assert_eq!(
                self.emu.reg_read(RSI).unwrap(),
                other.reg.rsi(),
                "register: rsi, uc: {:#x} emu: {:#x}",
                self.emu.reg_read(RSI).unwrap(),
                other.reg.rsi()
            );

            assert_eq!(
                self.emu.reg_read(RDI).unwrap(),
                other.reg.rdi(),
                "register: rdi, uc: {:#x} emu: {:#x}",
                self.emu.reg_read(RDI).unwrap(),
                other.reg.rdi()
            );

            // we don't emulate all of the flags, just the status flags.
            assert_eq!(
                self.emu.reg_read(EFLAGS).unwrap() & STATUS_MASK,
                other.reg.rflags() & STATUS_MASK,
                "flags, uc: {:#b} emu: {:#b}",
                self.emu.reg_read(EFLAGS).unwrap() & STATUS_MASK,
                other.reg.rflags() & STATUS_MASK,
            );

            // dereferece $SP and $BP
            let rsp = other.reg.rsp();
            assert_eq!(
                self.mem_read_u64(rsp).unwrap(),
                other.mem.read_u64(rsp).unwrap(),
                "*RSP, uc: {:#x} emu: {:#x}",
                self.mem_read_u64(rsp).unwrap(),
                other.mem.read_u64(rsp).unwrap(),
            );

            let rbp = other.reg.rbp();
            assert_eq!(
                self.mem_read_u64(rbp).unwrap(),
                other.mem.read_u64(rbp).unwrap(),
                "*RBP, uc: {:#x} emu: {:#x}",
                self.mem_read_u64(rbp).unwrap(),
                other.mem.read_u64(rbp).unwrap(),
            );
        }
    }

    pub fn uc_from_shellcode64(code: &[u8]) -> Uc {
        let m = load_shellcode64(code);
        let mut uc = Uc::from_module(&m);

        uc.emu
            .reg_write(unicorn_engine::RegisterX86::RIP, m.address_space.base_address)
            .unwrap(); // 0x0

        uc.emu.mem_map(0x5000, 0x2000, Prot::ALL).unwrap();
        uc.emu.reg_write(unicorn_engine::RegisterX86::RSP, 0x6000).unwrap();
        uc.emu.reg_write(unicorn_engine::RegisterX86::RBP, 0x6000).unwrap();

        uc
    }
}
