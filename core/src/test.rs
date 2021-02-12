//< Helpers that are useful for tests and doctests.
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
