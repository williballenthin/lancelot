//< Helpers that are useful for tests and doctests.
use crate::{
    aspace::{AddressSpace, RelativeAddressSpace},
    module::{Arch, Module, Permissions, Section},
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
#[cfg(feature = "dis")]
pub fn read_insn(module: &Module, va: VA) -> zydis::DecodedInstruction {
    use crate::analysis::dis;

    let decoder = dis::get_disassembler(module).unwrap();
    let mut insn_buf = [0u8; 16];
    module.address_space.read_into(va, &mut insn_buf).unwrap();
    decoder.decode(&insn_buf).unwrap().unwrap()
}
