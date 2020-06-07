//< Helpers that are useful for tests and doctests.

use anyhow::Result;

use crate::aspace::RelativeAddressSpace;
use crate::module::{Arch, Module, Permissions, Section};
use crate::RVA;

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

pub fn load_shellcode(arch: Arch, buf: &[u8]) -> Result<Module> {
    let mut address_space = RelativeAddressSpace::with_capacity(buf.len() as u64);
    address_space.map.writezx(0x0, buf)?;

    Ok(Module {
        arch,
        sections: vec![Section {
            name: "shellcode".to_string(),
            perms: Permissions::RWX,
            physical_range: std::ops::Range {
                start: 0x0,
                end: buf.len() as RVA,
            },
            virtual_range: std::ops::Range {
                start: 0x0,
                end: buf.len() as RVA,
            },
        }],
        address_space: address_space.into_absolute(0x0)?,
    })
}

pub fn load_shellcode32(buf: &[u8]) -> Result<Module> {
    load_shellcode(Arch::X32, buf)
}

pub fn load_shellcode64(buf: &[u8]) -> Result<Module> {
    load_shellcode(Arch::X32, buf)
}
