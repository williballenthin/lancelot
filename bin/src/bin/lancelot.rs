#![allow(clippy::upper_case_acronyms)]

use anyhow::Result;
use log::{debug, error, info};
#[macro_use]
extern crate clap;
#[macro_use]
extern crate anyhow;

use lancelot::{analysis::dis, aspace::AddressSpace, loader::pe::PE, util, RVA, VA};

fn handle_functions(pe: &PE) -> Result<()> {
    let functions = lancelot::analysis::pe::find_function_starts(pe)?;

    info!("found {} functions", functions.len());
    for va in functions.iter() {
        println!("{:#x}", va);
    }

    Ok(())
}

fn render_insn_buf(buf: &[u8], width: usize) -> String {
    let mut out = String::new();
    for (i, c) in hex::encode(buf).chars().enumerate() {
        out.push(c);

        if i % 2 == 1 {
            out.push(' ');
        }
    }

    let out = out.trim_end_matches(' ').to_string();
    if out.len() > width {
        out[..width].to_string()
    } else {
        out
    }
}

fn render_insn(insn: &zydis::ffi::DecodedInstruction, va: VA) -> String {
    let formatter = zydis::Formatter::new(zydis::FormatterStyle::INTEL).expect("formatter");
    let mut buffer = [0u8; 200];
    let mut buffer = zydis::OutputBuffer::new(&mut buffer[..]);

    formatter
        .format_instruction(insn, &mut buffer, Some(va), None)
        .expect("format");
    format!("{}", buffer)
}

fn handle_disassemble(pe: &PE, va: VA) -> Result<()> {
    let cfg = lancelot::analysis::cfg::build_cfg(&pe.module, va)?;
    let decoder = dis::get_disassembler(&pe.module)?;

    info!("found {} basic blocks", cfg.basic_blocks.len());
    for bb in cfg.basic_blocks.values() {
        // need to over-read the bb buffer, to account for the final instructions.
        let buf = pe
            .module
            .address_space
            .read_bytes(bb.address, bb.length as usize + 0x10)?;
        for (offset, insn) in dis::linear_disassemble(&decoder, &buf) {
            // because we over-read the bb buffer,
            // discard the instructions found after it.
            if offset >= bb.length as usize {
                break;
            }

            let va = bb.address + offset as RVA;

            let name = &pe
                .module
                .sections
                .iter()
                .find(|sec| sec.virtual_range.contains(&va))
                .unwrap()
                .name;

            if let Ok(Some(insn)) = insn {
                let insn_buf = &buf[offset..offset + insn.length as usize];
                println!(
                    "{}:{:016x}  {:15}  {}",
                    name,
                    va,
                    render_insn_buf(insn_buf, 15),
                    render_insn(&insn, va)
                );
            } else {
                println!("  {}:{:#x}: INVALID", name, va);
                break;
            }
        }
        println!();
    }

    Ok(())
}

fn parse_va(s: &str) -> Result<VA> {
    if s.starts_with("0x") {
        let without_prefix = s.trim_start_matches("0x");
        Ok(u64::from_str_radix(without_prefix, 16)?)
    } else {
        Ok(s.parse()?)
    }
}

fn _main() -> Result<()> {
    better_panic::install();

    let matches = clap::clap_app!(lancelot =>
        (author: "Willi Ballenthin <william.ballenthin@mandiant.com>")
        (about: "Binary analysis framework")
        (@arg verbose: -v --verbose +multiple "log verbose messages")
        (@arg quiet: -q --quiet "disable informational messages")
        (@subcommand functions =>
            (about: "find functions")
            (@arg input: +required "path to file to analyze"))
        (@subcommand disassemble =>
            (about: "disassemble function")
            (@arg input: +required "path to file to analyze")
            (@arg va: +required "VA of function")))
    .get_matches();

    // --quiet overrides --verbose
    let log_level = if matches.is_present("quiet") {
        log::LevelFilter::Error
    } else {
        match matches.occurrences_of("verbose") {
            0 => log::LevelFilter::Info,
            1 => log::LevelFilter::Debug,
            2 => log::LevelFilter::Trace,
            _ => log::LevelFilter::Trace,
        }
    };

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

    if let Some(matches) = matches.subcommand_matches("functions") {
        debug!("mode: find functions");

        let filename = matches.value_of("input").unwrap();
        debug!("input: {}", filename);

        let buf = util::read_file(filename)?;
        let pe = PE::from_bytes(&buf)?;

        handle_functions(&pe)
    } else if let Some(matches) = matches.subcommand_matches("disassemble") {
        debug!("mode: disassemble");

        let filename = matches.value_of("input").unwrap();
        debug!("input: {}", filename);

        let va = parse_va(matches.value_of("va").unwrap())?;

        let buf = util::read_file(filename)?;
        let pe = PE::from_bytes(&buf)?;

        handle_disassemble(&pe, va)
    } else {
        Err(anyhow!("SUBCOMMAND required"))
    }
}

fn main() {
    if let Err(e) = _main() {
        #[cfg(debug_assertions)]
        error!("{:?}", e);
        #[cfg(not(debug_assertions))]
        error!("{:}", e);
    }
}
