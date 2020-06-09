use anyhow::Result;
use better_panic;
use chrono;
use fern;
use log::{debug, error, info};
#[macro_use]
extern crate clap;
#[macro_use]
extern crate anyhow;

use lancelot::loader::pe::{load_pe, PE};
use lancelot::util;
use lancelot::VA;

fn handle_functions(pe: &PE) -> Result<()> {
    let functions = lancelot::analysis::pe::find_function_starts(pe)?;

    info!("found {} functions", functions.len());
    for va in functions.iter() {
        println!("{:#x}", va);
    }

    Ok(())
}

fn handle_disassemble(pe: &PE, va: VA) -> Result<()> {
    let cfg = lancelot::analysis::cfg::build_cfg(&pe.module, va)?;

    info!("found {} basic blocks", cfg.basic_blocks.len());
    for bb in cfg.basic_blocks.values() {
        println!("{:#x}", bb.addr);
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
        let pe = load_pe(&buf)?;

        handle_functions(&pe)
    } else if let Some(matches) = matches.subcommand_matches("disassemble") {
        debug!("mode: disassemble");

        let filename = matches.value_of("input").unwrap();
        debug!("input: {}", filename);

        let va = parse_va(matches.value_of("va").unwrap())?;

        let buf = util::read_file(filename)?;
        let pe = load_pe(&buf)?;

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
