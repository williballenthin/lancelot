#![allow(clippy::upper_case_acronyms)]

use anyhow::{anyhow, Result};
use log::{debug, error, info};

use lancelot::{
    analysis::dis,
    aspace::AddressSpace,
    util,
    workspace::{formatter::Formatter, workspace_from_bytes, Workspace},
    RVA, VA,
};

fn handle_functions(ws: &dyn Workspace) -> Result<()> {
    info!("found {} functions", ws.analysis().functions.len());
    for (va, md) in ws.analysis().functions.iter() {
        print!("{va:#x}");

        if md.flags.intersects(lancelot::workspace::FunctionFlags::NORET) {
            print!(" noret")
        }

        if md.flags.intersects(lancelot::workspace::FunctionFlags::THUNK) {
            print!(" thunk")
        }

        if let Some(name) = ws.analysis().names.names_by_address.get(va) {
            print!(" {name}");
        }

        println!();
    }
    Ok(())
}

fn handle_disassemble(ws: &dyn Workspace, va: VA) -> Result<()> {
    let mut blocks = ws.cfg().get_reachable_blocks(va).collect::<Vec<_>>();
    blocks.sort_unstable_by_key(|&bb| bb.address);
    info!("found {} basic blocks", blocks.len());

    let decoder = dis::get_disassembler(ws.module()).unwrap();
    let fmt = Formatter::new();

    for bb in blocks.into_iter() {
        // need to over-read the bb buffer, to account for the final instructions.
        let buf = ws
            .module()
            .address_space
            .read_bytes(bb.address, bb.length as usize + 0x10)?;
        for (offset, insn) in dis::linear_disassemble(&decoder, &buf) {
            // because we over-read the bb buffer,
            // discard the instructions found after it.
            if offset >= bb.length as usize {
                break;
            }

            if let Ok(Some(insn)) = insn {
                let va = bb.address + offset as RVA;
                println!("{}", fmt.format_instruction(ws, &insn, va)?);
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

    let matches = clap::App::new("lancelot")
        .author("Willi Ballenthin <william.ballenthin@mandiant.com>")
        .about("Binary analysis framework")
        .arg(
            clap::Arg::new("verbose")
                .short('v')
                .long("verbose")
                .multiple_occurrences(true)
                .help("log verbose messages"),
        )
        .arg(
            clap::Arg::new("quiet")
                .short('q')
                .long("quiet")
                .help("disable informational messages"),
        )
        .arg(
            clap::Arg::new("configuration")
                .long("config")
                .takes_value(true)
                .help("path to configuration directory"),
        )
        .subcommand(
            clap::App::new("functions").about("find functions").arg(
                clap::Arg::new("input")
                    .required(true)
                    .index(1)
                    .help("path to file to analyze"),
            ),
        )
        .subcommand(
            clap::App::new("disassemble")
                .about("disassemble function")
                .arg(
                    clap::Arg::new("input")
                        .required(true)
                        .index(1)
                        .help("path to file to analyze"),
                )
                .arg(clap::Arg::new("va").required(true).index(2).help("VA of function")),
        )
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

    // Enable ANSI support for Windows
    // via: https://github.com/sharkdp/hexyl/blob/d1ae68585fe743d225bb39361bd383cb925b61f7/src/bin/hexyl.rs#L261
    #[cfg(windows)]
    let _ = ansi_term::enable_ansi_support();

    let config = if matches.is_present("configuration") {
        let path = matches.value_of("configuration").unwrap();
        log::info!("configuration: {}", path);
        Box::new(lancelot::workspace::config::FileSystemConfiguration::from_path(
            &std::path::PathBuf::from(path),
        ))
    } else {
        log::info!("using default, empty configuration");
        lancelot::workspace::config::empty()
    };

    if let Some(matches) = matches.subcommand_matches("functions") {
        debug!("mode: find functions");

        let filename = matches.value_of("input").unwrap();
        debug!("input: {}", filename);

        let buf = util::read_file(filename)?;
        let ws = workspace_from_bytes(config, &buf)?;

        handle_functions(&*ws)
    } else if let Some(matches) = matches.subcommand_matches("disassemble") {
        debug!("mode: disassemble");

        let filename = matches.value_of("input").unwrap();
        debug!("input: {}", filename);

        let va = parse_va(matches.value_of("va").unwrap())?;

        let buf = util::read_file(filename)?;
        let ws = workspace_from_bytes(config, &buf)?;

        handle_disassemble(&*ws, va)
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
