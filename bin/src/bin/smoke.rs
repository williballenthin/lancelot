#![allow(clippy::upper_case_acronyms)]

use anyhow::Result;
use log::{debug, error, info};

use lancelot::{
    analysis::cfg,
    util,
    workspace::{config::empty, workspace_from_bytes},
};

fn _main() -> Result<()> {
    better_panic::install();

    let matches = clap::App::new("lancelot")
        .author("Willi Ballenthin <william.ballenthin@mandiant.com>")
        .about("smoke test lancelot against the given binary")
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
            clap::Arg::new("input")
                .required(true)
                .index(1)
                .help("path to file to analyze"),
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

    let filename = matches.value_of("input").unwrap();
    debug!("input: {}", filename);

    let buf = util::read_file(filename)?;
    let config = empty();
    let ws = workspace_from_bytes(config, &buf)?;

    info!("found {} functions", ws.analysis().functions.len());

    let mut insns: cfg::InstructionIndex = Default::default();
    for &va in ws.analysis().functions.keys() {
        insns.build_index(ws.module(), va)?;
    }
    info!("found {} instructions", insns.insns_by_address.len());

    let cfg = cfg::CFG::from_instructions(ws.module(), insns)?;
    info!("found {} basic blocks", cfg.basic_blocks.blocks_by_address.len());

    Ok(())
}

fn main() {
    if let Err(e) = _main() {
        #[cfg(debug_assertions)]
        error!("{:?}", e);
        #[cfg(not(debug_assertions))]
        error!("{:}", e);
    }
}
