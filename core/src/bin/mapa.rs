use anyhow::Result;
use log::{debug, error, info};
#[macro_use]
extern crate clap;
#[macro_use]
extern crate anyhow;

use lancelot::{
    analysis::dis,
    aspace::AddressSpace,
    loader::pe::{load_pe, PE},
    util, RVA, VA,
};

fn _main() -> Result<()> {
    better_panic::install();

    let matches = clap::clap_app!(lancelot =>
        (author: "Willi Ballenthin <william.ballenthin@mandiant.com>")
        (about: "Intelligent strings")
        (@arg verbose: -v --verbose +multiple "log verbose messages")
        (@arg quiet: -q --quiet "disable informational messages")
        (@arg input: +required "path to file to analyze"))
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
    let pe = load_pe(&buf)?;

    let functions = lancelot::analysis::pe::find_function_starts(&pe)?;
    let decoder = dis::get_disassembler(&pe.module)?;

    info!("found {} functions", functions.len());
    for &va in functions.iter() {
        println!("{:#x}", va);
        let cfg = lancelot::analysis::cfg::build_cfg(&pe.module, va)?;

        info!("found {} basic blocks", cfg.basic_blocks.len());
        for bb in cfg.basic_blocks.values() {
            // pass
        }
    }

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
