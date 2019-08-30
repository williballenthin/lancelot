extern crate lancelot;
extern crate log;
extern crate chrono;
#[macro_use] extern crate clap;

use fern;
use log::{error, info, debug};
use failure::{Error};
use better_panic;

use lancelot::workspace::Workspace;


fn handle_functions(ws: &Workspace) -> Result<(), Error> {
    let mut functions = ws.get_functions().collect::<Vec<_>>();
    functions.sort();

    info!("found {} functions", functions.len());
    for rva in functions.iter() {
        let basic_blocks = ws.get_basic_blocks(**rva)?;
        println!("{:#x} found {} basic blocks", **rva, basic_blocks.len());
    }

    Ok(())
}

fn main() {
    better_panic::install();

    let matches = clap_app!(lancelot =>
        (author: "Willi Ballenthin <willi.ballenthin@gmail.com>")
        (about: "Binary analysis framework")
        (@arg verbose: -v --verbose +multiple "log verbose messages")
        (@subcommand functions =>
            (about: "find functions")
            (@arg input: +required "path to file to analyze")
        )
    ).get_matches();

    let log_level = match matches.occurrences_of("verbose") {
        0 => log::LevelFilter::Info,
        1 => log::LevelFilter::Debug,
        2 => log::LevelFilter::Trace,
        _ => log::LevelFilter::Trace,
    };

    fern::Dispatch::new()
        .format(move |out, message, record| {
            out.finish(format_args!(
                "{} [{:5}] {} {}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.level(),
                if log_level == log::LevelFilter::Trace {record.target()} else {""},
                message
            ))
        })
        .level(log_level)
        .chain(std::io::stderr())
        .filter(|metadata| {
            !metadata.target().starts_with("goblin::pe")
        })
        .apply()
        .expect("failed to configure logging");

    if let Some(matches) = matches.subcommand_matches("functions") {
        debug!("mode: find functions");

        let filename = matches.value_of("input").unwrap();
        debug!("input: {}", filename);

        let ws = Workspace::from_file(filename)
            .unwrap_or_else(|e| panic!("failed to load workspace: {}", e));

        let ws = ws.load()
            .unwrap_or_else(|e| panic!("failed to load workspace: {}", e));

        if let Err(e) = handle_functions(&ws) {
            error!("error: {}", e)
        }
    };

    return;
}
