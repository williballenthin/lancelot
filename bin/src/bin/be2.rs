#![allow(clippy::upper_case_acronyms)]

use anyhow::{anyhow, Result};
use log::{debug, error};

use lancelot::{
    util,
    workspace::{export::binexport2, workspace_from_bytes},
};

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

    let filename = matches.value_of("input").unwrap();
    debug!("input: {}", filename);

    let buf = util::read_file(filename)?;
    let ws = workspace_from_bytes(config, &buf)?;

    let executable_name = std::path::PathBuf::from(filename)
        .file_name()
        .ok_or(anyhow!("failed to extract filename"))?
        .to_str()
        .map(|v| v.to_string());

    let hash = sha256::digest(buf);

    let out = binexport2::export_workspace_to_binexport2(&*ws, hash, executable_name)?;

    {
        use std::io::Write;
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(&out)?
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
