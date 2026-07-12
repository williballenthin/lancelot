#![allow(clippy::upper_case_acronyms)]

use anyhow::{anyhow, Result};
use log::{debug, error};

use lancelot::{
    util,
    workspace::{export::binexport2, workspace_from_bytes},
};

fn _main() -> Result<()> {
    better_panic::install();

    let matches = lancelot_bin::cli::add_config_arg(lancelot_bin::cli::add_common_args(clap::Command::new("be2")))
        .author("Willi Ballenthin <william.ballenthin@mandiant.com>")
        .about("Binary analysis framework")
        .arg(
            clap::Arg::new("input")
                .required(true)
                .index(1)
                .help("path to file to analyze"),
        )
        .get_matches();

    lancelot_bin::cli::configure_logging(&matches, &[]);

    let config = lancelot_bin::cli::configuration_from_matches(&matches);

    let filename = matches.get_one::<String>("input").unwrap();
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
