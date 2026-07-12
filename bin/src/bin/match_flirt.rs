#![allow(clippy::upper_case_acronyms)]

use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;
use log::{debug, error, info};

use lancelot::{loader::pe::PE, util, VA};
use lancelot_flirt::*;

fn _main() -> Result<()> {
    better_panic::install();

    let matches = lancelot_bin::cli::add_common_args(clap::Command::new("match_flirt"))
        .author("Willi Ballenthin <william.ballenthin@mandiant.com>")
        .about("Show FLIRT matches in the given file")
        .arg(
            clap::Arg::new("input")
                .required(true)
                .index(1)
                .help("path to file to analyze"),
        )
        .arg(
            clap::Arg::new("sig")
                .required(true)
                .index(2)
                .num_args(1..)
                .help("path to file to analyze"),
        )
        .get_matches();

    lancelot_bin::cli::configure_logging(&matches, &[]);

    let mut sigs = vec![];
    for sigpath in matches.get_many::<String>("sig").unwrap() {
        if sigpath.ends_with(".pat") {
            sigs.extend(pat::parse(&String::from_utf8(util::read_file(sigpath)?)?)?);
        } else if sigpath.ends_with(".sig") {
            sigs.extend(sig::parse(&util::read_file(sigpath)?)?);
        } else {
            return Err(anyhow::anyhow!("--sig must end with .pat or .sig"));
        };
    }
    let sigs = FlirtSignatureSet::with_signatures(sigs);

    let filename = matches.get_one::<String>("input").unwrap();
    debug!("input: {}", filename);

    let buf = util::read_file(filename)?;
    let pe = PE::from_bytes(&buf)?;

    let mut functions = lancelot::analysis::pe::find_function_starts(&pe)?;
    functions.sort_unstable();
    info!("found {} functions", functions.len());

    #[derive(PartialEq, Eq, PartialOrd, Ord)]
    enum Name {
        Public(String),
        Local(String),
    }

    impl std::fmt::Display for Name {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            match self {
                Name::Public(s) => write!(f, "(public) {s}"),
                Name::Local(s) => write!(f, "(local)  {s}"),
            }
        }
    }

    let mut names: BTreeMap<VA, BTreeSet<Name>> = Default::default();

    for &va in functions.iter() {
        for sig in lancelot::analysis::flirt::match_flirt(&pe.module, &sigs, va)
            .unwrap_or_default()
            .iter()
        {
            for name in sig.names.iter() {
                match name {
                    Symbol::Reference(_) => continue,
                    Symbol::Local(lancelot_flirt::Name { name, offset }) => {
                        names
                            .entry((va as i64 + *offset) as u64)
                            .or_default()
                            .insert(Name::Local(name.clone()));
                    }
                    Symbol::Public(lancelot_flirt::Name { name, offset }) => {
                        names
                            .entry((va as i64 + *offset) as u64)
                            .or_default()
                            .insert(Name::Public(name.clone()));
                    }
                }
            }
        }
    }

    for &va in functions.iter() {
        if let Some(names) = names.get(&va) {
            if names.len() == 1 {
                let names: Vec<_> = names.iter().collect();
                println!("{va:#x}: {}", names[0]);
            } else {
                println!("{va:#x}:");
                for name in names.iter() {
                    println!("  - {name}");
                }
            }
        } else {
            println!("{va:#x}: (unknown)");
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
