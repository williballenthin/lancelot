extern crate log;
extern crate lancelot;

use std::env;
use std::process;
use log::{debug, error, trace};
use goblin::Object;

use lancelot::{Workspace, Error};
use lancelot::analysis;

pub struct Config {
    pub filename: String,
}

impl Config {
    pub fn from_args(args: env::Args) -> Result<Config, &'static str> {
        let args: Vec<String> = args.collect();

        if args.len() < 2 {
            return Err("not enough arguments");
        }

        let filename = args[1].clone();
        trace!("config: parsed filename: {:?}", filename);

        Ok(Config { filename })
    }
}

pub fn setup_logging(_args: &Config) {
    simplelog::TermLogger::init(simplelog::LevelFilter::Info, simplelog::Config::default())
        .expect("failed to setup logging");
}

pub fn run(args: &Config) -> Result<(), Error> {
    debug!("filename: {:?}", args.filename);
    let ws = Workspace::from_file(&args.filename)?;

    if let Object::PE(pe) = ws.get_obj()? {
        let oep = if let Some(opt) = pe.header.optional_header {
            opt.standard_fields.address_of_entry_point
        } else {
            0x0
        };
        println!("entrypoint: {:}", ws.get_insn(oep)?);
    }

    //println!("roots: {:}", analysis::find_roots(&ws).expect("foo").len());
    /*
    println!(
        "call targets: {:}",
        analysis::find_call_targets(&ws).expect("foo").len()
    );
    println!(
        "branch targets: {:}",
        analysis::find_branch_targets(&ws).expect("foo").len()
    );
    */
    println!(
        "entry points: {:}",
        analysis::find_entrypoints(&ws).expect("foo").len()
    );
    println!(
        "runtime functions: {:}",
        analysis::find_runtime_functions(&ws).expect("foo").len()
    );

    let fvas = analysis::find_functions(&ws).expect("foo");

    println!("find functions: {:}", fvas.len());

    analysis::compute_coverage(&ws, &fvas)?;

    Ok(())
}

fn main() {
    let args = Config::from_args(env::args()).unwrap_or_else(|err| {
        eprintln!("error parsing arguments: {}", err);
        process::exit(1);
    });

    setup_logging(&args);

    if let Err(e) = run(&args) {
        error!("{:?}", e)
    }
}
