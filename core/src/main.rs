extern crate lancelot;
extern crate log;

use std::env;
use std::process;

use log::{error, info, trace};
use better_panic;
use failure::{Error, Fail};

use lancelot::workspace::Workspace;


#[derive(Debug, Fail)]
pub enum MainError {
    #[fail(display = "foo")]
    Foo,
}

pub struct Config {
    pub filename: String,
}

impl Config {
    pub fn from_args(args: env::Args) -> Result<Config, &'static str> {
        let args: Vec<String> = args.collect();

        if args.len() < 2 {
            return Err("not enough arguments: provide `lancelot.exe /path/to/input`");
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
    info!("filename: {:?}", args.filename);

    let ws = Workspace::from_file(&args.filename)?.load()?;

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

    let args = Config::from_args(env::args()).unwrap_or_else(|err| {
        eprintln!("error parsing arguments: {}", err);
        process::exit(1);
    });

    setup_logging(&args);

    if let Err(e) = run(&args) {
        error!("{:?}", e)
    }
}
