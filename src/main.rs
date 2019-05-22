extern crate lancelot;
extern crate log;

use failure::{Error, Fail};
use log::{error, info, trace};
use std::env;
use std::process;

use lancelot::arch::*;
use lancelot::workspace::Workspace;


#[derive(Debug, Fail)]
pub enum MainError {
    #[fail(display = "foo")]
    Foo,
}

pub struct Config {
    pub mode: u8,
    pub filename: String,
}

impl Config {
    pub fn from_args(args: env::Args) -> Result<Config, &'static str> {
        let args: Vec<String> = args.collect();

        if args.len() < 3 {
            return Err("not enough arguments: provide `lancelot.exe 32|64 /path/to/input`");
        }

        let mode = match args[1].as_ref() {
            "32" => 32,
            "64" => 64,
            _ => return Err("invalid mode, pick one of `32` or `64`"),
        };

        let filename = args[2].clone();
        trace!("config: parsed filename: {:?}", filename);

        Ok(Config { mode, filename })
    }
}

pub fn setup_logging(_args: &Config) {
    simplelog::TermLogger::init(simplelog::LevelFilter::Info, simplelog::Config::default())
        .expect("failed to setup logging");
}

pub fn run(args: &Config) -> Result<(), Error> {
    info!("filename: {:?}", args.filename);

    if args.mode == 32 {
        let ws = Workspace::<Arch32>::from_file(&args.filename)?.load()?;

        let mut functions = ws.get_functions().collect::<Vec<_>>();
        functions.sort();

        info!("found {} functions", functions.len());
        for rva in functions.iter() {
            println!("{:#x}", ws.module.base_address + **rva as u32);
        }
    } else if args.mode == 64 {
        let ws = Workspace::<Arch64>::from_file(&args.filename)?.load()?;

        let mut functions = ws.get_functions().collect::<Vec<_>>();
        functions.sort();

        info!("found {} functions", functions.len());
        for rva in functions.iter() {
            println!("{:#x}", ws.module.base_address + **rva as u64);
        }
    }

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
