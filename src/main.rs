extern crate log;
extern crate lancelot;

use std::env;
use std::process;
use log::{error, info, trace};
use failure::{Error, Fail};

use lancelot::arch::*;
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
    info!("filename: {:?}", args.filename);

    let _ = Workspace::<Arch32>::from_file(&args.filename)?
      .load()?;

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
