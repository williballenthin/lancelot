extern crate lancelot;
extern crate log;

use failure::{Error, Fail};
use log::{error, info, trace};
use std::env;
use std::process;

use lancelot::arch::*;
use lancelot::workspace::Workspace;

// TODO: removeme
use goblin::{Object};


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
        let mut ws = Workspace::<Arch32>::from_file(&args.filename)?.load()?;
    } else if args.mode == 64 {
        let mut ws = Workspace::<Arch64>::from_file(&args.filename)?.load()?;

        if ws.loader.get_name() == "Windows/64/PE" {
            if let Ok(Object::PE(pe)) = Object::parse(&ws.buf) {
                let entry = pe.entry;
                let exports: Vec<(usize, Option<String>)> = pe.exports.iter()
                    // re-exports are simply strings that point to a `DLL.export_name` ASCII string.
                    // therefore, they're not functions/code.
                    .filter(|exp| exp.reexport.is_none())
                    .map(|exp| {
                        (exp.rva, exp.name.map(|n| n.to_string()))
                    }).collect();

                // TODO: need to add symbols for re-exports

                info!("PE entry: {:#x}", entry);
                ws.make_symbol(entry as i64, "entry");
                ws.make_insn(entry as i64)?;
                ws.analyze()?;
                for (rva, name) in exports.iter() {
                    info!("export: {:#x}", rva);
                    ws.make_insn(*rva as i64)?;
                    if let Some(name) = name {
                        ws.make_symbol(*rva as i64, &name)?;
                    }
                    ws.analyze()?;
                }
            }
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
