// TODO:
//   - get completion actually working
//   - formatting

extern crate log;
extern crate simplelog;

use std::fs;
use std::env;
use std::collections;
use std::io::prelude::*;
use goblin::{Object};
use goblin::pe::{PE};
use log::{trace, debug, info, error};


pub struct Config {
    pub filename: String,
}

impl Config {
    pub fn from_args(args: env::Args) -> Result<Config, &'static str> {
        let args: Vec<String> = args.collect();

        if args.len() < 2 {
            return Err("not enough arguments")
        }

        let filename = args[1].clone();
        trace!("config: parsed filename: {:?}", filename);

        Ok(Config {
            filename: filename
        })
    }
}


pub fn setup_logging(_args: &Config) {
    simplelog::TermLogger::init(simplelog::LevelFilter::Info,
                                simplelog::Config::default())
        .expect("failed to setup logging");
}

#[derive(Debug)]
pub enum Error {
    FileAccess,
    FileFormat,
    NotImplemented,
}


fn foo(pe: &PE, buf: &[u8]) -> Result<(), Error> {
    info!("foo: {}", pe.name.unwrap_or("(unknown)"));

    // like:
    //     exports:
    //       - Foo
    if pe.exports.len() > 0 {
        info!("exports:");
        for export in pe.exports.iter() {
            info!("  - {}", export.name.unwrap_or("(unknown)"));
        }
    }

    // like:
    //     imports:
    //       - advapi32.dll
    //         - OpenProcessToken
    //         ...
    if pe.imports.len() > 0 {
        let mut dlls = pe.imports.iter()
                         .map(|import| {import.dll.to_lowercase()})
                         .collect::<collections::HashSet<String>>()
                         .iter()
                         .map(|e| {e.clone()})
                         .collect::<Vec<String>>();
        dlls.sort_unstable();

        info!("imports:");
        for dll in dlls.iter() {
            info!("  - {}", dll);

            let mut funcs: Vec<_> = pe.imports.iter()
                                          .filter(|import| { import.dll.to_lowercase() == **dll })
                                          .collect();
            funcs.sort_unstable_by(|a, b| { a.name.cmp(&b.name) });

            for func in funcs {
                info!("    - {}", func.name);
            }
        }
    }

    info!("bitness: {}", if pe.is_64 { "64" } else { "32"});
    info!("image base: 0x{:x}", pe.image_base);
    info!("entry rva: 0x{:x}", pe.entry);

    for section in pe.sections.iter() {
        info!("section:");
        if section.real_name.is_some() {
            info!("  name: {} ({})",
                  String::from_utf8_lossy(&section.name[..]),
                  section.real_name.as_ref().unwrap_or(&"(unknown)".to_string())
                  );
        } else {
            info!("  name: {}", String::from_utf8_lossy(&section.name[..]));
        }
    }

    Ok(())
}


pub fn run(args: &Config) -> Result<(), Error> {
    debug!("filename: {:?}", args.filename);

    let mut buf = Vec::new();
    {
        debug!("reading file: {}", args.filename);
        let mut f = match fs::File::open(&args.filename) {
            Ok(f) => f,
            Err(_) => { 
                error!("failed to open file: {}", args.filename);
                return Err(Error::FileAccess);
            }
        };
        let bytes_read = match f.read_to_end(&mut buf) {
            Ok(c) => c,
            Err(_) => { 
                error!("failed to read entire file: {}", args.filename);
                return Err(Error::FileAccess); 
            }
        };
        debug!("read {} bytes", bytes_read);
        if bytes_read < 0x10 {
            error!("file too small: {}", args.filename);
            return Err(Error::FileFormat);
        }
    }

    let obj = match Object::parse(&buf) {
        Ok(o) => o,
        Err(e) => {
            error!("failed to parse file: {} error: {:?}", args.filename, e);
            return Err(Error::FileFormat);
        }
    };

    match obj {
        Object::PE(pe) => {
            info!("found PE file");
            foo(&pe, &buf).expect("failed to foo")
        },
        Object::Elf(_) => {
            error!("found ELF file, format not yet supported");
            return Err(Error::NotImplemented);
        },
        Object::Mach(_) => {
            error!("found Mach-O file, format not yet supported");
            return Err(Error::NotImplemented);
        },
        Object::Archive(_) => {
            error!("found archive file, format not yet supported");
            return Err(Error::NotImplemented);
        },
        Object::Unknown(_) => {
            error!("unknown file format, magic: | {:02X} {:02X} | '{}{}' ", 
                   buf[0], buf[1],
                   hexdump_ascii(buf[0] as char),
                   hexdump_ascii(buf[1] as char));
            return Err(Error::NotImplemented);
        }
    }

    Ok(())
}

fn hexdump_ascii(c: char) -> char {
    if c.is_ascii() {
        c
    } else {
        '.'
    }
}