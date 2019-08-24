extern crate lancelot;
extern crate log;

use std::collections::HashMap;
use std::env;
use std::ops::Range;
use std::process;

use better_panic;
use failure::{Error, Fail};
use goblin::Object;
use log::{error, info, trace};

use lancelot::workspace::Workspace;

#[derive(Debug, Fail)]
pub enum MainError {
    #[fail(display = "foo")]
    Foo,
    #[fail(display = "Invalid PE file")]
    InvalidFile,
}

pub struct Config {
    pub filename: String,
}

impl Config {
    pub fn from_args(args: env::Args) -> Result<Config, &'static str> {
        let args: Vec<String> = args.collect();

        if args.len() < 2 {
            return Err("not enough arguments: provide `mapa.exe /path/to/input.exe`");
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


/*
    File
      Header,
        IMAGE_DOS_HEADER,
        IMAGE_NT_HEADERS,
          IMAGE_FILE_HEADER,
          IMAGE_OPTIONAL_HEADER,
      IMAGE_SECTION_HEADER,
      Section(u32),
*/

#[derive(Debug)]
enum Structure {
    /// the complete file
    File,
    /// the file headers.
    Header,
    IMAGE_DOS_HEADER,
    IMAGE_NT_HEADERS,
    IMAGE_FILE_HEADER,
    IMAGE_OPTIONAL_HEADER,
    IMAGE_SECTION_HEADER(u16),
    /// a section's content
    Section(u16),
}

pub fn run(args: &Config) -> Result<(), Error> {
    info!("filename: {:?}", args.filename);

    let ws = Workspace::from_file(&args.filename)?.load()?;
    let pe = match Object::parse(&ws.buf) {
        Ok(Object::PE(pe)) => pe,
        _ => return Err(MainError::InvalidFile.into()),
    };

    let mut locations: HashMap<Range<u64>, Structure> = HashMap::new();

    locations.insert(
        Range {
            start: 0,
            end: ws.buf.len() as u64,
        },
        Structure::File,
    );

    let sizeof_IMAGE_DOS_HEADER = 0x40;
    locations.insert(
        Range {
            start: 0,
            end: sizeof_IMAGE_DOS_HEADER,
        },
        Structure::IMAGE_DOS_HEADER,
    );

    let offset_IMAGE_NT_HEADERS = pe.header.dos_header.pe_pointer as u64;
    let sizeof_Signature: u64 = 0x4;
    let sizeof_IMAGE_FILE_HEADER: u64 = 0x14;
    locations.insert(
        Range {
            start: offset_IMAGE_NT_HEADERS,
            end: offset_IMAGE_NT_HEADERS
                + sizeof_Signature
                + sizeof_IMAGE_FILE_HEADER
                + (pe.header.coff_header.size_of_optional_header as u64),
        },
        Structure::IMAGE_NT_HEADERS,
    );

    let offset_IMAGE_FILE_HEADER = offset_IMAGE_NT_HEADERS + sizeof_Signature;
    locations.insert(
        Range {
            start: offset_IMAGE_FILE_HEADER,
            end: offset_IMAGE_FILE_HEADER + sizeof_IMAGE_FILE_HEADER,
        },
        Structure::IMAGE_FILE_HEADER,
    );

    let end_of_headers = if pe.header.coff_header.size_of_optional_header > 0 {
        let offset_IMAGE_OPTIONAL_HEADER = offset_IMAGE_FILE_HEADER + sizeof_IMAGE_FILE_HEADER;
        let end_of_headers = offset_IMAGE_OPTIONAL_HEADER
                    + (pe.header.coff_header.size_of_optional_header as u64);
        locations.insert(
            Range {
                start: offset_IMAGE_OPTIONAL_HEADER,
                end: end_of_headers,
            },
            Structure::IMAGE_OPTIONAL_HEADER,
        );
        locations.insert(
            Range {
                start: 0x0,
                end: offset_IMAGE_OPTIONAL_HEADER
                    + (pe.header.coff_header.size_of_optional_header as u64),
            },
            Structure::Header,
        );
        end_of_headers
    } else {
        let end_of_headers = offset_IMAGE_FILE_HEADER + sizeof_IMAGE_FILE_HEADER;
        locations.insert(
            Range {
                start: 0x0,
                end: end_of_headers,
            },
            Structure::Header,
        );
        end_of_headers
    };

    let mut offset_IMAGE_SECTION_HEADER = end_of_headers;
    let sizeof_IMAGE_SECTION_HEADER = 0x28;
    for i in 0..pe.header.coff_header.number_of_sections {
        locations.insert(
            Range {
                start: offset_IMAGE_SECTION_HEADER,
                end: offset_IMAGE_SECTION_HEADER + sizeof_IMAGE_SECTION_HEADER,
            },
            Structure::IMAGE_SECTION_HEADER(i)
        );

        let section = &pe.sections[i as usize];
        locations.insert(
            Range {
                start: section.pointer_to_raw_data as u64,
                end: (section.pointer_to_raw_data + section.size_of_raw_data) as u64,
            },
            Structure::Section(i),
        );

        offset_IMAGE_SECTION_HEADER += sizeof_IMAGE_SECTION_HEADER;
    }

    let mut ranges: Vec<Range<u64>> = locations.keys().cloned().collect();
    ranges.sort_by(|a, b|
        if a.start < b.start {
            std::cmp::Ordering::Less
        } else if a.start > b.start {
            std::cmp::Ordering::Greater
        } else if a.end < b.end {
            std::cmp::Ordering::Greater
        } else if a.end > b.end {
            std::cmp::Ordering::Less
        } else {
            std::cmp::Ordering::Equal
        }
    );

    for range in ranges.iter() {
        println!("{:?} {:?}", range, locations[range]);
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
