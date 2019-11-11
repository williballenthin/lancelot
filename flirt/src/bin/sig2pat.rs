use log::{error};
use fern;
use failure::{Error};
use better_panic;
extern crate log;
extern crate clap;
extern crate chrono;

fn run(sig_path: &str) -> Result<(), Error> {
    let buf = std::fs::read(sig_path)?;

    for sig in flirt::sig::parse(&buf)?.iter() {
        println!("{:}", sig);
    }

    Ok(())
}

fn main() {
    better_panic::install();

    // while the macro form of clap is more readable,
    // it doesn't seem to allow us to use dynamically-generated values,
    // such as the defaults pulled from env vars, etc.
    let matches = clap::App::new("sig2pat")
        .author("Willi Ballenthin <willi.ballenthin@gmail.com>")
        .about("translate a FLIRT .sig file into a .pat file")
        .arg(clap::Arg::with_name("verbose")
            .short("v")
            .long("verbose")
            .multiple(true)
            .help("log verbose messages")
        )
        .arg(clap::Arg::with_name("sig")
            .required(true)
            .index(1)
            .help("path to .sig file")
        ).get_matches();

    let log_level = match matches.occurrences_of("verbose") {
        0 => log::LevelFilter::Info,
        1 => log::LevelFilter::Debug,
        2 => log::LevelFilter::Trace,
        _ => log::LevelFilter::Trace,
    };

    fern::Dispatch::new()
        .format(move |out, message, record| {
            out.finish(format_args!(
                "{} [{:5}] {} {}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.level(),
                if log_level == log::LevelFilter::Trace {record.target()} else {""},
                message
            ))
        })
        .level(log_level)
        .chain(std::io::stderr())
        .apply()
        .expect("failed to configure logging");

    if let Err(e) = run(matches.value_of("sig").unwrap()) {
        error!("{:?}", e)
    }
}
