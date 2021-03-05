use anyhow::Result;
extern crate chrono;
extern crate clap;
extern crate log;

fn run(pat_path: &str) -> Result<()> {
    let pat = String::from_utf8(std::fs::read(pat_path)?)?;

    for pat in lancelot_flirt::pat::parse(&pat)?.iter() {
        println!("{}", pat.render_pat());
    }

    Ok(())
}

fn main() {
    better_panic::install();

    // while the macro form of clap is more readable,
    // it doesn't seem to allow us to use dynamically-generated values,
    // such as the defaults pulled from env vars, etc.
    let matches = clap::App::new("parsepat")
        .author("Willi Ballenthin <willi.ballenthin@gmail.com>")
        .about("parse a .pat file and... do nothing.")
        .arg(
            clap::Arg::with_name("verbose")
                .short("v")
                .long("verbose")
                .multiple(true)
                .help("log verbose messages"),
        )
        .arg(
            clap::Arg::with_name("pat")
                .required(true)
                .index(1)
                .help("path to .pat file"),
        )
        .get_matches();

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
                if log_level == log::LevelFilter::Trace {
                    record.target()
                } else {
                    ""
                },
                message
            ))
        })
        .level(log_level)
        .chain(std::io::stderr())
        .apply()
        .expect("failed to configure logging");

    if let Err(e) = run(matches.value_of("pat").unwrap()) {
        eprintln!("error: {:}", e);
    }
}
