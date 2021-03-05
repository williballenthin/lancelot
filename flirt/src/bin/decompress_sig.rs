use anyhow::Result;
extern crate chrono;
extern crate clap;
extern crate log;

fn run(sig_path: &str, output_path: &str) -> Result<()> {
    let buf = std::fs::read(sig_path)?;
    let buf = lancelot_flirt::sig::unpack_sig(&buf)?;

    std::fs::write(output_path, &buf)?;

    Ok(())
}

fn main() {
    better_panic::install();

    // while the macro form of clap is more readable,
    // it doesn't seem to allow us to use dynamically-generated values,
    // such as the defaults pulled from env vars, etc.
    let matches = clap::App::new("sig2pat")
        .author("Willi Ballenthin <willi.ballenthin@gmail.com>")
        .about("decompress a FLIRT .sig file with compression into one without compression")
        .arg(
            clap::Arg::with_name("verbose")
                .short("v")
                .long("verbose")
                .multiple(true)
                .help("log verbose messages"),
        )
        .arg(
            clap::Arg::with_name("sig")
                .required(true)
                .index(1)
                .help("path to .sig file"),
        )
        .arg(
            clap::Arg::with_name("output")
                .required(true)
                .index(2)
                .help("path to output file"),
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

    if let Err(e) = run(matches.value_of("sig").unwrap(), matches.value_of("output").unwrap()) {
        eprintln!("error: {:}", e);
    }
}
