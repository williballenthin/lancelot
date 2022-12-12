use anyhow::Result;

fn run(sig_path: &str) -> Result<()> {
    let buf = std::fs::read(sig_path)?;

    for sig in lancelot_flirt::sig::parse(&buf)?.iter() {
        println!("{}", sig.render_pat());
    }

    Ok(())
}

fn main() {
    better_panic::install();

    let matches = clap::App::new("sig2pat")
        .author("Willi Ballenthin <william.ballenthin@mandiant.com>")
        .about("translate a FLIRT .sig file into a .pat file")
        .arg(
            clap::Arg::new("verbose")
                .short('v')
                .long("verbose")
                .multiple_occurrences(true)
                .help("log verbose messages"),
        )
        .arg(clap::Arg::new("sig").required(true).index(1).help("path to .sig file"))
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

    if let Err(e) = run(matches.value_of("sig").unwrap()) {
        eprintln!("error: {e}");
    }
}
