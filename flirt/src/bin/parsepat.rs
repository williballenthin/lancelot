use anyhow::Result;

fn run(pat_path: &str) -> Result<()> {
    let pat = String::from_utf8(std::fs::read(pat_path)?)?;

    for pat in lancelot_flirt::pat::parse(&pat)?.iter() {
        println!("{}", pat.render_pat());
    }

    Ok(())
}

fn main() {
    better_panic::install();

    let matches = clap::App::new("parsepat")
        .author("Willi Ballenthin <william.ballenthin@mandiant.com>")
        .about("parse a .pat file and... do nothing.")
        .arg(
            clap::Arg::new("verbose")
                .short('v')
                .long("verbose")
                .multiple_occurrences(true)
                .help("log verbose messages"),
        )
        .arg(clap::Arg::new("pat").required(true).index(1).help("path to .pat file"))
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
        eprintln!("error: {e:}");
    }
}
