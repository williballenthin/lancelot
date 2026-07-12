extern crate log;

/// shared plumbing for the lancelot CLI tools:
/// common arguments, logging setup, and workspace configuration.
pub mod cli {
    /// add the standard `--verbose`/`--quiet` arguments.
    pub fn add_common_args(cmd: clap::Command) -> clap::Command {
        cmd.arg(
            clap::Arg::new("verbose")
                .short('v')
                .long("verbose")
                .action(clap::ArgAction::Count)
                .help("log verbose messages"),
        )
        .arg(
            clap::Arg::new("quiet")
                .short('q')
                .long("quiet")
                .action(clap::ArgAction::SetTrue)
                .help("disable informational messages"),
        )
    }

    /// configure logging according to the standard `--verbose`/`--quiet`
    /// arguments (see [`add_common_args`]).
    ///
    /// messages from the given targets are suppressed,
    /// in addition to the always-noisy `goblin::pe`.
    pub fn configure_logging(matches: &clap::ArgMatches, ignored_targets: &'static [&'static str]) {
        // --quiet overrides --verbose
        let log_level = if matches.get_flag("quiet") {
            log::LevelFilter::Error
        } else {
            match matches.get_count("verbose") {
                0 => log::LevelFilter::Info,
                1 => log::LevelFilter::Debug,
                _ => log::LevelFilter::Trace,
            }
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
            .filter(|metadata| !metadata.target().starts_with("goblin::pe"))
            .filter(move |metadata| {
                !ignored_targets
                    .iter()
                    .any(|target| metadata.target().starts_with(target))
            })
            .apply()
            .expect("failed to configure logging");

        // Enable ANSI support for Windows
        // via: https://github.com/sharkdp/hexyl/blob/d1ae68585fe743d225bb39361bd383cb925b61f7/src/bin/hexyl.rs#L261
        #[cfg(windows)]
        let _ = nu_ansi_term::enable_ansi_support();
    }

    /// add the standard `--config` argument.
    pub fn add_config_arg(cmd: clap::Command) -> clap::Command {
        cmd.arg(
            clap::Arg::new("configuration")
                .long("config")
                .help("path to configuration directory"),
        )
    }

    /// build the workspace configuration according to the standard `--config`
    /// argument (see [`add_config_arg`]).
    pub fn configuration_from_matches(
        matches: &clap::ArgMatches,
    ) -> Box<dyn lancelot::workspace::config::Configuration> {
        if let Some(path) = matches.get_one::<String>("configuration") {
            log::info!("configuration: {}", path);
            Box::new(lancelot::workspace::config::FileSystemConfiguration::from_path(
                &std::path::PathBuf::from(path),
            ))
        } else {
            log::info!("using default, empty configuration");
            lancelot::workspace::config::empty()
        }
    }
}
