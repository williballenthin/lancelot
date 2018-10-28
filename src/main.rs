extern crate log;
extern crate lancelot;

use std::env;
use std::process;
use log::{error};

use lancelot::Config;


fn main() {
    let args = Config::from_args(env::args()).unwrap_or_else(|err| {
        eprintln!("error parsing arguments: {}", err);
        process::exit(1);
    });

    lancelot::setup_logging(&args);

    if let Err(e) = lancelot::run(&args) {
        error!("{:?}", e)
    }
}
