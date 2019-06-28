use log::{debug};
use goblin::{Object};
use failure::{Error};

use super::super::{Analyzer};
use super::super::super::arch::RVA;
use super::super::super::workspace::Workspace;


pub struct EntryPointAnalyzer {}

impl EntryPointAnalyzer {
    pub fn new() -> EntryPointAnalyzer {
        EntryPointAnalyzer {}
    }
}

impl Analyzer for EntryPointAnalyzer {
    fn get_name(&self) -> String {
        "PE entry point analyzer".to_string()
    }

    fn analyze(&self, ws: &mut Workspace) -> Result<(), Error> {
        let pe = match Object::parse(&ws.buf) {
            Ok(Object::PE(pe)) => pe,
            _ => panic!("can't analyze unexpected format"),
        };

        let entry = RVA::from(pe.entry);
        debug!("entry point: {}", entry);

        ws.make_symbol(entry, "entry")?;
        ws.make_function(entry)?;
        ws.analyze()?;

        Ok(())
    }
}
