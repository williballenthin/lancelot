use log::{debug};
use goblin::{Object};
use failure::{Error};

use super::super::super::arch::{RVA};
use super::super::super::workspace::Workspace;
use super::super::{Analyzer};


pub struct ExportsAnalyzer {}

impl ExportsAnalyzer {
    pub fn new() -> ExportsAnalyzer {
        ExportsAnalyzer{}
    }
}

impl Analyzer for ExportsAnalyzer {
    fn get_name(&self) -> String {
        "PE exports analyzer".to_string()
    }

    fn analyze(&self, ws: &mut Workspace) -> Result<(), Error> {
        let pe = match Object::parse(&ws.buf) {
            Ok(Object::PE(pe)) => pe,
            _ => panic!("can't analyze unexpected format"),
        };

        let entry = RVA::from(pe.entry);

        let exports: Vec<RVA> = pe.exports.iter()
            // re-exports are simply strings that point to a `DLL.export_name` ASCII string.
            // therefore, they're not functions/code.
            .filter(|exp| exp.reexport.is_none())
            .map(|exp| exp.rva)
            .map(|rva| RVA::from(rva))
            .collect();

        let symbols: Vec<(RVA, String)> = pe.exports.iter()
            .filter(|exp| exp.name.is_some())
            .map(|exp| (RVA::from(exp.rva), exp.name.unwrap().to_string()))
            .collect();

        for (rva, name) in symbols.into_iter() {
            debug!("export: {}: {}", rva, name);
            ws.make_symbol(rva, &name)?;
            ws.analyze()?;
        }

        for rva in exports.into_iter() {
            ws.make_function(rva)?;
            ws.analyze()?;
        }

        ws.make_function(entry)?;
        ws.make_symbol(entry, "entry")?;
        ws.analyze()?;

        Ok(())
    }
}
