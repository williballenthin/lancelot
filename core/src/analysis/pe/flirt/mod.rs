use log::{debug};
use failure::{Error};
use flirt;
use flirt::pat;


use super::super::super::util;
use super::super::super::arch::{RVA};
use super::super::super::workspace::Workspace;
use super::super::{Analyzer};


pub struct FlirtAnalyzer {
    sigs: flirt::FlirtSignatureSet,
}

impl FlirtAnalyzer {
    pub fn new() -> FlirtAnalyzer {
        // TODO: read all pat files in this directory
        // TODO: filter signatures for:
        //   - duplicates
        //   - not specific enough (no checksum, too many wildcards, etc.)
        // TODO: add startup signatures to detect runtime/signature set
        let path = "C:/Users/user/Documents/code/Lancelot/flirt/sigs/pat/__EH_prolog3.pat";
        let buf = util::read_file(path).unwrap();  // danger
        let s = String::from_utf8(buf).unwrap(); // danger
        let sigs = flirt::FlirtSignatureSet::with_signatures(pat::parse(&s).unwrap());  // danger

        FlirtAnalyzer{
            sigs
        }
    }
}

impl Analyzer for FlirtAnalyzer {
    fn get_name(&self) -> String {
        "FLIRT function signature analyzer".to_string()
    }

    fn analyze(&self, ws: &mut Workspace) -> Result<(), Error> {
        let mut buf = [0u8; 0xFF];
        let functions: Vec<RVA> = ws.get_functions().cloned().collect();

        for &fva in functions.iter() {
            if let Ok(buf) = ws.read_bytes_into(fva, &mut buf[..]) {
                let matches = self.sigs.r#match(buf);

                match matches.len() {
                    0 => debug!("no FLIRT signature match: {}", fva),
                    1 => {
                        if let Some(name) = matches[0].get_name() {
                            debug!("FLIRT signature match: {} {}", fva, name);
                            ws.make_symbol(fva, name).unwrap();  // danger
                        }
                    }
                    _ => debug!("many FLIRT signature matches: {}", fva),
                }
            }
        }

        ws.analyze()?;

        Ok(())
    }
}
