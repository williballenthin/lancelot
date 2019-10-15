use std::path::{Path};

use log::{debug, info, trace};
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
    /// parse the given file system path into a collection of FLIRT signatures.
    fn load_flirt_file(path: &Path) -> Result<Vec<flirt::FlirtSignature>, Error> {
        let buf = util::read_file(path.to_str().unwrap())?;  // danger
        let s = String::from_utf8(buf)?;
        pat::parse(&s)
    }

    /// remove sigantures from the given collection that don't match basic criteria:
    ///   - the signature must specify a name (or its no use to us)
    ///   - functions must be at least 8 bytes long
    ///   - shorter functions must not have too many wildcards
    fn filter_flirt_signatures(sigs: Vec<flirt::FlirtSignature>) -> Vec<flirt::FlirtSignature> {
        sigs.into_iter()
            .filter(|sig| {
                if let None = sig.get_name() {
                    // must have a name that we can apply.
                    return false;
                }

                let wc_count = sig.byte_sig.0.iter().take(sig.size_of_function as usize).filter(|b| match b {
                    flirt::SigElement::Wildcard => true,
                    flirt::SigElement::Byte(_) => false,
                }).count();

                if sig.size_of_function < 0x8 {
                    // lancelot specific: don't use signatures for functions less than 0x8 bytes.
                    // this just seems too short to be unique and specific.
                    trace!("sig too short: {} {:?}", sig.size_of_function, sig.get_name());
                    return false;
                } else if sig.size_of_function < 0x10 && wc_count > 0 {
                    // lancelot specific: don't allow many wildcards for short functions.
                    trace!("sig too many wildcards: {}/{} {:?}", wc_count, sig.size_of_function, sig.get_name());
                    return false;
                } else if sig.size_of_function < 0x18 && wc_count > 4 {
                    trace!("sig too many wildcards: {}/{} {:?}", wc_count, sig.size_of_function, sig.get_name());
                    return false;
                } else if sig.size_of_function < 0x20 && wc_count > 0x10 {
                    trace!("sig too many wildcards: {}/{} {:?}", wc_count, sig.size_of_function, sig.get_name());
                    return false;
                } else {
                    return true;
                }
            })
            .collect()
    }

    /// parse the given directory into a set of FLIRT signatures.
    ///
    /// applies some filtering on the signatures for better accuracy:
    ///   - the signature must specify a name (or its no use to us)
    ///   - functions must be at least 8 bytes long
    ///   - shorter functions must not have too many wildcards
    ///
    /// the directory structure should look like:
    ///   - flat directory of .pat files
    fn load_flirt_directory(path: &str) -> Result<flirt::FlirtSignatureSet, Error> {

        // TODO: need lots of error handling here.

        let mut sigs = vec![];

        for entry in std::fs::read_dir(Path::new(path))? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                continue
            }

            let ext = path.extension().and_then(|ext| ext.to_str()).unwrap_or("");

            if ext == "pat" {
                debug!("FLIRT analyzer: loading .pat file: {:?}", path);
                sigs.extend(FlirtAnalyzer::load_flirt_file(&path).unwrap()); //danger
            } else if ext == ".sig" {
                // ....
                debug!("FLIRT analyzer: skipping .sig file: {:?}", path);
            } else {
                debug!("FLIRT analyzer: skipping file: {:?}", path);
            }
        }
        debug!("loaded {} total FLIRT signatures", sigs.len());

        let sigs = FlirtAnalyzer::filter_flirt_signatures(sigs);
        info!("loaded {} FLIRT signatures", sigs.len());

        Ok(flirt::FlirtSignatureSet::with_signatures(sigs))
    }

    pub fn new() -> FlirtAnalyzer {
        // TODO: add startup signatures to detect runtime/signature set
        // TODO: use .sig rather than .pat files
        let sigs = FlirtAnalyzer::load_flirt_directory("C:/Users/user/Documents/code/Lancelot/flirt/sigs/pat/").unwrap();

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

                // no matches
                if matches.len() == 0 {
                    continue;
                }

                if matches.len() > 1 {
                    // more than one match.
                    //
                    // the only time this is acceptable is if we've loaded multiple signature sets
                    //  and these match the same functions.
                    // in this case, all the names should be the same.
                    // so, lets ensure their names don't conflict.
                    //
                    // implementation: the first name should be the same as all the other names.
                    let name1 = matches[0].get_name();
                    if let Some(m2) = matches[1..]
                        .iter()
                        .find(|m| m.get_name() != name1) {

                        debug!("ambiguous FLIRT signature match: {}: {:?} and {:?}",
                               fva, name1, m2.get_name());
                        continue;
                    }
                };

                let match_ = matches[0];

                // TODO: should not apply the same symbol name to more than one location?
                // TODO: apply reference names

                // can unwrap name cause its guaranteed to have a name due to filter above.
                let name = match_.get_name().unwrap();
                debug!("FLIRT signature match: {} {}", fva, name);
                ws.make_symbol(fva, name).unwrap();  // danger
                continue;
            }
        }

        ws.analyze()?;

        Ok(())
    }
}
