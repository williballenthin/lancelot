// https://github.com/NationalSecurityAgency/ghidra/tree/79d8f164f8bb8b15cfb60c5d4faeb8e1c25d15ca/Ghidra/Processors/x86/data/patterns

use anyhow::Result;
use log::debug;
use regex::bytes::Regex;

use crate::loader::pe::PE;
use crate::VA;

lazy_static! {
    static ref PATTERNS: Regex = {

        /// CC debug filler, x86win_patterns.xml#L4
        let CC = b"\xCC";
        /// multiple CC filler bytes, x86win_patterns.xml#L5
        let CCCC = b"\xCC\xCC";
        /// NOP filler, x86win_patterns.xml#L6
        let NOP = b"\x90";
        /// RET filler, x86win_patterns.xml#L7
        let RET = b"\xC3";
        /// LEAVE RET, x86win_patterns.xml#L8
        let LEAVE_RET = b"\xC9\xC3";

        /// x86win_patterns.xml#L9
        // 0xC2 ......00 0x00
        // let RET_LONGFORM =

        // (?-u)($one|$two|$three|...)

        let re = format!(
            r"(?x)   # whitespace allowed
              (?-u)  # disable unicode mode, so we can match raw bytes
              ({})   # capture the match
            ",
            patterns
            );

        Regex::new(re)
    };
}

/*
pub fn find_function_prologues(pe: &PE) -> Result<Vec<VA>> {
    let mut ret = vec![];
    let executable_sections = pe.get_pe_executable_sections()?;

    for section in executable_sections.iter() {
        let sec_buf = pe.module.address_space.slice(section.start - pe.module.base_address, section.end - pe.module.base_address)?;
    }
}
 */
