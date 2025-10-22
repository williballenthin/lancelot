#![allow(non_snake_case)]
use anyhow::Result;
use log::debug;
use regex::bytes::Regex;

use crate::{
    aspace::AddressSpace,
    loader::elf::ELF,
    VA
};

lazy_static! {
    static ref PATTERNS: Regex = {

        // CC debug filler, x86win_patterns.xml#L4
        let CC = r"\xCC";
        // multiple CC filler bytes, x86win_patterns.xml#L5
        let CCCC = r"\xCC\xCC";
        // NOP filler, x86win_patterns.xml#L6
        let NOP = r"\x90";
        // RET filler, x86win_patterns.xml#L7
        let RET = r"\xC3";
        // LEAVE RET, x86win_patterns.xml#L8
        let LEAVE_RET = r"\xC9\xC3";

        // JMP DWORD PTR ds:????????
        // mimikatz:0x46B674
        let JMP_FAR = r"\xFF\x25....";

        // RETN ???
        // mimikatz:0x45D025
        let RETN = r"\xC2..";

        // x86win_patterns.xml#L9
        // 0xC2 ......00 0x00
        // let RET_LONGFORM =

        let PREPATTERN = format!("(?P<prepattern>{})", [
            CC,
            CCCC,
            NOP,
            RET,
            LEAVE_RET,
            JMP_FAR,
            RETN,
        ].join("|"));

        // PUSH EBP; MOV EBP, ESP, x86win_patterns.xml#L12
        let P0 = r"\x55\x8B\xEC";

        // x64 standard prologue: PUSH RBP; MOV RBP, RSP
        let P1 = r"\x55\x48\x89\xE5";

        // x64 prologue with SUB RSP
        // PUSH RBP; MOV RBP, RSP; SUB RSP, ??
        let P2 = r"\x55\x48\x89\xE5\x48\x83\xEC.";

        // ENDBR64; PUSH RBP; MOV RBP, RSP
        let P3 = r"\xF3\x0F\x1E\xFA\x55\x48\x89\xE5";

        // x64 ENDBR64 alone
        let P4 = r"\xF3\x0F\x1E\xFA";

        // LEA RDI, [RIP+offset]
        let P5 = r"\x48\x8D\x3D....";

        // x86win_patterns.xml#L18
        //    MOV EDI,EDI : PUSH EBP : MOV EBP,ESP
        // <data>0x8bff558bec</data>
        let P6 = r"\x8B\xFF\x55\x8B\xEC";

        // x64 msvc prologue
        // see #100
        //
        //     .text:0000000140001060 48 89 54 24 10       mov     [rsp+arg_8], rdx
        //     .text:0000000140001065 4C 89 44 24 18       mov     [rsp+arg_10], r8
        //     .text:000000014000106A 4C 89 4C 24 20       mov     [rsp+arg_18], r9
        //     .text:000000014000106F 53                   push    rbx
        //     .text:0000000140001070 56                   push    rsi
        //     .text:0000000140001071 57                   push    rdi
        //     .text:0000000140001072 48 83 EC 30          sub     rsp, 30h
        let P18 = r"
            (?:
                (?: \x48|\x4C ) \x89 . \x24 .    # mov  [rsp+??], ??
            )+
            \x40? [\x50-\x5F]+                   # push ??
            \x48 \x83 \xEC .                     # sub  rsp, ??
        ";
        
        // x64 msvc prologue
        //
        //     .text:000000014004742B 40 55                push    rbp
        //     .text:000000014004742D 48 83 EC 20          sub     rsp, 20h
        let P19 = r"
            \x40 \x55                            # push rbp
            \x48 \x83 \xEC .                     # sub  rsp, ??
        ";

        let POSTPATTERN = format!("(?P<postpattern>{})", [
            P0, P1, P2, P3, P4, P5, P6, P18, P19
        ].join("|"));

        let re = format!(
            r"(?x)                # whitespace allowed
              (?-u)               # disable unicode mode, so we can match raw bytes
              (:?{PREPATTERN})    # capture the pre match
              (:?{POSTPATTERN})   # capture the match
            ");

        Regex::new(&re).unwrap()
    };
}

#[allow(dead_code)]
const INDEX_ALL: usize = 0;
#[allow(dead_code)]
const INDEX_PREMATCH: usize = 2;
const INDEX_MATCH: usize = 4;

pub fn find_function_prologues(elf: &ELF) -> Result<Vec<VA>> {
    let mut ret = vec![];

    for section in elf.module.sections.iter() {
        let name = &section.name;
        let vstart: VA = section.virtual_range.start;
        let vsize = (section.virtual_range.end - section.virtual_range.start) as usize;
        let sec_buf = elf.module.address_space.read_bytes(vstart, vsize)?;

        for capture in PATTERNS.captures_iter(&sec_buf) {
            let m = capture.get(INDEX_MATCH).unwrap();
            let va = vstart + m.start() as u64;
            ret.push(va);
        }

        let count = ret.len();
        debug!("elf function prologues: {name}, candidates: {count}");
    }
    
    Ok(ret)
}
