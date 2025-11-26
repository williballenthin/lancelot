//https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Processors/x86/data/patterns/x86-64gcc_patterns.xml

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

        // NOP NOP, x86-64gcc_patterns.xml
        let NOP = r"\x90\x90";
        // RET NOP, x86-64gcc_patterns.xml
        let RET_NOP = r"\xC3\x90";
        // two-byte nop, x86-64gcc_patterns.xml
        let NOP2 = r"\x66\x90";
        // LEAVE RET, x86-64gcc_patterns.xml
        let LEAVE_RET = r"\xC9\xC3";
        // JMP xxx - after a shared jump target, x86-64gcc_patterns.xml
        let JMP = r"\xE9....";
        // JMP xxx, NOP - after a shared jump target, x86-64gcc_patterns.xml
        let JMP_NOP = r"\xE9....\x90";
        // JMP small, x86-64gcc_patterns.xml
        let JMP_SMALL = r"\xEB..";
        // JMP small, NOP, x86-64gcc_patterns.xml
        let JMP_SMALL_NOP = r"\xEB..\x90";
        // POP RBP, RET, x86-64gcc_patterns.xml
        let POP_RBP_RET = r"\x5D\xC3";
        // POP RBX, RET, x86-64gcc_patterns.xml
        let POP_RBX_RET = r"\x5B\xC3";
        // POP R12-15, RET, x86-64gcc_patterns.xml
        let POP_R_RET = r"\x41[\x5C-\x5F]\xC3";
        // XOR(EAX,EAX), RET, x86-64gcc_patterns.xml
        let XOR_EAX_RET = r"\x31\xC0\xC3";
        // ADD RSP, C; RET, x86-64gcc_patterns.xml
        let ADD_RSP_RET = r"\x48\x83\xC4.\xC3";
        // three-byte NOP, x86-64gcc_patterns.xml
        let NOP3 = r"\x66\x66\x90";
        // three-byte NOP, x86-64gcc_patterns.xml
        let NOP3_ALT = r"\x0F\x1F\x00";
        // four-byte NOP, x86-64gcc_patterns.xml
        let NOP4 = r"\x0F\x1F\x40\x00";
        // five-byte NOP, x86-64gcc_patterns.xml
        let NOP5 = r"\x0F\x1F\x44\x00\x00";
        // six-byte NOP, x86-64gcc_patterns.xml
        let NOP6 = r"\x66\x0F\x1F\x44\x00\x00";
        // seven-byte NOP, x86-64gcc_patterns.xml
        let NOP7 = r"\x0F\x1F\x80\x00\x00\x00\x00";
        // eight-byte NOP, x86-64gcc_patterns.xml
        let NOP8 = r"\x0F\x1F\x84\x00\x00\x00\x00\x00";
        // nine-byte NOP, x86-64gcc_patterns.xml
        let NOP9 = r"\x66\x0F\x1F\x84\x00\x00\x00\x00\x00";

        let PREPATTERN = format!("(?P<prepattern>{})", [
            NOP,
            RET_NOP,
            NOP2,
            LEAVE_RET,
            JMP,
            JMP_NOP,
            JMP_SMALL,
            JMP_SMALL_NOP,
            POP_RBP_RET,
            POP_RBX_RET,
            POP_R_RET,
            XOR_EAX_RET,
            ADD_RSP_RET,
            NOP3,
            NOP3_ALT,
            NOP4,
            NOP5,
            NOP6,
            NOP7,
            NOP8,
            NOP9,
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

        // x86-64gcc_patterns.xml#L1
        //    PUSH RBP; MOV(EBP, ESP) (shared objects)
        // <data>0x5589e5</data>
        let P7 = r"\x55\x89\xE5";

        // x86-64gcc_patterns.xml#L2
        //    PUSH RBP; PUSH RBX; MOV(R12/3/4/5/xX,RxX)
        // <data>0x55 0x53 0100100. 0x89 11......</data>
        let P8 = r"\x55\x53[\x48-\x4F]\x89[\xC0-\xFF]";

        // x86-64gcc_patterns.xml#L3
        //    PUSH R12; PUSH RBP; MOV(R12/3/4/5/xX,RxX)
        // <data>0x4154 0x55 0100100. 0x89 11......</data>
        let P9 = r"\x41\x54\x55[\x48-\x4F]\x89[\xC0-\xFF]";

        // x86-64gcc_patterns.xml#L4
        //    PUSH R12; PUSH RBP; PUSH RBX; MOV(R12/3/4/5/xX,RxX)
        // <data>0x4154 0x55 0x53 0100100. 0x89 11......</data>
        let P10 = r"\x41\x54\x55\x53[\x48-\x4F]\x89[\xC0-\xFF]";

        // x86-64gcc_patterns.xml#L5
        //    PUSH RBX; SUB RSP, C
        // <data>0x53 0x48 0x83 0xec 0....000</data>
        let P11 = r"\x53\x48\x83\xEC.";

        // x86-64gcc_patterns.xml#L6
        //    SUB RSP, C
        // <data>0x48 0x83 0xec .....000</data>
        let P12 = r"\x48\x83\xEC.";

        // x86-64gcc_patterns.xml#L7
        //    SUB RSP, big C
        // <data>0x48 0x81 0xec .....000 00...... 0x00</data>
        let P13 = r"\x48\x81\xEC..\x00";

        // x86-64gcc_patterns.xml#L8
        //    PUSH RBP; PUSH RBX; SUB RSP, big/C
        // <data>0x55 0x53 0x48 0x83 100000.1 0xec .....000</data>
        let P14 = r"\x55\x53\x48\x83.\xEC.";

        // x86-64gcc_patterns.xml#L9
        //    PUSH RBP; MOV(RBP, RSP) (shared objects)
        // <data>0x554889e5</data>
        let P15 = r"\x55\x48\x89\xE5";

        // x86-64gcc_patterns.xml#L10
        //    PUSH RBP; MOV RBP, RSP; SUB RSP, big/C
        // <data>0x55 0x48 0x89 0xe5 0x48 100000.1 0xec .....000</data>
        let P16 = r"\x55\x48\x89\xE5\x48.\xEC.";

        // x86-64gcc_patterns.xml#L11
        //    PUSH RBP; MOV RBP, RSP; PUSH RBX
        // <data>0x554889e553</data>
        let P17 = r"\x55\x48\x89\xE5\x53";

        // x86-64gcc_patterns.xml#L12
        //    PUSH R15; PUSH R14; PUSH R13
        // <data>0x4157 0x4156 0x4155</data>
        let P20 = r"\x41\x57\x41\x56\x41\x55";

        // x86-64gcc_patterns.xml#L13
        //    PUSH R15; PUSH R14
        // <data>0x4157 0x4156</data>
        let P21 = r"\x41\x57\x41\x56";

        // x86-64gcc_patterns.xml#L14
        //    PUSH R14; PUSH R13
        // <data>0x4156 0x4155</data>
        let P22 = r"\x41\x56\x41\x55";

        // x86-64gcc_patterns.xml#L15
        //    PUSH R13; PUSH R12
        // <data>0x41554154</data>
        let P23 = r"\x41\x55\x41\x54";

        // x86-64gcc_patterns.xml#L16
        //    PUSH R12/3/4/5; MOV(R12/3/4/5/xX,RxX); PUSH(RBP)
        // <data>0x41 010101.. 0100100. 0x89 11......</data>
        let P24 = r"\x41[\x54-\x57][\x48-\x4F]\x89[\xC0-\xFF]\x55";

        // x86-64gcc_patterns.xml#L17
        //    PUSH R12/3/4/5; PUSH R12/3/4/5; MOV(R12/3/4/5/xX,RxX)
        // <data>0x41 010101.. 0x41 010101.. 0100100. 0x89 11......</data>
        let P25 = r"\x41[\x54-\x57]\x41[\x54-\x57][\x48-\x4F]\x89[\xC0-\xFF]";

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
            P0, P1, P2, P3, P4, P5, P6, P7, P8, P9, P10, P11, P12, P13, P14, P15, P16, P17, P18, P19, P20, P21, P22, P23, P24, P25
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
