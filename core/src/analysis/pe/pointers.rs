//! Scan the file looking for aligned, pointer-sized values that fall within an executable section.
//!
//! This analysis pass should be particularly useful for finding callbacks,
//! such as the start address passed to `CreateThread`.
//!
//! TODO: would need to search for non-pointer aligned pointers in executable sections.
//! TODO: alternatively, can use relocation information to help with this.
//! TODO: but doesn't help find callbacks referenced relatively - need disassembly for this.
//!
//! This analysis pass should also be good at handling global vtables.
//! Its especially important when CFGuard metadata is not present.
//!
//! Assumes:
//!   - sections are pointer aligned (guaranteed)
//!   - pointers are pointer aligned (probably guaranteed in data sections)
//!   - pointers are 32-bits on x32 and 64-bits on x64 (*not* 32-bits on x64)
//!
//! However, in practice, the analysis pass doesn't work very well, as it generates many FPs due to:
//!   - exception handlers
//!   - jump table entries
//!
//! Filtering out these two constructs is difficult with analyzing how the pointers are used.
//!
//! TODO: quantify how useful this pass is, especially in presence/absence of CFGuard.

use anyhow::Result;
use byteorder::ByteOrder;

use crate::loader::pe::PE;
use crate::VA;

pub fn _find_pe_nonrelocated_executable_pointers<'a>(buf: &'a [u8], pe: &PE) -> Result<Vec<VA>> {
    let executable_sections = pe.get_pe_executable_sections()?;

    // TODO: this may find jump table entries, such as 0x401B74 in nop.exe.
    //
    //     .text:00401B74 jpt_40141F      dd offset loc_4015B6    ; DATA XREF: __output+85↑r
    //     .text:00401B74                 dd offset loc_401426    ; jump table for switch statement
    //     .text:00401B74                 dd offset loc_401443
    //     .text:00401B74                 dd offset loc_40148F
    //     .text:00401B74                 dd offset loc_4014D0
    //     .text:00401B74                 dd offset loc_4014D9
    //     .text:00401B74                 dd offset loc_401517
    //     .text:00401B74                 dd offset loc_4015F8
    //
    // notably:
    //   1. there are contiguous pointers into the same section
    //   2. this is in an executable section
    //
    // we should be able to use these facts, at least for this compiler, to filter out jmp tables.
    //
    // however, in vdir.exe, we see the jump table in a non-executable section (.rdata):
    //
    //     FF 24 85 AC B6 41 00    jmp     ds:jpt_415D57[eax*4] ; switch jump
    //
    //     ; jump table for switch statement sub_415AC0+297
    //     .rdata:0041B6AC jpt_415D57      dd offset loc_416219, offset loc_4171DE, offset def_415D57
    //     .rdata:0041B6AC                 dd offset def_415D57, offset def_415D57, offset def_415D57
    //     .rdata:0041B6AC                 dd offset def_415D57, offset def_415D57, offset def_415D57
    //     .rdata:0041B6AC                 dd offset def_415D57, offset def_415D57, offset def_415D57
    //
    // in the same binary, we also have this handler lookup:
    //
    //     8B 04 85 00 BC 41 00    mov     eax, ds:off_41BC00[eax*4]
    //     89 44 24 08             mov     [esp+1Ch+var_14], eax
    //     E8 A7 B1 00 00          call    sub_40CA90
    //
    //     .rdata:0041BC00 off_41BC00      dd offset sub_403220    ; DATA XREF: sub_401810+C9↑r
    //     .rdata:0041BC04                 dd offset sub_403260
    //     .rdata:0041BC08                 dd offset sub_403240
    //     .rdata:0041BC0C                 dd offset sub_4032F0
    //     .rdata:0041BC10                 dd offset sub_4016C0
    //     .rdata:0041BC14                 dd offset sub_401BC0
    //
    // these point to functions, but not all start with a typical prologue (e.g. first entry):
    //
    //     8B 44 24 04             mov     eax, [esp+arg_0]
    //     8B 10                   mov     edx, [eax]
    //     8B 44 24 08             mov     eax, [esp+arg_4]
    //     8B 00                   mov     eax, [eax]

    // TODO: within code, global pointers may not be pointer-aligned?

    if pe.pe.header.coff_header.machine == goblin::pe::header::COFF_MACHINE_X86_64 {
        Ok(buf
            .chunks_exact(8)
            .map(|b| byteorder::LittleEndian::read_u64(b) as VA)
            .filter(|&va| {
                executable_sections
                    .iter()
                    .any(|section| section.start <= va && section.end > va)
            })
            .collect())
    } else {
        Ok(buf
            .chunks_exact(4)
            .map(|b| byteorder::LittleEndian::read_u32(b) as VA)
            .filter(|&va| {
                executable_sections
                    .iter()
                    .any(|section| section.start <= va && section.end > va)
            })
            .collect())
    }
}
