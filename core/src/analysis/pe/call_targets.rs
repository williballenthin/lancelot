//! Search for functions by disassembling executable regions and finding `call` instructions.
//!
//! For each executable region, do a linear disassembly.
//! For each instruction,
//!  if the mnemonic is a `CALL`, then extract the first operand and try to follow it.
//! When this target falls within an executable region,
//!  then consider the target a potential function.
//! Rely on the caller to validate that the function looks reasonable, if necessary.
//!
//! Instead of a linear disassembly, we could do a thorough disassembly -
//! that is, attempt to disassemble *every* offset.
//! Here's a non-scientific comparison using `mshtml.exe`:
//!
//!   |                    | linear    | thorough     |
//!   +--------------------+-----------+--------------+
//!   | time               |   2.6 sec |      7.4 sec |
//!   | valid instructions | 4,802,884 |   15,164,782 |
//!   | calls              |   276,830 |      354,260 |
//!   | functions found    |    42,242 |       44,174 |
//!   +--------------------+-----------+--------------+
//!
//!  notes:
//!   - `--release` mode
//!   - other analysis passes disabled
//!   - no validation of the found functions (e.g. sane disassembly)
//!
//! Conclusion: thorough disassembly takes a lot more cycles at minimal gain.
//! I've heard that Intel x86 is "self-synchronizing", though I don't have a reference.
//! In any case, the effect is that linear disassembly should work well *most* of the time.

// TODO: detect thunks (call to unconditional jmp).

use log::debug;

use anyhow::Result;

use crate::aspace::AddressSpace;
use crate::loader::pe::PE;
use crate::util;
use crate::VA;

fn get_disassember(pe: &PE) -> Result<zydis::Decoder> {
    let mut decoder = match pe.pe.is_64 {
        true => zydis::Decoder::new(zydis::MachineMode::LONG_64, zydis::AddressWidth::_64)?,
        false => zydis::Decoder::new(zydis::MachineMode::LEGACY_32, zydis::AddressWidth::_32)?,
    };

    // modes described here: https://github.com/zyantific/zydis/blob/5af06d64432aaa3f6af3cd3e120eefa061b790ab/include/Zydis/Decoder.h#L55
    //
    // performance, captured empirically:
    //  - minimal mode - 8.7M instructions/second
    //  - full mode    - 4.5M instructions/second
    decoder.enable_mode(zydis::DecoderMode::MINIMAL, false)?;

    decoder.enable_mode(zydis::DecoderMode::KNC, false)?;
    decoder.enable_mode(zydis::DecoderMode::MPX, false)?;
    decoder.enable_mode(zydis::DecoderMode::CET, false)?;
    decoder.enable_mode(zydis::DecoderMode::LZCNT, false)?;
    decoder.enable_mode(zydis::DecoderMode::TZCNT, false)?;
    decoder.enable_mode(zydis::DecoderMode::WBNOINVD, false)?;
    decoder.enable_mode(zydis::DecoderMode::CLDEMOTE, false)?;

    Ok(decoder)
}

fn linear_disassemble<'a>(
    decoder: &'a zydis::Decoder,
    buf: &'a [u8],
) -> Box<dyn Iterator<Item = (usize, zydis::Result<Option<zydis::DecodedInstruction>>)> + 'a> {
    let mut offset = 0usize;
    let mut insn_count = 0usize;
    let iter = std::iter::from_fn(move || {
        if offset >= buf.len() {
            debug!("decoded {} instructions", insn_count);
            return None;
        }

        let insn_offset = offset;
        let insn_buf = &buf[insn_offset..];
        let insn = decoder.decode(insn_buf);

        if let Ok(Some(insn)) = &insn {
            // see discussion of linear vs thorough disassemble in this module's doc.
            // thorough is 4x more expensive, with limited results.

            // linear disassembly:
            offset += insn.length as usize;

            // thorough disassembly:
            // offset += 1;

            insn_count += 1;
        } else {
            offset += 1;
        }

        Some((insn_offset, insn))
    });

    Box::new(iter)
}

pub fn find_pe_call_targets(pe: &PE) -> Result<Vec<VA>> {
    let mut ret = vec![];
    let executable_sections = pe.get_pe_executable_sections()?;
    let decoder = get_disassember(pe)?;

    let is_valid_target = |target: VA| -> bool { executable_sections.iter().any(|sec| sec.contains(&target)) };

    let mut call_count = 0usize;
    for section in executable_sections.iter() {
        let sec_buf = pe.module.address_space.relative.read_buf(
            section.start - pe.module.address_space.base_address,
            (section.end - pe.module.address_space.base_address) as usize,
        )?;
        for (insn_offset, insn) in linear_disassemble(&decoder, &sec_buf) {
            if let Ok(Some(insn)) = insn {
                if insn.meta.category != zydis::InstructionCategory::CALL {
                    continue;
                }

                let insn_va = section.start + insn_offset as u64;
                let op0 = &insn.operands[0];

                match op0.ty {
                    zydis::OperandType::POINTER => {
                        // the follow is *not* an actual instruction, but does decode ok.
                        // its located within a switch table in the .text section,
                        // so linear disassembly confuses it.
                        //
                        //     mimi.exe:.text:0042A00D 9A 42 00 9D 9B 42 00  call    far ptr 42h:9B9D0042h
                        //       ty: POINTER,
                        //       ptr: PointerInfo {
                        //         segment: 66,
                        //         offset: 2610757698,
                        //       },
                        //
                        // TODO: do something intelligent with the segment.
                        // i suspect we can whitelist the few valid segments?

                        // ref: https://c9x.me/x86/html/file_module_x86_id_147.html
                        //
                        // > Far Jumps in Real-Address or Virtual-8086 Mode.
                        // > When executing a far jump in realaddress or virtual-8086 mode,
                        // > the processor jumps to the code segment and offset specified with the target operand.
                        // > Here the target operand specifies an absolute far address either directly with a
                        // > pointer (ptr16:16 or ptr16:32) or indirectly with a memory location (m16:16 or m16:32).
                        // > With the pointer method, the segment and address of the called procedure is encoded
                        // > in the instruction, using a 4-byte (16-bit operand size) or
                        // > 6-byte (32-bit operand size) far address immediate.

                        let target = op0.ptr.offset as u64;
                        if is_valid_target(target) {
                            ret.push(target);
                        }
                    }
                    zydis::OperandType::IMMEDIATE => {
                        if op0.imm.is_relative {
                            //     nop.exe:.text:0040100C  E8 1A 00 00 00  call  _printf (0x40102B)
                            //       ty: IMMEDIATE
                            //       imm: ImmediateInfo {
                            //         is_signed: true,
                            //         is_relative: true,
                            //         value: 26,
                            //       },
                            let imm = if op0.imm.is_signed {
                                util::u64_i64(op0.imm.value)
                            } else {
                                op0.imm.value as i64
                            };

                            let target = ((insn_va + insn.length as u64) as i64 + imm) as u64;
                            if is_valid_target(target) {
                                ret.push(target);
                            }
                        } else {
                            debug!("CALL-IMM-ABS: {:#x}", insn_va);
                            panic!("call immediate absolute")
                        }
                    }
                    _ => continue,
                }

                call_count += 1;
            }
        }

        debug!("call count: {}", call_count);
    }

    Ok(ret)
}

#[cfg(test)]
mod tests {
    use crate::aspace::AddressSpace;
    use crate::rsrc::*;
    use anyhow::Result;

    #[test]
    fn k32() -> Result<()> {
        let buf = get_buf(Rsrc::K32);
        let pe = crate::loader::pe::load_pe(&buf)?;

        let fns = crate::analysis::pe::call_targets::find_pe_call_targets(&pe)?;
        assert_eq!(3610, fns.len());

        Ok(())
    }

    #[test]
    fn tiny() -> Result<()> {
        let buf = get_buf(Rsrc::TINY);
        let pe = crate::loader::pe::load_pe(&buf)?;

        // no optional header
        assert!(crate::analysis::pe::call_targets::find_pe_call_targets(&pe).is_err());

        Ok(())
    }

    #[test]
    fn nop() -> Result<()> {
        let buf = get_buf(Rsrc::NOP);
        let pe = crate::loader::pe::load_pe(&buf)?;

        let fns = crate::analysis::pe::call_targets::find_pe_call_targets(&pe)?;
        assert_eq!(250, fns.len());

        Ok(())
    }

    #[test]
    fn mimi() -> Result<()> {
        let buf = get_buf(Rsrc::MIMI);
        let pe = crate::loader::pe::load_pe(&buf)?;

        let fns = crate::analysis::pe::call_targets::find_pe_call_targets(&pe)?;
        assert_eq!(10907, fns.len());

        Ok(())
    }
}
