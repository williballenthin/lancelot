use anyhow::Result;
use log::debug;

use crate::loader::pe::PE;

pub fn get_disassembler(pe: &PE) -> Result<zydis::Decoder> {
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

pub fn linear_disassemble<'a>(
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
            // see discussion of linear vs thorough disassemble in this module doc for
            // call_targets. thorough is 4x more expensive, with limited
            // results.

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
