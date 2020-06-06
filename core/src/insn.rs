use zydis;

use crate::VA;

pub enum Instruction {
    Invalid {
        loc: VA,
    },
    Valid {
        loc: VA,
        insn: zydis::ffi::DecodedInstruction,
    },
}

impl Instruction {
    pub fn from(decoder: &zydis::ffi::Decoder, buf: &[u8], loc: VA) -> Instruction {
        match decoder.decode(buf) {
            Ok(Some(insn)) => Instruction::Valid { loc, insn },
            _ => Instruction::Invalid { loc },
        }
    }
}

impl std::fmt::Display for Instruction {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let formatter = zydis::Formatter::new(zydis::FormatterStyle::INTEL).expect("formatter");
        let mut buffer = [0u8; 200];
        let mut buffer = zydis::OutputBuffer::new(&mut buffer[..]);
        match &self {
            Instruction::Valid { insn, loc } => {
                formatter
                    .format_instruction(&insn, &mut buffer, Some(*loc), None)
                    .expect("format");
                write!(f, "0x{:016X}: {}", loc, buffer)
            }
            Instruction::Invalid { loc } => write!(f, "0x{:016X}: invalid instruction", loc),
        }
    }
}
