use zydis;

pub enum Instruction<'a> {
    Invalid {
        loc: &'a Location,
    },
    Valid {
        loc: &'a Location,
        insn: zydis::ffi::DecodedInstruction,
    },
}

impl<'a> Instruction<'a> {
    pub fn from<'b>(
        decoder: &zydis::ffi::Decoder,
        buf: &[u8],
        loc: &'b Location,
    ) -> Instruction<'b> {
        match decoder.decode(buf) {
            Ok(Some(insn)) => Instruction::Valid { loc, insn },
            _ => Instruction::Invalid { loc },
        }
    }
}

impl<'a> fmt::Display for Instruction<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let formatter = zydis::Formatter::new(zydis::FormatterStyle::Intel).expect("formatter");
        let mut buffer = [0u8; 200];
        let mut buffer = zydis::OutputBuffer::new(&mut buffer[..]);
        match &self {
            Instruction::Valid { insn, loc } => {
                formatter
                    .format_instruction(&insn, &mut buffer, Some(loc.addr), None)
                    .expect("format");
                write!(f, "0x{:016X}: {}", loc.addr, buffer)
            }
            Instruction::Invalid { loc } => write!(f, "0x{:016X}: invalid instruction", loc.addr),
        }
    }
}
