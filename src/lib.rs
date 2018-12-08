extern crate log;
extern crate simplelog;

use goblin::Object;
use log::{debug, error, info, trace, warn};
use rayon::prelude::*;
use std::env;
use std::fs;
use std::io::prelude::*;
use zydis;

// enabled only during testing.
// supports reaching into the resources dir for test data.
// TODO: doesn't work nicely work vscode-rls (which doesn't pass along the features=test)
// #[cfg(feature = "test")]
pub mod rsrc;

pub struct Config {
    pub filename: String,
}

impl Config {
    pub fn from_args(args: env::Args) -> Result<Config, &'static str> {
        let args: Vec<String> = args.collect();

        if args.len() < 2 {
            return Err("not enough arguments");
        }

        let filename = args[1].clone();
        trace!("config: parsed filename: {:?}", filename);

        Ok(Config { filename })
    }
}

pub fn setup_logging(_args: &Config) {
    simplelog::TermLogger::init(simplelog::LevelFilter::Info, simplelog::Config::default())
        .expect("failed to setup logging");
}

#[derive(Debug)]
pub enum Error {
    FileAccess,
    FileFormat,
    NotImplemented(&'static str),
    InvalidRva,
}

/// Static cast the given 64-bit unsigned integer to a 64-bit signed integer.
/// This is probably only useful when some other code provides you a u64
///  that is meant to be an i64 (aka. uncommon).
/// 
/// In C: `*(int64_t *)&i`
/// 
/// # Examples
/// 
/// ```
/// use lancelot::*;
/// assert_eq!(0, u64_i64(0));
/// assert_eq!(1, u64_i64(0x1));
/// assert_eq!(-1, u64_i64(0xFFFF_FFFF_FFFF_FFFF));
/// ```
pub fn u64_i64(i: u64) -> i64 {
    if i & 1 << 63 > 0 {
        // TODO: there's probably some elegant rust-way to do this.
        // in the meantime, manually compute twos-complement.
        let bits = i & 0x7FFF_FFFF_FFFF_FFFF;
        let bits = !bits;
        let bits = bits + 1;
        let bits = bits & 0x7FFF_FFFF_FFFF_FFFF;
        -(bits as i64)
    } else {
        i as i64
    }
}

/// Round the given value up to the next multiple of the given base.
///
/// # Panics
///
///   - Base `b` must be at least `2`.
///
/// # Examples
///
/// ```
/// use lancelot::*;
/// assert_eq!(align(0, 2), 0);
/// assert_eq!(align(1, 2), 2);
/// assert_eq!(align(2, 2), 2);
/// assert_eq!(align(3, 2), 4);
/// assert_eq!(align(4, 2), 4);
/// ```
pub fn align(i: usize, b: usize) -> usize {
    if b < 2 {
        panic!("base `b` must be at least: 2");
    }
    let rem = i % b;
    if rem == 0 {
        i
    } else {
        i + (b - rem)
    }
}

pub fn hexdump_ascii(b: u8) -> char {
    if b.is_ascii_graphic() || b == b' ' {
        b as char
    } else {
        '.'
    }
}

pub fn hexdump(buf: &[u8], offset: usize) -> String {
    // 01234567:  00 01 02 03 04 05 06 07  ...............
    // <prefix>   <hex col>                <ascii col>

    let padding = "  ";

    let padding_size = 2;
    let hex_col_size = 3;
    let ascii_col_size = 1;
    let prefix_size = 8 + 1;
    let newline_size = 1;
    let line_size = prefix_size
        + padding_size
        + 16 * hex_col_size
        + padding_size
        + 16 * ascii_col_size
        + newline_size;
    let line_count = align(buf.len(), 0x10) / 0x10;

    let mut ret = String::with_capacity(line_count * line_size);

    let mut line = String::with_capacity(line_size);
    let mut remaining_count = buf.len();
    for line_index in 0..line_count {
        let line_elem_count = 0x10.min(remaining_count);
        let padding_elem_count = 0x10 - line_elem_count;

        // 01234567:  00 01 02 03 04 05 06 07  ...............
        // ^^^^^^^^^
        line.push_str(format!("{:08x}:", offset + 0x10 * line_index).as_str());

        // 01234567:  00 01 02 03 04 05 06 07  ...............
        //          ^^
        line.push_str(padding);

        // 01234567:  00 01 02 03 04 05 06 07  ...............
        //            ^^^
        for elem in &buf[line_index..line_index + line_elem_count] {
            line.push_str(format!("{:02x} ", elem).as_str());
        }
        for _ in 0..padding_elem_count {
            line.push_str("   ");
        }

        // 01234567:  00 01 02 03 04 05 06 07  ...............
        //                                   ^^
        line.push_str(padding);

        // 01234567:  00 01 02 03 04 05 06 07  ...............
        //                                     ^
        for elem in &buf[line_index..line_index + line_elem_count] {
            line.push(hexdump_ascii(*elem))
        }
        for _ in 0..padding_elem_count {
            line.push(' ');
        }
        line.push_str(padding);

        // 01234567:  00 01 02 03 04 05 06 07  ...............
        //                                                    ^
        line.push('\n');

        ret.push_str(line.as_str());
        line.truncate(0x0);
        remaining_count -= line_elem_count;
    }

    ret
}

pub fn read_file(filename: &str) -> Result<Vec<u8>, Error> {
    debug!("read_file: {:?}", filename);

    let mut buf = Vec::new();
    {
        debug!("reading file: {}", filename);
        let mut f = match fs::File::open(filename) {
            Ok(f) => f,
            Err(_) => {
                error!("failed to open file: {}", filename);
                return Err(Error::FileAccess);
            }
        };
        let bytes_read = match f.read_to_end(&mut buf) {
            Ok(c) => c,
            Err(_) => {
                error!("failed to read entire file: {}", filename);
                return Err(Error::FileAccess);
            }
        };
        debug!("read {} bytes", bytes_read);
        if bytes_read < 0x10 {
            error!("file too small: {}", filename);
            return Err(Error::FileFormat);
        }
    }

    Ok(buf)
}

type Rva = u64;

#[derive(Debug)]
enum Xref {
    // mov eax, eax
    // push ebp
    Fallthrough { src: Rva, dst: Rva },
    // call [0x401000]
    Call { src: Rva, dst: Rva },
    // call [eax]
    //IndirectCall { src: Rva },
    // jmp 0x401000
    UnconditionalJump { src: Rva, dst: Rva },
    // jmp eax
    //UnconditionalIndirectJump { src: Rva, dst: Rva },
    // jnz 0x401000
    ConditionalJump { src: Rva, dst: Rva },
    // jnz eax
    //ConditionalIndirectJump { src: Rva },
    // cmov 0x1
    ConditionalMove { src: Rva, dst: Rva },
}

pub struct Xrefs {
    from: Vec<Xref>,
    to: Vec<Xref>,
}

pub enum Instruction {
    Invalid,
    Valid {
        insn: zydis::ffi::DecodedInstruction,
        xrefs: Xrefs,
    },
}

pub struct Section {
    pub name: String,
    pub addr: Rva,
    pub buf: Vec<u8>,
    pub insns: Vec<Instruction>,
}

impl Section {
    pub fn contains(self: &Section, rva: Rva) -> bool {
        if rva < self.addr {
            return false;
        }
        if rva >= self.addr + self.buf.len() as Rva {
            return false;
        }

        true
    }
}

pub struct Disassembler {
    pub decoder: zydis::ffi::Decoder,
    pub pc: zydis::enums::register::Register,
}

pub struct Workspace {
    pub filename: String,
    pub buf: Vec<u8>,
    pub sections: Vec<Section>,
    pub dis: Disassembler,
}

impl Workspace {
    /// Parse the given file into its object.
    ///
    /// # Errors
    ///   - `Error::FileFormat`: when not able to be parsed by Goblin.
    ///
    /// # Examples
    ///
    /// ```
    /// use goblin::Object;
    /// use matches::matches;
    /// use lancelot::rsrc::*;
    /// let ws = get_workspace(Rsrc::K32);
    /// assert!(matches!(ws.get_obj().unwrap(), Object::PE(_)));
    /// ```
    ///
    /// you might be tempted to maintain a method `get_pe`,
    /// however, i don't think this is a good idea:
    /// its fragile because the file type may not be PE.
    /// therefore, force clients to be explicit:
    ///
    /// ```
    /// use goblin::Object;
    /// use lancelot::rsrc::*;
    /// let ws = get_workspace(Rsrc::K32);
    /// if let Object::PE(_) = ws.get_obj().unwrap() {
    ///     // everyone is happy!
    /// }
    /// ```
    ///
    /// TODO: demonstrate `Error::FileFormat`.
    pub fn get_obj(&self) -> Result<Object, Error> {
        let obj = match Object::parse(&self.buf) {
            Ok(o) => o,
            Err(e) => {
                error!("failed to parse file: {} error: {:?}", self.filename, e);
                return Err(Error::FileFormat);
            }
        };

        match obj {
            Object::Unknown(_) => {
                error!(
                    "unknown file format, magic: | {:02X} {:02X} | '{}{}' ",
                    self.buf[0],
                    self.buf[1],
                    hexdump_ascii(self.buf[0]),
                    hexdump_ascii(self.buf[1])
                );

                Err(Error::FileFormat)
            }
            _ => Ok(obj),
        }
    }

    /// Fetch the section that contains the given address.
    ///
    /// # Examples
    ///
    /// ```
    /// use lancelot::*;
    /// use lancelot::rsrc::*;
    /// let ws = rsrc::get_workspace(rsrc::Rsrc::K32);
    /// assert_eq!(ws.get_section(0x130C0).expect("section").name, ".text");
    /// ```
    pub fn get_section(self: &Workspace, rva: Rva) -> Result<&Section, Error> {
        let sec = self.sections.iter().find(|sec| sec.contains(rva));
        match sec {
            None => Err(Error::InvalidRva),
            Some(sec) => Ok(sec),
        }
    }

    pub fn is_rva_valid(self: &Workspace, rva: Rva) -> bool {
        self.sections.iter().any(|sec| sec.contains(rva))
    }

    /// Fetch the instruction at the given RVA.
    ///
    /// # Result
    ///
    /// Err: if the RVA does not fall within a section.
    /// None: if there is not a valid instruction at the given RVA.
    /// _: valid instruction.
    ///
    /// # Examples
    ///
    /// ```
    /// use zydis::*;
    /// use lancelot::*;
    /// use lancelot::rsrc::*;
    /// use matches::matches;
    /// let ws = rsrc::get_workspace(rsrc::Rsrc::K32);
    /// let insn = ws.get_insn(0x130C0).unwrap().unwrap();
    /// assert!(matches!(insn.mnemonic, zydis::enums::mnemonic::Mnemonic::MOV));
    /// ```
    pub fn get_insn(
        self: &Workspace,
        rva: Rva,
    ) -> Result<&Instruction, Error> {
        let sec = self.get_section(rva)?;
        let insn = &(sec.insns[(rva - sec.addr) as usize]);
        Ok(insn)
    }

    fn analyze_operand_xrefs(
        self: &Workspace,
        rva: Rva,
        insn: &zydis::ffi::DecodedInstruction,
        op: &zydis::ffi::DecodedOperand,
    ) -> Result<Option<Rva>, Error> {
        match op.ty {
            zydis::enums::OperandType::Unused => Err(Error::NotImplemented("xref from unused register")),
            zydis::enums::OperandType::Register => {
                // like: CALL rbx
                // TODO: for now, don't index unresolved indirect branches
                Ok(None)
            }
            zydis::enums::OperandType::Memory => {
                // like: .text:0000000180001041 FF 15 D1 78 07 00      call    cs:__imp_RtlVirtualUnwind_0
                //           0x0000000000001041:                       call    [0x0000000000079980]
                if self.dis.pc == op.mem.base && op.mem.disp.has_displacement && op.mem.scale == 0 {
                    // RIP-relative
                    // this is the default encoding on x64.
                    // tools like IDA automatically compute and display the target.
                    // CALL [RIP + 0x401000]
                    if let zydis::enums::register::Register::NONE = op.mem.index {
                        let target =
                            (rva as i64 
                            // TODO: cast from rva (u64) to i64 is lossy.
                            + op.mem.disp.displacement 
                            + i64::from(insn.length)) as Rva;

                        if self.is_rva_valid(target) {
                            Ok(Some(target))
                        } else {
                            // TODO: record this anomaly somewhere.
                            warn!("problem: invalid xref target: memory not in sections");
                            Ok(None)
                        }
                    } else {
                        // unsupported
                        // like: CALL [RIP + 4*RCX + 0x401000] ??
                        println!("CALL [RIP + 4*RCX + 0x401000] ??");
                        Err(Error::NotImplemented("xref from RIP-relative, non-zero index memory"))
                    }
                } else if op.mem.base == zydis::enums::register::Register::NONE {
                    // like: CALL [0x401000] ??
                    println!("TODO: other OperandType::Memory branch");
                    Err(Error::NotImplemented("xref from non-RIP-relative memory"))
                } else {
                    // like: CALL [rbx]
                    // like: CALL [rbx + 0x10]
                    // TODO: for now, don't index unresolved indirect branches
                    Ok(None)
                }
            }
            zydis::enums::OperandType::Pointer => {
                println!("operand: pointer");
                Err(Error::NotImplemented("xref from pointer"))
            }
            zydis::enums::OperandType::Immediate => {
                if !op.imm.is_relative {
                    println!("TODO: absolute immediate operand");
                    Err(Error::NotImplemented("xref from absolute immediate"))
                } else {
                    let imm = if op.imm.is_signed {
                        u64_i64(op.imm.value)
                    } else {
                        op.imm.value as i64
                    };

                    // TODO: cast from rva (u64) to i64 is lossy.
                    let dst = (rva as i64 + imm + i64::from(insn.length)) as Rva;
                    if self.is_rva_valid(dst) {
                        Ok(Some(dst))
                    } else {
                        // TODO: record this anomaly somewhere.
                        warn!("problem: invalid xref target: relative immediate not in sections");
                        Ok(None)
                    }
                }
            }
        }
    }

    fn analyze_insn_xrefs(
        self: &Workspace,
        rva: Rva,
        insn: &zydis::ffi::DecodedInstruction,
    ) -> Result<Vec<Xref>, Error> {
        match insn.mnemonic {
            // see InstructionCategory
            // syscall, sysexit, sysret
            // vmcall, vmmcall
            zydis::enums::mnemonic::Mnemonic::CALL => {
                let op = insn
                    .operands
                    .iter()
                    .find(|op| op.visibility == zydis::enums::OperandVisibility::Explicit)
                    // a CALL always has an operand, so assume this is ok.
                    .unwrap();

                let fallthrough = Xref::Fallthrough {
                    src: rva,
                    dst: rva + u64::from(insn.length),
                };

                match self.analyze_operand_xrefs(rva, insn, op)? {
                    // TODO: fallthrough is not guaranteed if the function is noret
                    Some(dst) => Ok(vec![Xref::Call { src: rva, dst: dst }, fallthrough]),
                    None => Ok(vec![fallthrough]),
                }
            }
            zydis::enums::mnemonic::Mnemonic::RET
            | zydis::enums::mnemonic::Mnemonic::IRET
            | zydis::enums::mnemonic::Mnemonic::IRETD
            | zydis::enums::mnemonic::Mnemonic::IRETQ => Ok(vec![]),
            zydis::enums::mnemonic::Mnemonic::JMP => {
                let op = insn
                    .operands
                    .iter()
                    .find(|op| op.visibility == zydis::enums::OperandVisibility::Explicit)
                    // a J* always has an operand, so assume this is ok.
                    .unwrap();

                match self.analyze_operand_xrefs(rva, insn, op)? {
                    Some(dst) => Ok(vec![Xref::UnconditionalJump { src: rva, dst: dst }]),
                    None => Ok(vec![]),
                }
            }
            zydis::enums::mnemonic::Mnemonic::JB
            | zydis::enums::mnemonic::Mnemonic::JBE
            | zydis::enums::mnemonic::Mnemonic::JCXZ
            | zydis::enums::mnemonic::Mnemonic::JECXZ
            | zydis::enums::mnemonic::Mnemonic::JKNZD
            | zydis::enums::mnemonic::Mnemonic::JKZD
            | zydis::enums::mnemonic::Mnemonic::JL
            | zydis::enums::mnemonic::Mnemonic::JLE
            | zydis::enums::mnemonic::Mnemonic::JNB
            | zydis::enums::mnemonic::Mnemonic::JNBE
            | zydis::enums::mnemonic::Mnemonic::JNL
            | zydis::enums::mnemonic::Mnemonic::JNLE
            | zydis::enums::mnemonic::Mnemonic::JNO
            | zydis::enums::mnemonic::Mnemonic::JNP
            | zydis::enums::mnemonic::Mnemonic::JNS
            | zydis::enums::mnemonic::Mnemonic::JNZ
            | zydis::enums::mnemonic::Mnemonic::JO
            | zydis::enums::mnemonic::Mnemonic::JP
            | zydis::enums::mnemonic::Mnemonic::JRCXZ
            | zydis::enums::mnemonic::Mnemonic::JS
            | zydis::enums::mnemonic::Mnemonic::JZ => {
                let op = insn
                    .operands
                    .iter()
                    .find(|op| op.visibility == zydis::enums::OperandVisibility::Explicit)
                    // a J* always has an operand, so assume this is ok.
                    .unwrap();

                let fallthrough = Xref::Fallthrough {
                    src: rva,
                    dst: rva + u64::from(insn.length),
                };

                match self.analyze_operand_xrefs(rva, insn, op)? {
                    Some(dst) => Ok(vec![
                        Xref::ConditionalJump { src: rva, dst: dst },
                        fallthrough,
                    ]),
                    None => Ok(vec![fallthrough]),
                }
            }
            zydis::enums::mnemonic::Mnemonic::CMOVB
            | zydis::enums::mnemonic::Mnemonic::CMOVBE
            | zydis::enums::mnemonic::Mnemonic::CMOVL
            | zydis::enums::mnemonic::Mnemonic::CMOVLE
            | zydis::enums::mnemonic::Mnemonic::CMOVNB
            | zydis::enums::mnemonic::Mnemonic::CMOVNBE
            | zydis::enums::mnemonic::Mnemonic::CMOVNL
            | zydis::enums::mnemonic::Mnemonic::CMOVNLE
            | zydis::enums::mnemonic::Mnemonic::CMOVNO
            | zydis::enums::mnemonic::Mnemonic::CMOVNP
            | zydis::enums::mnemonic::Mnemonic::CMOVNS
            | zydis::enums::mnemonic::Mnemonic::CMOVNZ
            | zydis::enums::mnemonic::Mnemonic::CMOVO
            | zydis::enums::mnemonic::Mnemonic::CMOVP
            | zydis::enums::mnemonic::Mnemonic::CMOVS
            | zydis::enums::mnemonic::Mnemonic::CMOVZ => {
                Ok(vec![
                    Xref::Fallthrough {
                        src: rva,
                        dst: rva + u64::from(insn.length),
                    },
                    Xref::ConditionalMove {
                        src: rva,
                        dst: rva + u64::from(insn.length),
                    },
                ])
            }
            _ => Ok(vec![Xref::Fallthrough {
                src: rva,
                dst: rva + u64::from(insn.length),
            }]),
        }
    }

    fn analyze_xrefs(self: &Workspace) -> Result<(), Error> {

        let formatter = zydis::Formatter::new(zydis::FormatterStyle::Intel).expect("formatter");
        for section in self.sections.iter() {
            println!("section: {}", section.name);

            // TODO: optimization: store small number (2?) of xrefs on stack when appropriate.
            let xrefs_from: Vec<Vec<Xref>> = section.insns.iter().enumerate().map(|(offset, insn)| {
                let rva = section.addr + offset as Rva;
                match insn {
                    Instruction::Valid{insn, ..} => {
                        self.analyze_insn_xrefs(rva, insn).expect("analyze xrefs")
                    },
                    Instruction::Invalid => vec![]
                }
            }).collect();

            let xrefs_to: Vec<Vec<Xref>> = section.insns.iter().map(|_| vec![]).collect();

            for xrefs in xrefs_from {
                for xref in xrefs {
                    match xref {
                        Xref::Fallthrough{src, dst} => (),
                            // this is not guaranteed to be in the section...
                            //xrefs_to[dst as usize].append(xref.clone());
                        //},
                        Xref::Call{src, dst} => (),
                        Xref::UnconditionalJump{src, dst} => (),
                        Xref::ConditionalJump{src, dst} => (),
                        Xref::ConditionalMove{src, dst} => (),
                    }
                }
            };

            for (offset, insn) in section.insns.iter().enumerate() {
                let rva = section.addr + offset as Rva;
                match insn {
                    Instruction::Valid{insn, ..} => {
                        let mut buffer = [0u8; 200];
                        let mut buffer = zydis::OutputBuffer::new(&mut buffer[..]);

                        formatter
                            .format_instruction(insn, &mut buffer, Some(rva as u64), None)
                            .expect("format");
                        println!("0x{:016X}: {}", rva, buffer);

                        let xs = self.analyze_insn_xrefs(rva, insn)?;
                        for x in xs {
                            println!("  xref: {:?}", x);
                        }
                    }
                    Instruction::Invalid => {
                        println!("0x{:016X}: ...", rva);
                    }
                }
            }
        }
        Ok(())
    }

    fn load_disassembler(self: &mut Workspace) -> Result<(), Error> {
        match self.get_obj()? {
            Object::PE(pe) => {
                if !pe.is_64 {
                    self.dis = Disassembler {
                        decoder: zydis::Decoder::new(
                            zydis::MachineMode::LongCompat32,
                            zydis::AddressWidth::_32,
                        )
                        .unwrap(),
                        pc: zydis::enums::register::Register::EAX,
                    }
                }
                Ok(())
            }
            _ => Err(Error::NotImplemented("disassembler for non-PE module")),
        }
    }

    // this must be called *after* `load_disassembler`.
    fn load_sections(self: &mut Workspace) -> Result<(), Error> {
        match self.get_obj()? {
            Object::PE(pe) => {
                let buf = &self.buf;
                let decoder = &self.dis.decoder;

                // TODO: load PE header, too

                self.sections
                    .extend(pe.sections.iter().map(|section| -> Section {
                        // TODO: i'm sure this can be abused.
                        // TODO: add tests for weird section names.
                        let name = String::from_utf8_lossy(&section.name[..])
                            .into_owned()
                            .trim_end_matches("\u{0}")
                            .trim_end()
                            .to_string();

                        // TODO: figure out if we will work with usize, or u64, or what,
                        // then assert usize is ok.
                        // ref: `usize::max_value()`
                        let mut secbuf = vec![0; align(section.virtual_size as usize, 0x200)];

                        {
                            let secsize = section.size_of_raw_data as usize;
                            let rawbuf = &mut secbuf[..secsize];
                            let pstart = section.pointer_to_raw_data as usize;
                            rawbuf.copy_from_slice(&buf[pstart..pstart + secsize]);
                        }

                        let insns: Vec<Instruction> = secbuf
                            .par_windows(0x10)
                            .map(|ibuf| match decoder.decode(ibuf) {
                                Ok(Some(insn)) => Instruction::Valid {
                                    insn: insn,
                                    xrefs: Xrefs {
                                        to: vec![],
                                        from: vec![],
                                    },
                                },
                                _ => Instruction::Invalid,
                            })
                            .collect();

                        info!("loaded section: {}", name);
                        Section {
                            name: name,
                            addr: section.virtual_address as Rva,
                            buf: secbuf,
                            insns: insns,
                        }
                    }));

                Ok(())
            }
            Object::Elf(_) => Err(Error::NotImplemented("load sections for ELF module")),
            Object::Mach(_) => Err(Error::NotImplemented("load sections for MachO module")),
            Object::Archive(_) => Err(Error::NotImplemented("load sections for archive module")),
            Object::Unknown(_) => Err(Error::NotImplemented("load sections for unknown module")),
        }
    }

    /// Construct a workspace from the module with the given contents.
    ///
    /// # Errors
    ///   - `Error::FileFormat`: when not able to be parsed by Goblin.
    ///   - `Error::NotImplemented`: when not a PE file.
    ///
    /// # Examples
    ///
    /// ```
    /// use lancelot::*;
    /// use lancelot::rsrc::*;
    /// let buf = get_buf(Rsrc::K32);
    /// let ws = Workspace::from_buf("kernel32.dll", buf).unwrap();
    /// ```
    ///
    /// TODO: demonstrate ELF file behavior.
    /// TODO: demonstrate MachO file behavior.
    /// TODO: demonstrate unknown file behavior.
    pub fn from_buf(filename: &str, buf: Vec<u8>) -> Result<Workspace, Error> {
        let mut ws = Workspace {
            filename: filename.to_string(),
            buf: buf,
            sections: vec![],
            dis: Disassembler {
                // default disassembly settings.
                // will be updated subsequently if 32-bit.
                decoder: zydis::Decoder::new(zydis::MachineMode::Long64, zydis::AddressWidth::_64)
                    .unwrap(),
                pc: zydis::enums::register::Register::RIP,
            },
        };

        ws.load_disassembler()?;
        ws.load_sections()?;

        ws.analyze_xrefs()?;

        Ok(ws)
    }

    /// Construct a workspace from the module at given a file path.
    ///
    /// ```
    /// use lancelot::*;
    /// use lancelot::rsrc::*;
    /// let path = get_path(Rsrc::K32);
    /// // This test resource file is mangled. Needs to be fixed before parsing.
    /// // Otherwise, the following would work:
    /// // let ws = Workspace::from_file(&path).unwrap();
    /// ```
    pub fn from_file(filename: &str) -> Result<Workspace, Error> {
        let buf = read_file(filename)?;
        Workspace::from_buf(filename, buf)
    }
}

pub fn run(args: &Config) -> Result<(), Error> {
    debug!("filename: {:?}", args.filename);
    let ws = Workspace::from_file(&args.filename)?;

    if let Object::PE(pe) = ws.get_obj()? {
        let formatter = zydis::Formatter::new(zydis::FormatterStyle::Intel).expect("formatter");

        let mut buffer = [0u8; 200];
        let mut buffer = zydis::OutputBuffer::new(&mut buffer[..]);

        let oep: Rva = pe
            .header
            .optional_header
            .unwrap()
            .standard_fields
            .address_of_entry_point;

        match ws.get_insn(oep)? {
            Instruction::Valid{insn, ..} => {
                formatter
                    .format_instruction(&insn, &mut buffer, Some(oep as u64), None)
                    .expect("format");
                println!("0x{:016X}: {}", oep, buffer);
            },
            _ => {
                panic!("failed to fetch valid instruction at OEP");
            },
        };
    }

    Ok(())
}
