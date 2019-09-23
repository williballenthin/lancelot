// from: https://github.com/Maktm/FLIRTDB/blob/1f5763535e02d7cccf2f90a96a8ebaa36e9b2495/cmt/windows/libcmt_15_msvc_x86.pat#L354
//
//     6AFF5064A100000000508B44240C64892500000000896C240C8D6C240C50F2C3 00 0000 0020 :0000 __EH_prolog
//
// take that first column and treat it as a byte signature:
//
//     rule __EH_prolog : flirt
//     {
//         strings:
//             $bytes = {6AFF5064A100000000508B44240C64892500000000896C240C8D6C240C50F2C3}
//         condition:
//             $bytes
//     }
//
// and search for it:
//
//     $ yara src/analysis/pe/flirt/__EH_prolog.yara /mnt/c/Windows/SysWOW64/
//     __EH_prolog /mnt/c/Windows/SysWOW64//ucrtbase.dll
//     __EH_prolog /mnt/c/Windows/SysWOW64//ucrtbased.dll
//     __EH_prolog /mnt/c/Windows/SysWOW64//vcruntime140.dll
//     __EH_prolog /mnt/c/Windows/SysWOW64//vcruntime140_clr0400.dll
//     __EH_prolog /mnt/c/Windows/SysWOW64//vcruntime140d.dll
// ```
extern crate nom;

pub mod pat;

#[derive(Debug)]
enum SigElement {
    Byte(u8),
    Wildcard,
}

impl std::fmt::Display for SigElement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SigElement::Byte(v) => write!(f, "{:02x}", v),
            SigElement::Wildcard => write!(f, ".."),
        }
    }
}

#[derive(Debug)]
pub struct ByteSignature(Vec<SigElement>);

impl std::fmt::Display for ByteSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for elem in self.0.iter() {
            write!(f, "{}", elem)?;
        }
        Ok(())
    }
}

#[derive(Debug)]
enum Offset {
    Public(u16),
    Local(u16),
    Reference(u16),
}

#[derive(Debug)]
pub struct Name {
    offset: u16,
    name: String,
}

#[derive(Debug)]
enum Symbol {
    Public(Name),
    Local(Name),
    Reference(Name),
}

impl std::fmt::Display for Symbol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Symbol::Public(name) => write!(f, ":{:04x} {}", name.offset, name.name),
            Symbol::Local(name) => write!(f, ":{:04x}@ {}", name.offset, name.name),
            Symbol::Reference(name) => write!(f, "^{:04x} {}", name.offset, name.name),
        }
    }
}

pub struct FlirtSignature {
    byte_sig: ByteSignature,

    /// number of bytes passed to the CRC16 checksum
    size_of_bytes_crc16: u8,  // max: 0xFF
    crc16: u16,
    size_of_function: u16,  // max: 0x8000

    names: Vec<Symbol>,

    footer: Option<ByteSignature>,
}

impl std::fmt::Display for FlirtSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ", self.byte_sig)?;
        write!(f, "{:02x} ", self.size_of_bytes_crc16)?;
        write!(f, "{:04x} ", self.crc16)?;
        write!(f, "{:04x} ", self.size_of_function)?;
        for (i, name) in self.names.iter().enumerate() {
            write!(f, "{}", name)?;
            if i != self.names.len() - 1 {
                write!(f, " ")?;
            }
        }
        if let Some(footer) = &self.footer {
            write!(f, " ")?;
            write!(f, "{}", footer)?;
        }
        Ok(())
    }
}

impl std::fmt::Debug for FlirtSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}
