// from: https://github.com/Maktm/FLIRTDB/blob/1f5763535e02d7cccf2f90a96a8ebaa36e9b2495/cmt/windows/libcmt_15_msvc_x86.pat#L354
//
// ```
//     6AFF5064A100000000508B44240C64892500000000896C240C8D6C240C50F2C3 00 0000 0020 :0000 __EH_prolog
// ```
//
// take that first column and treat it as a byte signature:
//
// ```
//     rule __EH_prolog : flirt
//     {
//         strings:
//             $bytes = {6AFF5064A100000000508B44240C64892500000000896C240C8D6C240C50F2C3}
//         condition:
//             $bytes
//     }
// ```
//
// and search for it:
//
// ```
//     $ yara src/analysis/pe/flirt/__EH_prolog.yara /mnt/c/Windows/SysWOW64/
//     __EH_prolog /mnt/c/Windows/SysWOW64//ucrtbase.dll
//     __EH_prolog /mnt/c/Windows/SysWOW64//ucrtbased.dll
//     __EH_prolog /mnt/c/Windows/SysWOW64//vcruntime140.dll
//     __EH_prolog /mnt/c/Windows/SysWOW64//vcruntime140_clr0400.dll
//     __EH_prolog /mnt/c/Windows/SysWOW64//vcruntime140d.dll
// ```

extern crate anyhow;
extern crate nom;
extern crate thiserror;
#[macro_use]
extern crate bitflags;
use log::trace;
use regex::bytes::Regex;
use std::collections::HashMap;

pub mod pat;
pub mod pattern_set;
pub mod sig;

#[derive(Debug, Clone, Copy)]
pub enum SigElement {
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

#[derive(Debug, Clone)]
pub struct ByteSignature(pub Vec<SigElement>);

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

#[derive(Debug, Clone)]
pub struct Name {
    pub offset: i64,
    pub name:   String,
}

#[derive(Debug, Clone)]
pub enum Symbol {
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

#[derive(Debug, Clone)]
struct TailByte {
    offset: u64,
    value:  u8,
}

impl std::fmt::Display for TailByte {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "({:04X}: {:02X})", self.offset, self.value)
    }
}

#[derive(Clone)]
pub struct FlirtSignature {
    pub byte_sig: ByteSignature,

    /// number of bytes passed to the CRC16 checksum
    pub size_of_bytes_crc16: u8, // max: 0xFF
    crc16:                   u16,
    pub size_of_function:    u64, // max: 0x8000

    pub names: Vec<Symbol>,

    // the .pat file format uses a ByteSignature-style to specify a footer mask
    // which starts "at the end of the crc16 block."
    // not sure how these are translated into tail bytes.
    footer: Option<ByteSignature>,

    // the .sig file format tracks (offset, byte value) pairs that differentiate
    // signatures with the same pattern/crc16/references.
    // not sure how these are translated into the footer.
    tail_bytes: Vec<TailByte>,
}

impl std::fmt::Display for FlirtSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ", self.byte_sig)?;
        write!(f, "{:02x} ", self.size_of_bytes_crc16)?;
        write!(f, "{:04x} ", self.crc16)?;
        write!(f, "{:04x} ", self.size_of_function)?;

        if let Some(name) = self.get_name() {
            write!(f, "{}", name)?;
        }

        for tail_byte in self.tail_bytes.iter() {
            write!(f, " {}", tail_byte)?;
        }

        Ok(())
    }
}

impl std::fmt::Debug for FlirtSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)?;

        // emit local names
        for (i, name) in self.names.iter().enumerate() {
            write!(f, "{}", name)?;
            if i != self.names.len() - 1 {
                write!(f, " ")?;
            }
        }

        // emit trailing byte patterns
        if let Some(footer) = &self.footer {
            write!(f, " ")?;
            write!(f, "{}", footer)?;
        }

        Ok(())
    }
}

impl FlirtSignature {
    pub fn create_matcher(&self) -> FlirtSignatureMatcher {
        FlirtSignatureMatcher::new(self)
    }

    pub fn get_name(&self) -> Option<&str> {
        for name in self.names.iter() {
            if let Symbol::Public(name) = name {
                if name.offset == 0x0 {
                    return Some(&name.name);
                }
            }
        }

        None
    }

    /// compute the IDA-specific CRC16 checksum for the given bytes.
    ///
    /// This is ported from flair tools flair/crc16.cpp
    fn crc16(buf: &[u8]) -> u16 {
        const POLY: u32 = 0x8408;

        if buf.is_empty() {
            return 0;
        }

        let mut crc: u32 = 0xFFFF;
        for &b in buf {
            let mut b = b as u32;

            for _ in 0..8 {
                if ((crc ^ b) & 1) > 0 {
                    crc = (crc >> 1) ^ POLY;
                } else {
                    crc >>= 1;
                }
                b >>= 1;
            }
        }

        crc = !crc; // bitwise invert

        // swap u16 byte order
        let h1: u16 = (crc & 0xFF) as u16;
        let h2: u16 = ((crc >> 8) & 0xFF) as u16;

        (h1 << 8) | h2
    }

    pub fn match_crc16(&self, buf: &[u8]) -> bool {
        if self.size_of_bytes_crc16 > 0 {
            let byte_sig_size = self.byte_sig.0.len();
            let start = byte_sig_size;
            let end = byte_sig_size + (self.size_of_bytes_crc16 as usize);
            if end > buf.len() {
                trace!("flirt signature: buffer not large enough");
                return false;
            }

            let crc16 = FlirtSignature::crc16(&buf[start..end]);

            if crc16 != self.crc16 {
                trace!("flirt signature: crc16 fails");
                return false;
            }
        }

        true
    }

    /// return true if all tail bytes match (if there are any).
    pub fn match_tail_bytes(&self, buf: &[u8]) -> bool {
        !self
            .tail_bytes
            .iter()
            .map(|tail_byte| match buf.get(tail_byte.offset as usize) {
                None => false,
                Some(&v) => v == tail_byte.value,
            })
            .any(|b| !b)
    }
}

pub struct FlirtSignatureMatcher<'a> {
    re:  Regex,
    sig: &'a FlirtSignature,
}

/// create a binary regular expression pattern for matching the given FLIRT byte
/// signature. using this pattern still requires creating a Regex object with
/// the appropriate options.
fn create_pattern(sig: &FlirtSignature) -> String {
    // the function may be shorter than the 0x20 byte pattern,
    // if so, only generate a pattern long enough to match the function.
    let elements = if sig.size_of_function < 32 {
        &sig.byte_sig.0[..sig.size_of_function as usize]
    } else {
        &sig.byte_sig.0
    };

    elements
        .iter()
        .map(|b| match b {
            // lots of allocations here.
            // could create a static translation table to the &str formats.
            SigElement::Byte(v) => format!("\\x{:02x}", v),
            SigElement::Wildcard => ".".to_string(),
        })
        .collect::<Vec<String>>()
        .join("")
}

impl<'a> FlirtSignatureMatcher<'a> {
    pub fn new(sig: &'a FlirtSignature) -> FlirtSignatureMatcher {
        FlirtSignatureMatcher {
            re: FlirtSignatureMatcher::create_match_re(sig),
            sig,
        }
    }

    /// translate the given FLIRT byte signature into a binary regex.
    ///
    /// it matches from the start of the input string, so its best for the
    /// `is_match` operation.
    fn create_match_re(sig: &'a FlirtSignature) -> Regex {
        // the `(?-u)` disables unicode mode, which lets us match raw byte values.
        let pattern = format!("(?-u)(^{})", create_pattern(sig));

        Regex::new(&pattern).expect("failed to compile regex")
    }

    /// ```
    /// use lancelot_flirt;
    /// use lancelot_flirt::pat;
    ///
    /// let pat_buf = "\
    /// 518B4C240C895C240C8D5C240C508D442408F7D923C18D60F88B43F08904248B 21 B4FE 006E :0000 __EH_prolog3_GS_align ^0041 ___security_cookie ........33C5508941FC8B4DF0895DF08B4304894504FF75F464A1000000008945F48D45F464A300000000F2C3
    /// 518B4C240C895C240C8D5C240C508D442408F7D923C18D60F88B43F08904248B 1F E4CF 0063 :0000 __EH_prolog3_align ^003F ___security_cookie ........33C5508B4304894504FF75F464A1000000008945F48D45F464A300000000F2C3
    /// 518B4C240C895C240C8D5C240C508D442408F7D923C18D60F88B43F08904248B 22 E4CE 006F :0000 __EH_prolog3_catch_GS_align ^0042 ___security_cookie ........33C5508941FC8B4DF08965F08B4304894504FF75F464A1000000008945F48D45F464A300000000F2C3
    /// 518B4C240C895C240C8D5C240C508D442408F7D923C18D60F88B43F08904248B 20 6562 0067 :0000 __EH_prolog3_catch_align ^0040 ___security_cookie ........33C5508965F08B4304894504FF75F464A1000000008945F48D45F464A300000000F2C3
    /// ---";
    ///
    /// let sigs = pat::parse(pat_buf).unwrap();
    /// #[allow(non_snake_case)]
    /// let __EH_prolog3_catch_align = &sigs[3];
    /// let m = __EH_prolog3_catch_align.create_matcher();
    /// assert!(m.r#match(&[
    ///     // apds.dll / 4FD932C41DF96D019DC265E26E94B81B
    ///     // __EH_prolog3_catch_align
    ///
    ///     // first 0x20
    ///     0x51, 0x8B, 0x4C, 0x24, 0x0C, 0x89, 0x5C, 0x24,
    ///     0x0C, 0x8D, 0x5C, 0x24, 0x0C, 0x50, 0x8D, 0x44,
    ///     0x24, 0x08, 0xF7, 0xD9, 0x23, 0xC1, 0x8D, 0x60,
    ///     0xF8, 0x8B, 0x43, 0xF0, 0x89, 0x04, 0x24, 0x8B,
    ///     // crc16 start
    ///     0x43, 0xF8, 0x50, 0x8B, 0x43, 0xFC, 0x8B, 0x4B,
    ///     0xF4, 0x89, 0x6C, 0x24, 0x0C, 0x8D, 0x6C, 0x24,
    ///     0x0C, 0xC7, 0x44, 0x24, 0x08, 0xFF, 0xFF, 0xFF,
    ///     0xFF, 0x51, 0x53, 0x2B, 0xE0, 0x56, 0x57, 0xA1,
    ///     // crc end
    ///     0xD4, 0xAD, 0x19, 0x01, 0x33, 0xC5, 0x50, 0x89,
    ///     0x65, 0xF0, 0x8B, 0x43, 0x04, 0x89, 0x45, 0x04,
    ///     0xFF, 0x75, 0xF4, 0x64, 0xA1, 0x00, 0x00, 0x00,
    ///     0x00, 0x89, 0x45, 0xF4, 0x8D, 0x45, 0xF4, 0x64,
    ///     0xA3, 0x00, 0x00, 0x00, 0x00, 0xC3]));
    /// ```
    pub fn r#match(&self, buf: &[u8]) -> bool {
        if !self.re.is_match(buf) {
            trace!("flirt signature: pattern fails");
            return false;
        }

        if !self.sig.match_crc16(buf) {
            trace!("flirt signature: crc16 fails");
            return false;
        }

        trace!("flirt signature: match");
        true
    }
}

pub struct FlirtSignatureSet {
    sigs:    HashMap<pattern_set::Pattern, FlirtSignature>,
    matcher: pattern_set::PatternSet,
}

impl std::convert::From<&FlirtSignature> for pattern_set::Pattern {
    fn from(sig: &FlirtSignature) -> pattern_set::Pattern {
        pattern_set::Pattern(
            sig.byte_sig
                .0
                .iter()
                .map(|s| match s {
                    SigElement::Wildcard => pattern_set::WILDCARD,
                    SigElement::Byte(v) => pattern_set::Symbol(*v as u16),
                })
                .collect(),
        )
    }
}

impl FlirtSignatureSet {
    pub fn with_signatures(sigs: Vec<FlirtSignature>) -> FlirtSignatureSet {
        let sigs: HashMap<pattern_set::Pattern, FlirtSignature> =
            sigs.into_iter().map(|sig| ((&sig).into(), sig)).collect();

        let patterns = sigs.keys().cloned().collect();

        FlirtSignatureSet {
            sigs,
            matcher: pattern_set::PatternSet::from_patterns(patterns),
        }
    }

    /// ```
    /// use lancelot_flirt;
    /// use lancelot_flirt::pat;
    ///
    /// let pat_buf = "\
    /// 518B4C240C895C240C8D5C240C508D442408F7D923C18D60F88B43F08904248B 21 B4FE 006E :0000 __EH_prolog3_GS_align ^0041 ___security_cookie ........33C5508941FC8B4DF0895DF08B4304894504FF75F464A1000000008945F48D45F464A300000000F2C3
    /// 518B4C240C895C240C8D5C240C508D442408F7D923C18D60F88B43F08904248B 1F E4CF 0063 :0000 __EH_prolog3_align ^003F ___security_cookie ........33C5508B4304894504FF75F464A1000000008945F48D45F464A300000000F2C3
    /// 518B4C240C895C240C8D5C240C508D442408F7D923C18D60F88B43F08904248B 22 E4CE 006F :0000 __EH_prolog3_catch_GS_align ^0042 ___security_cookie ........33C5508941FC8B4DF08965F08B4304894504FF75F464A1000000008945F48D45F464A300000000F2C3
    /// 518B4C240C895C240C8D5C240C508D442408F7D923C18D60F88B43F08904248B 20 6562 0067 :0000 __EH_prolog3_catch_align ^0040 ___security_cookie ........33C5508965F08B4304894504FF75F464A1000000008945F48D45F464A300000000F2C3
    /// ---";
    ///
    /// let sigs = lancelot_flirt::FlirtSignatureSet::with_signatures(pat::parse(pat_buf).unwrap());
    /// let matches = sigs.r#match(&[
    ///     // apds.dll / 4FD932C41DF96D019DC265E26E94B81B
    ///     // __EH_prolog3_catch_align
    ///
    ///     // first 0x20
    ///     0x51, 0x8B, 0x4C, 0x24, 0x0C, 0x89, 0x5C, 0x24,
    ///     0x0C, 0x8D, 0x5C, 0x24, 0x0C, 0x50, 0x8D, 0x44,
    ///     0x24, 0x08, 0xF7, 0xD9, 0x23, 0xC1, 0x8D, 0x60,
    ///     0xF8, 0x8B, 0x43, 0xF0, 0x89, 0x04, 0x24, 0x8B,
    ///     // crc16 start
    ///     0x43, 0xF8, 0x50, 0x8B, 0x43, 0xFC, 0x8B, 0x4B,
    ///     0xF4, 0x89, 0x6C, 0x24, 0x0C, 0x8D, 0x6C, 0x24,
    ///     0x0C, 0xC7, 0x44, 0x24, 0x08, 0xFF, 0xFF, 0xFF,
    ///     0xFF, 0x51, 0x53, 0x2B, 0xE0, 0x56, 0x57, 0xA1,
    ///     // crc end
    ///     0xD4, 0xAD, 0x19, 0x01, 0x33, 0xC5, 0x50, 0x89,
    ///     0x65, 0xF0, 0x8B, 0x43, 0x04, 0x89, 0x45, 0x04,
    ///     0xFF, 0x75, 0xF4, 0x64, 0xA1, 0x00, 0x00, 0x00,
    ///     0x00, 0x89, 0x45, 0xF4, 0x8D, 0x45, 0xF4, 0x64,
    ///     0xA3, 0x00, 0x00, 0x00, 0x00, 0xC3]);
    ///
    /// assert_eq!(matches.len(), 1);
    /// assert_eq!(matches[0].get_name().unwrap(), "__EH_prolog3_catch_align");
    /// ```
    pub fn r#match(&self, buf: &[u8]) -> Vec<&FlirtSignature> {
        self.matcher
            .r#match(buf)
            .iter()
            .map(|&pattern| self.sigs.get(pattern).unwrap())
            .filter(|&sig| sig.match_crc16(buf))
            .filter(|&sig| sig.match_tail_bytes(buf))
            .collect()
    }
}
