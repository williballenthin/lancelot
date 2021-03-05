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

pub mod decision_tree;
pub mod pat;
pub mod pattern_set;
pub mod sig;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
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
    Public(u64),
    Local(u64),
    Reference(u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Name {
    pub offset: i64,
    pub name:   String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// a sequence of potentially wildcarded bytes that must match at the start
    /// of the input buffer. by default, the signature size is up to
    /// 32-bytes. relocations/fixups get masked by the wildcards.
    ///
    /// example (human readable):
    ///
    /// ```text
    /// 48895c2408574883ec20488bd9488d3d........488bcfe8........85c07422
    /// ```
    pub byte_sig: ByteSignature,

    /// after byte signature matching the start of the function,
    /// flirt checks the CRC16 checksum of subsequent data.
    /// usually this is up to the next relocation/fixup.
    ///
    /// example
    ///
    /// ```text
    ///  06 2828
    /// ```
    ///
    /// means: the CRC16 of the six bytes following the byte signature match
    /// must be 0x2828.

    /// number of bytes passed to the CRC16 checksum
    pub size_of_bytes_crc16: u8, // max: 0xFF
    pub crc16:               u16,

    /// then size of function.
    ///
    /// TODO: i'm not sure if this is used for matching.
    /// it would require a disassembly of the bytes and reconstruction of the
    /// control flow.
    pub size_of_function: u64, // max: 0x8000

    /// next is a sequence of (offset, type, name) tuples.
    /// the offset is relative from the start of the function/signature match.
    /// the type is one of:
    ///   - public
    ///   - local
    ///   - reference
    ///
    /// public and local names are the names applied to locations once the
    /// signature completely matched. they're the whole point of doing FLIRT
    /// signature matching.
    ///
    /// reference names are used to differentiate otherwise identical code.
    /// think of wrapper functions with trivial instructions that jump to a well
    /// known API. the reference is a relocation/fixup that points to some
    /// other code or data. if that thing has the given name, then the
    /// signature can match.
    ///
    /// TODO: im not exactly sure if FLIRT relies on these names being provided
    /// by some other technology (providing the names manually works in IDA)
    /// or if the matching is recursive ("go FLIRT match over there, then
    /// come back when you have results").
    ///
    /// TODO: im not sure how the reference is expected to be formatted.
    /// is it always a relocation? is it ever an offset embedded within an
    /// instruction? some results: its not strictly a relocation.
    /// in 34a05606d7c41a5856f4a9a64316c6ca at 0x1400152E1 is a reference to
    /// 0x140034D00 that is `_vmldSinHATab`. its encoded as: `1400152E1 F2
    /// 0F 10 05 17 FA 01 00 movsd   xmm0, cs:qword_140034D00` instruction
    /// is at relative offset 0x41, while rule specifies reference is at 0x45:
    /// `17 FA 01 00` there is not a relocation here, confirmed via CFF and
    /// IDA Instruction Details. so need to disassemble to find the
    /// instruction xref? or maybe guess at the address encoding.
    /// i wonder if its best left to the caller to validate these references?
    ///
    /// pat files seem to have many more names, especially references, than
    /// actually make it into sig files. i presume that sigmake reduces the
    /// necessary reference names down to whats actually needed to differentiate
    /// signatures.
    ///
    /// example:
    ///
    /// ```text
    /// :0000 __sse2_tanh2 :021d@ _2TAG_PACKET_1_0_1
    /// ```
    /// means:
    ///  - relative offset 0x0 is public name `__sse2_tanh2`
    ///  - relative offset 0x21D is local (@) name `_2TAG_PACKET_1_0_1`
    ///
    /// example:
    ///
    /// ```text
    /// :0000 __common_dsin_cout_rare ^0045 _vmldSinHATab
    /// ```
    ///
    /// means:
    ///  - relative offset 0x0 is public name `__common_dsin_cout_rare`
    ///  - relative offset 0x45 should be a reference (^) to symbol
    ///    `_vmldSinHATab`
    pub names: Vec<Symbol>,

    /// the .pat file format uses a ByteSignature-style to specify a footer mask
    /// which starts "at the end of the crc16 block."
    ///
    /// however, the entire footer doesn't show up in sig files.
    /// so, i presume that sigmake reduces the byte signature down to the
    /// minimal set of tail bytes.
    ///
    /// if we aim to support parsing both sig and pat files into a single
    /// signature format, we'll need to be able to match using either of
    /// these mechanisms.
    ///
    /// example:
    ///
    /// ```text
    ///  ........904883C4305DC3CC
    /// ```
    footer: Option<ByteSignature>,

    /// the .sig file format tracks (offset, byte value) pairs that
    /// differentiate signatures with the same pattern/crc16/references.
    ///
    /// example:
    ///
    /// ```text
    ///  (0050: 15)
    /// ```
    ///
    /// means: at relative offset 0x50 should be byte 0x15.
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

    /// return true if all the footer bytes match (if there are any).
    pub fn match_footer(&self, buf: &[u8]) -> bool {
        let footer_offset = self.byte_sig.0.len() + self.size_of_bytes_crc16 as usize;
        if let Some(sig) = &self.footer {
            sig.0
                .iter()
                .enumerate()
                .map(|(i, symbol)| (footer_offset + i, symbol))
                .map(|(offset, symbol)| match symbol {
                    // there are potentially a bunch of index operations here,
                    // but we don't expect this method to be called too often,
                    // since its the last step of matching.
                    SigElement::Byte(wanted) => match buf.get(offset) {
                        None => false,
                        Some(&found) => found == *wanted,
                    },
                    SigElement::Wildcard => true,
                })
                .find(|b| !b)
                .is_none()
        } else {
            true
        }
    }

    pub fn render_pat(&self) -> String {
        use std::io::prelude::*;
        let mut f: Vec<u8> = vec![];

        // no reason these writes should fail, except allocation failure.
        // which we're not going to handle.
        write!(f, "{}", self.byte_sig).unwrap();
        write!(f, " {:02x}", self.size_of_bytes_crc16).unwrap();
        write!(f, " {:04x}", self.crc16).unwrap();
        write!(f, " {:04x}", self.size_of_function).unwrap();

        for name in self.names.iter() {
            write!(f, " {}", name).unwrap();
        }

        for tail_byte in self.tail_bytes.iter() {
            write!(f, " ({:04X}: {:02X})", tail_byte.offset, tail_byte.value).unwrap();
        }

        if let Some(footer) = &self.footer {
            write!(f, " {}", footer).unwrap();
        }

        // we're writing utf8 above, so no reason for this to fail.
        String::from_utf8(f).unwrap()
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
    sigs_by_pattern: HashMap<pattern_set::Pattern, Vec<FlirtSignature>>,
    matcher:         pattern_set::PatternSet,
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
        let mut sigs_by_pattern: HashMap<pattern_set::Pattern, Vec<FlirtSignature>> = Default::default();

        for sig in sigs.into_iter() {
            sigs_by_pattern
                .entry(pattern_set::Pattern::from(&sig))
                .or_default()
                .push(sig);
        }

        let patterns = sigs_by_pattern.keys().cloned().collect();

        FlirtSignatureSet {
            sigs_by_pattern,
            matcher: pattern_set::PatternSet::from_patterns(patterns),
        }
    }

    pub fn r#match(&self, buf: &[u8]) -> Vec<&FlirtSignature> {
        self.matcher
            .r#match(buf)
            .iter()
            .flat_map(|&pattern| self.sigs_by_pattern.get(pattern).unwrap())
            .filter(|&sig| sig.match_crc16(buf))
            .filter(|&sig| sig.match_tail_bytes(buf))
            .filter(|&sig| sig.match_footer(buf))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{pat, sig, *};

    const PAT: &'static str = "\
518B4C240C895C240C8D5C240C508D442408F7D923C18D60F88B43F08904248B 21 B4FE 006E :0000 __EH_prolog3_GS_align ^0041 ___security_cookie ........33C5508941FC8B4DF0895DF08B4304894504FF75F464A1000000008945F48D45F464A300000000F2C3
518B4C240C895C240C8D5C240C508D442408F7D923C18D60F88B43F08904248B 1F E4CF 0063 :0000 __EH_prolog3_align ^003F ___security_cookie ........33C5508B4304894504FF75F464A1000000008945F48D45F464A300000000F2C3
518B4C240C895C240C8D5C240C508D442408F7D923C18D60F88B43F08904248B 22 E4CE 006F :0000 __EH_prolog3_catch_GS_align ^0042 ___security_cookie ........33C5508941FC8B4DF08965F08B4304894504FF75F464A1000000008945F48D45F464A300000000F2C3
518B4C240C895C240C8D5C240C508D442408F7D923C18D60F88B43F08904248B 20 6562 0067 :0000 __EH_prolog3_catch_align ^0040 ___security_cookie ........33C5508965F08B4304894504FF75F464A1000000008945F48D45F464A300000000F2C3
---";

    // sigmake __EH_prolog3.pat __EH_prolog3.sig
    const SIG: [u8; 217] = [
        0x49, 0x44, 0x41, 0x53, 0x47, 0x4e, 0x0a, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x55, 0x6e, 0x6e, 0x61, 0x6d, 0x65, 0x64, 0x20, 0x73,
        0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x6c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x01, 0x20, 0x00, 0x51, 0x8b,
        0x4c, 0x24, 0x0c, 0x89, 0x5c, 0x24, 0x0c, 0x8d, 0x5c, 0x24, 0x0c, 0x50, 0x8d, 0x44, 0x24, 0x08, 0xf7, 0xd9,
        0x23, 0xc1, 0x8d, 0x60, 0xf8, 0x8b, 0x43, 0xf0, 0x89, 0x04, 0x24, 0x8b, 0x00, 0x22, 0xe4, 0xce, 0x6f, 0x00,
        0x5f, 0x5f, 0x45, 0x48, 0x5f, 0x70, 0x72, 0x6f, 0x6c, 0x6f, 0x67, 0x33, 0x5f, 0x63, 0x61, 0x74, 0x63, 0x68,
        0x5f, 0x47, 0x53, 0x5f, 0x61, 0x6c, 0x69, 0x67, 0x6e, 0x10, 0x21, 0xb4, 0xfe, 0x6e, 0x00, 0x5f, 0x5f, 0x45,
        0x48, 0x5f, 0x70, 0x72, 0x6f, 0x6c, 0x6f, 0x67, 0x33, 0x5f, 0x47, 0x53, 0x5f, 0x61, 0x6c, 0x69, 0x67, 0x6e,
        0x10, 0x20, 0x65, 0x62, 0x67, 0x00, 0x5f, 0x5f, 0x45, 0x48, 0x5f, 0x70, 0x72, 0x6f, 0x6c, 0x6f, 0x67, 0x33,
        0x5f, 0x63, 0x61, 0x74, 0x63, 0x68, 0x5f, 0x61, 0x6c, 0x69, 0x67, 0x6e, 0x10, 0x1f, 0xe4, 0xcf, 0x63, 0x00,
        0x5f, 0x5f, 0x45, 0x48, 0x5f, 0x70, 0x72, 0x6f, 0x6c, 0x6f, 0x67, 0x33, 0x5f, 0x61, 0x6c, 0x69, 0x67, 0x6e,
        0x00,
    ];

    const BUF: [u8; 103] = [
        // utcutil.dll
        //  MD5 abc9ea116498feb8f1de45f60d595af6
        //  SHA-1 2f1ba350237b74c454caf816b7410490f5994c59
        //  SHA-256 7607897638e9dae406f0840dbae68e879c3bb2f08da350c6734e4e2ef8d61ac2
        // __EH_prolog3_catch_align

        // first 0x20
        0x51, 0x8b, 0x4c, 0x24, 0x0c, 0x89, 0x5c, 0x24, 0x0c, 0x8d, 0x5c, 0x24, 0x0c, 0x50, 0x8d, 0x44, 0x24, 0x08,
        0xf7, 0xd9, 0x23, 0xc1, 0x8d, 0x60, 0xf8, 0x8b, 0x43, 0xf0, 0x89, 0x04, 0x24, 0x8b, // crc16 start
        0x43, 0xf8, 0x50, 0x8b, 0x43, 0xfc, 0x8b, 0x4b, 0xf4, 0x89, 0x6c, 0x24, 0x0c, 0x8d, 0x6c, 0x24, 0x0c, 0xc7,
        0x44, 0x24, 0x08, 0xff, 0xff, 0xff, 0xff, 0x51, 0x53, 0x2b, 0xe0, 0x56, 0x57, 0xa1, // footer start
        0x70, 0x14, 0x01, 0x10, 0x33, 0xc5, 0x50, 0x89, 0x65, 0xf0, 0x8b, 0x43, 0x04, 0x89, 0x45, 0x04, 0xff, 0x75,
        0xf4, 0x64, 0xa1, 0x00, 0x00, 0x00, 0x00, 0x89, 0x45, 0xf4, 0x8d, 0x45, 0xf4, 0x64, 0xa3, 0x00, 0x00, 0x00,
        0x00, 0xf2, 0xc3,
    ];

    #[test]
    fn test_sig_pat_same() {
        let pats = pat::parse(PAT).unwrap();
        let sigs = sig::parse(&SIG).unwrap();

        let pat = pats
            .iter()
            .find(|sig| sig.get_name().unwrap() == "__EH_prolog3_catch_align")
            .unwrap();
        let sig = sigs
            .iter()
            .find(|sig| sig.get_name().unwrap() == "__EH_prolog3_catch_align")
            .unwrap();

        assert_eq!(pat.byte_sig, sig.byte_sig);
        assert_eq!(pat.size_of_bytes_crc16, sig.size_of_bytes_crc16);
        assert_eq!(pat.crc16, sig.crc16);

        // pat references __security_cookie
        // sig does not have any references
        // assert_eq!(pat.names, sig.names);
    }

    #[test]
    fn test_one_pat_match() {
        let sigs = pat::parse(&PAT).unwrap();
        let sig = sigs
            .iter()
            .find(|sig| sig.get_name().unwrap() == "__EH_prolog3_catch_align")
            .unwrap();

        let sigs = FlirtSignatureSet::with_signatures(vec![sig.clone()]);
        let matches = sigs.r#match(&BUF);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].get_name().unwrap(), "__EH_prolog3_catch_align");
    }

    #[test]
    fn test_pat_match() {
        let sigs = FlirtSignatureSet::with_signatures(pat::parse(PAT).unwrap());
        let matches = sigs.r#match(&BUF);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].get_name().unwrap(), "__EH_prolog3_catch_align");
    }

    #[test]
    fn test_one_sig_match() {
        let sigs = sig::parse(&SIG).unwrap();
        let sig = sigs
            .iter()
            .find(|sig| sig.get_name().unwrap() == "__EH_prolog3_catch_align")
            .unwrap();

        let sigs = FlirtSignatureSet::with_signatures(vec![sig.clone()]);
        let matches = sigs.r#match(&BUF);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].get_name().unwrap(), "__EH_prolog3_catch_align");
    }

    #[test]
    fn test_sig_match() {
        let sigs = FlirtSignatureSet::with_signatures(sig::parse(&SIG).unwrap());
        let matches = sigs.r#match(&BUF);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].get_name().unwrap(), "__EH_prolog3_catch_align");
    }
}
