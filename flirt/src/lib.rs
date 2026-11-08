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

pub mod pat;
pub mod sig;

/// parse the contents of a signature file.
/// a file that starts with the `IDASGN` magic is a .sig file.
/// any other file is a .pat file.
pub fn parse(buf: &[u8]) -> anyhow::Result<Vec<FlirtSignature>> {
    if buf.starts_with(b"IDASGN") {
        sig::parse(buf)
    } else {
        pat::parse(std::str::from_utf8(buf)?)
    }
}

/// one element of a byte signature: a byte, or a wildcard.
///
/// `FlirtSignatureSet` sorts signatures with the derived order:
/// `Byte(0x00) < ... < Byte(0xFF) < Wildcard`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SigElement {
    Byte(u8),
    Wildcard,
}

impl std::fmt::Display for SigElement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SigElement::Byte(v) => write!(f, "{v:02x}"),
            SigElement::Wildcard => write!(f, ".."),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ByteSignature(pub Vec<SigElement>);

impl ByteSignature {
    /// return true if this matches the start of the buffer.
    ///
    /// a wildcard matches any byte. it also matches after the end of the buffer.
    /// the elements after the end of a function are wildcards: version 10 .sig
    /// files have one, and .pat files have enough to make 32 bytes. and a
    /// function can end at the end of the buffer, for example at the end of a
    /// section.
    pub fn is_match(&self, buf: &[u8]) -> bool {
        self.0.iter().enumerate().all(|(i, element)| match element {
            SigElement::Byte(wanted) => buf.get(i) == Some(wanted),
            SigElement::Wildcard => true,
        })
    }
}

impl std::fmt::Display for ByteSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for elem in self.0.iter() {
            write!(f, "{elem}")?;
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

/// the name sigmake gives to modules that it couldn't tell apart.
pub const UNRESOLVED_COLLISION: &str = "?";

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
    /// the size of the byte signature.
    /// if `byte_sig` has fewer elements, its assumed to be padded with
    /// wildcards.
    pub byte_sig_size: u16,

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

    // after byte signature matching the start of the function,
    // flirt checks the CRC16 checksum of subsequent data.
    // usually this is up to the next relocation/fixup.
    //
    // example
    //
    // ```text
    //  06 2828
    // ```
    //
    // means: the CRC16 of the six bytes following the byte signature match
    // must be 0x2828.
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
    ///  - relative offset 0x45 should be a reference (^) to symbol `_vmldSinHATab`
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
            write!(f, "{name}")?;
        }

        for tail_byte in self.tail_bytes.iter() {
            write!(f, " {tail_byte}")?;
        }

        Ok(())
    }
}

impl std::fmt::Debug for FlirtSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self}")?;

        // emit local names
        for name in self.names.iter() {
            write!(f, " {name}")?;
        }

        // emit trailing byte patterns
        if let Some(footer) = &self.footer {
            write!(f, " {footer}")?;
        }

        Ok(())
    }
}

impl FlirtSignature {
    /// get the name of the function that this signature matches:
    /// the public name at offset 0. if there isn't one, the local (static)
    /// name at offset 0.
    ///
    /// sigmake gives the name `?` to modules that it couldn't tell apart.
    /// this isn't a real name, so it's skipped.
    pub fn get_name(&self) -> Option<&str> {
        let at_start = |name: &&Name| name.offset == 0x0 && name.name != UNRESOLVED_COLLISION;

        self.names
            .iter()
            .filter_map(|name| match name {
                Symbol::Public(name) => Some(name),
                _ => None,
            })
            .find(at_start)
            .or_else(|| {
                self.names
                    .iter()
                    .filter_map(|name| match name {
                        Symbol::Local(name) => Some(name),
                        _ => None,
                    })
                    .find(at_start)
            })
            .map(|name| name.name.as_str())
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

    /// return true if the byte signature matches the start of the buffer.
    /// see `ByteSignature::is_match`.
    pub fn match_pattern(&self, buf: &[u8]) -> bool {
        self.byte_sig.is_match(buf)
    }

    /// return true if all parts of the signature match the start of the buffer:
    /// the byte signature, the CRC16, the tail bytes, and the footer.
    ///
    /// this doesn't check the references. the caller must do that.
    ///
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
    /// // utcutil.dll / abc9ea116498feb8f1de45f60d595af6
    /// // __EH_prolog3_catch_align
    /// let mut buf = vec![
    ///     // first 0x20
    ///     0x51, 0x8b, 0x4c, 0x24, 0x0c, 0x89, 0x5c, 0x24,
    ///     0x0c, 0x8d, 0x5c, 0x24, 0x0c, 0x50, 0x8d, 0x44,
    ///     0x24, 0x08, 0xf7, 0xd9, 0x23, 0xc1, 0x8d, 0x60,
    ///     0xf8, 0x8b, 0x43, 0xf0, 0x89, 0x04, 0x24, 0x8b,
    ///     // crc16 start
    ///     0x43, 0xf8, 0x50, 0x8b, 0x43, 0xfc, 0x8b, 0x4b,
    ///     0xf4, 0x89, 0x6c, 0x24, 0x0c, 0x8d, 0x6c, 0x24,
    ///     0x0c, 0xc7, 0x44, 0x24, 0x08, 0xff, 0xff, 0xff,
    ///     0xff, 0x51, 0x53, 0x2b, 0xe0, 0x56, 0x57, 0xa1,
    ///     // crc end, footer start
    ///     0x70, 0x14, 0x01, 0x10, 0x33, 0xc5, 0x50, 0x89,
    ///     0x65, 0xf0, 0x8b, 0x43, 0x04, 0x89, 0x45, 0x04,
    ///     0xff, 0x75, 0xf4, 0x64, 0xa1, 0x00, 0x00, 0x00,
    ///     0x00, 0x89, 0x45, 0xf4, 0x8d, 0x45, 0xf4, 0x64,
    ///     0xa3, 0x00, 0x00, 0x00, 0x00, 0xf2, 0xc3,
    /// ];
    /// assert!(__EH_prolog3_catch_align.is_match(&buf));
    ///
    /// // apds.dll has the same function, but it ends with `ret`, not `bnd ret`.
    /// // so, the footer from the .pat file doesn't match.
    /// buf.truncate(buf.len() - 2);
    /// buf.push(0xc3);
    /// assert!(!__EH_prolog3_catch_align.is_match(&buf));
    /// ```
    pub fn is_match(&self, buf: &[u8]) -> bool {
        self.match_pattern(buf) && self.match_crc16(buf) && self.match_tail_bytes(buf) && self.match_footer(buf)
    }

    /// the offset of the end of the CRC16 block.
    /// the tail byte offsets and the footer start here.
    fn crc16_end(&self) -> usize {
        self.byte_sig_size as usize + self.size_of_bytes_crc16 as usize
    }

    /// return true if the CRC16 of the bytes after the byte signature matches,
    /// or if there are no CRC16 bytes.
    pub fn match_crc16(&self, buf: &[u8]) -> bool {
        if self.size_of_bytes_crc16 == 0 {
            return true;
        }

        match buf.get(self.byte_sig_size as usize..self.crc16_end()) {
            Some(crc16_block) => FlirtSignature::crc16(crc16_block) == self.crc16,
            None => false,
        }
    }

    /// return true if all tail bytes match (if there are any).
    pub fn match_tail_bytes(&self, buf: &[u8]) -> bool {
        self.tail_bytes
            .iter()
            .all(|tail_byte| buf.get(self.crc16_end() + tail_byte.offset as usize) == Some(&tail_byte.value))
    }

    /// return true if the footer matches (if there is one).
    pub fn match_footer(&self, buf: &[u8]) -> bool {
        match &self.footer {
            Some(footer) => footer.is_match(buf.get(self.crc16_end()..).unwrap_or_default()),
            None => true,
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
            write!(f, " {name}").unwrap();
        }

        for tail_byte in self.tail_bytes.iter() {
            write!(f, " ({:04X}: {:02X})", tail_byte.offset, tail_byte.value).unwrap();
        }

        if let Some(footer) = &self.footer {
            write!(f, " {footer}").unwrap();
        }

        // we're writing utf8 above, so no reason for this to fail.
        String::from_utf8(f).unwrap()
    }
}

/// a collection of signatures, indexed to match many of them at once.
///
/// the signatures are sorted by their byte signatures (see `SigElement` for
/// the order). with this order, signatures with the same prefix are next to
/// each other. so, the sorted list is a prefix tree (trie): a binary search
/// finds the signatures that continue a prefix with a given element.
///
/// to match, `walk` goes down this tree with the bytes of the buffer.
/// a wildcard is an element too, so at each position the walk follows at
/// most two branches: the buffer's byte, and the wildcard. in theory, the
/// work can double at each position. but in practice, the walk follows only
/// a few branches at a time: wildcards mask relocations, and related
/// functions have relocations at the same positions.
///
/// so, to build the index, we only sort the signatures. a .sig file stores
/// its patterns as a tree, and the depth-first order of that tree is already
/// this order. so, the sort only confirms the order.
pub struct FlirtSignatureSet {
    /// sorted by `byte_sig`.
    sigs: Vec<FlirtSignature>,
}

impl FlirtSignatureSet {
    pub fn with_signatures(mut sigs: Vec<FlirtSignature>) -> FlirtSignatureSet {
        sigs.sort_by(|a, b| a.byte_sig.0.cmp(&b.byte_sig.0));
        FlirtSignatureSet { sigs }
    }

    pub fn is_empty(&self) -> bool {
        self.sigs.is_empty()
    }

    /// find the signatures that match the start of the buffer.
    /// see `FlirtSignature::is_match`.
    pub fn r#match(&self, buf: &[u8]) -> Vec<&FlirtSignature> {
        let mut matches = vec![];
        walk(&self.sigs, buf, 0, &mut matches);

        // the byte signatures match. now check the other parts.
        matches.retain(|sig| sig.match_crc16(buf) && sig.match_tail_bytes(buf) && sig.match_footer(buf));
        matches
    }
}

/// find the signatures in `sigs` whose byte signatures match `buf`.
///
/// `sigs` must be sorted. all of them must have the same first `depth`
/// elements, and these elements must match `buf`.
fn walk<'a>(sigs: &'a [FlirtSignature], buf: &[u8], depth: usize, matches: &mut Vec<&'a FlirtSignature>) {
    let element = |sig: &FlirtSignature| sig.byte_sig.0.get(depth).copied();

    // signatures that end here are matches. they are first in the order.
    let ended = sigs.partition_point(|sig| element(sig).is_none());
    matches.extend(&sigs[..ended]);

    // signatures with a wildcard here are last in the order.
    // a wildcard matches any byte, and also the end of the buffer.
    let wildcards = sigs.partition_point(|sig| element(sig) < Some(SigElement::Wildcard));
    if wildcards < sigs.len() {
        walk(&sigs[wildcards..], buf, depth + 1, matches);
    }

    // signatures with the buffer's byte here.
    if let Some(&b) = buf.get(depth) {
        let byte = Some(SigElement::Byte(b));
        let start = sigs.partition_point(|sig| element(sig) < byte);
        let end = sigs.partition_point(|sig| element(sig) <= byte);
        if start < end {
            walk(&sigs[start..end], buf, depth + 1, matches);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAT: &str = "\
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
    fn test_parse_either_format() {
        let from_sig: Vec<String> = parse(&SIG).unwrap().iter().map(|s| format!("{s:?}")).collect();
        let from_pat: Vec<String> = parse(PAT.as_bytes())
            .unwrap()
            .iter()
            .map(|s| format!("{s:?}"))
            .collect();
        assert_eq!(
            from_sig,
            sig::parse(&SIG)
                .unwrap()
                .iter()
                .map(|s| format!("{s:?}"))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            from_pat,
            pat::parse(PAT)
                .unwrap()
                .iter()
                .map(|s| format!("{s:?}"))
                .collect::<Vec<_>>()
        );
        // not a .sig file, and not valid .pat text.
        assert!(parse(b"MZ\x90\x00").is_err());
    }

    /// malformed .sig files are errors, not panics.
    #[test]
    fn test_sig_corrupt() {
        // every truncation.
        for len in 0..SIG.len() {
            let _ = sig::parse(&SIG[..len]);
        }

        // every single byte replaced by every value.
        let mut buf = SIG;
        for i in 0..SIG.len() {
            for v in 0..=255u8 {
                buf[i] = v;
                let _ = sig::parse(&buf);
            }
            buf[i] = SIG[i];
        }

        // also, specific cases: a name that isn't valid UTF-8, and unknown feature bits.
        let name = SIG.windows(5).position(|w| w == b"__EH_").unwrap();
        let mut buf = SIG;
        buf[name] = 0xFF;
        assert!(sig::parse(&buf).is_err());

        let mut buf = SIG;
        buf[0x11] = 0x80;
        assert!(sig::parse(&buf).is_err());
    }

    #[test]
    fn test_one_pat_match() {
        let sigs = pat::parse(PAT).unwrap();
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

    // from: https://github.com/williballenthin/lancelot/issues/112#issuecomment-802147183
    // user might provide too much data for a small function, which should stil
    // match.
    #[test]
    fn test_too_much_data() {
        let buf = [
            0xffu8, 0x35, 0xa0, 0x22, 0x41, 0x00, 0xff, 0x74, 0x24, 0x08, 0xe8, 0x03, 0x00, 0x00, 0x00, 0x59, 0x59,
            0xc3, 0x83, 0x7c, 0x24, 0x04, 0xe0, 0x77, 0x22, 0xff, 0x74, 0x24, 0x04, 0xe8, 0x1c, 0x00, 0x00, 0x00, 0x85,
            0xc0, 0x59, 0x75, 0x16, 0x39, 0x44, 0x24, 0x08, 0x74, 0x10, 0xff, 0x74, 0x24, 0x04, 0xe8, 0x7d, 0x2e, 0x00,
            0x00, 0x85, 0xc0, 0x59, 0x75, 0xde, 0x33, 0xc0, 0xc3, 0x55, 0x8b, 0xec, 0x6a, 0xff, 0x68, 0x88, 0xd1, 0x40,
            0x00, 0x68, 0x84, 0x68, 0x40, 0x00, 0x64, 0xa1, 0x00, 0x00, 0x00, 0x00, 0x50, 0x64, 0x89, 0x25, 0x00, 0x00,
            0x00, 0x00, 0x83, 0xec, 0x0c, 0x53, 0x56, 0x57, 0xa1, 0xa4, 0x36, 0x41, 0x00, 0x83, 0xf8, 0x03, 0x75, 0x43,
            0x8b, 0x75, 0x08, 0x3b, 0x35, 0x9c, 0x36, 0x41, 0x00, 0x0f, 0x87, 0x93, 0x00, 0x00, 0x00, 0x6a, 0x09, 0xe8,
            0xbc, 0x2d, 0x00, 0x00, 0x59, 0x83, 0x65, 0xfc, 0x00, 0x56, 0xe8, 0x10, 0x1f, 0x00, 0x00, 0x59, 0x89, 0x45,
            0xe4, 0x83, 0x4d, 0xfc, 0xff, 0xe8, 0x0c, 0x00, 0x00, 0x00, 0x8b, 0x45, 0xe4, 0x85, 0xc0, 0x74, 0x6d, 0xe9,
            0x86, 0x00, 0x00, 0x00, 0x6a, 0x09, 0xe8, 0xf2, 0x2d, 0x00, 0x00, 0x59, 0xc3, 0x83, 0xf8, 0x02, 0x75, 0x5a,
            0x8b, 0x45, 0x08, 0x85, 0xc0, 0x74, 0x08, 0x8d, 0x70, 0x0f, 0x83, 0xe6, 0xf0, 0xeb, 0x03, 0x6a, 0x10, 0x5e,
            0x89, 0x75, 0x08, 0x3b, 0x35, 0xfc, 0x14, 0x41, 0x00, 0x77, 0x2e, 0x6a, 0x09, 0xe8, 0x66, 0x2d, 0x00, 0x00,
            0x59, 0xc7, 0x45, 0xfc, 0x01, 0x00, 0x00, 0x00, 0x8b, 0xc6, 0xc1, 0xe8, 0x04, 0x50, 0xe8, 0x55, 0x29, 0x00,
            0x00, 0x59, 0x89, 0x45, 0xe4, 0x83, 0x4d, 0xfc, 0xff, 0xe8, 0x0d, 0x00, 0x00, 0x00, 0x8b, 0x45, 0xe4, 0x85,
            0xc0, 0x75, 0x2d, 0x56, 0xeb,
        ];
        let pat = "ff35........ff742408e8........5959c3 00 0000 0012 :0000 _malloc\n---";
        let sigs = FlirtSignatureSet::with_signatures(pat::parse(pat).unwrap());
        let matches = sigs.r#match(&buf[..]);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].get_name().unwrap(), "_malloc");
    }

    // https://github.com/williballenthin/lancelot/issues/112#issuecomment-802331085
    #[test]
    fn test_byte_sig_size() {
        let buf = [
            0x56, 0xe8, 0x76, 0x00, 0x00, 0x00, 0x8b, 0x4c, 0x24, 0x08, 0x33, 0xf6, 0x89, 0x08, 0xb8, 0x10, 0xf2, 0x40,
            0x00, 0x3b, 0x08, 0x74, 0x22, 0x83, 0xc0, 0x08, 0x46, 0x3d, 0x78, 0xf3, 0x40, 0x00, 0x7c, 0xf1, 0x83, 0xf9,
            0x13, 0x72, 0x22, 0x83, 0xf9, 0x24, 0x77, 0x1d, 0xe8, 0x42, 0x00, 0x00, 0x00, 0xc7, 0x00, 0x0d, 0x00, 0x00,
            0x00, 0x5e, 0xc3, 0xe8, 0x35, 0x00, 0x00, 0x00, 0x8b, 0x0c, 0xf5, 0x14, 0xf2, 0x40, 0x00, 0x5e, 0x89, 0x08,
            0xc3, 0x81, 0xf9, 0xbc, 0x00, 0x00, 0x00, 0x72, 0x15, 0x81, 0xf9, 0xca, 0x00, 0x00, 0x00, 0x77, 0x0d, 0xe8,
            0x15, 0x00, 0x00, 0x00, 0xc7, 0x00, 0x08, 0x00, 0x00, 0x00, 0x5e, 0xc3, 0xe8, 0x08, 0x00, 0x00, 0x00, 0xc7,
            0x00, 0x16, 0x00, 0x00, 0x00, 0x5e, 0xc3, 0xe8, 0xb7, 0x14, 0x00, 0x00, 0x83, 0xc0, 0x08, 0xc3, 0xe8, 0xae,
            0x14, 0x00, 0x00, 0x83, 0xc0, 0x0c, 0xc3, 0x56, 0x8b, 0x74, 0x24, 0x08, 0x57, 0x83, 0xcf, 0xff, 0xf6, 0x46,
            0x0c, 0x40, 0x74, 0x06, 0x83, 0x66, 0x0c, 0x00, 0xeb, 0x17, 0x56, 0xe8, 0xb0, 0x2d, 0x00, 0x00, 0x56, 0xe8,
            0x10, 0x00, 0x00, 0x00, 0x56, 0x8b, 0xf8, 0xe8, 0xf4, 0x2d, 0x00, 0x00, 0x83, 0xc4, 0x0c, 0x8b, 0xc7, 0x5f,
            0x5e, 0xc3, 0x56, 0x8b, 0x74, 0x24, 0x08, 0x57, 0x83, 0xcf, 0xff, 0xf6, 0x46, 0x0c, 0x83, 0x74, 0x34, 0x56,
            0xe8, 0xe4, 0x08, 0x00, 0x00, 0x56, 0x8b, 0xf8, 0xe8, 0x01, 0x2f, 0x00, 0x00, 0xff, 0x76, 0x10, 0xe8, 0x19,
            0x2e, 0x00, 0x00, 0x83, 0xc4, 0x0c, 0x85, 0xc0, 0x7d, 0x05, 0x83, 0xcf, 0xff, 0xeb, 0x12, 0x8b, 0x46, 0x1c,
            0x85, 0xc0, 0x74, 0x0b, 0x50, 0xe8, 0x82, 0xfc, 0xff, 0xff, 0x83, 0x66, 0x1c, 0x00, 0x59, 0x83, 0x66, 0x0c,
            0x00, 0x8b, 0xc7, 0x5f,
        ];
        let pat = "\
56e8........8b4c240833f68908b8........3b08742283c008463d 0d 2a18 0073 :0000 __dosmaperr
---";
        let sigs = FlirtSignatureSet::with_signatures(pat::parse(pat).unwrap());
        let matches = sigs.r#match(&buf[..]);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].get_name().unwrap(), "__dosmaperr");
    }

    #[test]
    fn test_tail_bytes() {
        let buf = [
            0x56, 0x8b, 0x74, 0x24, 0x08, 0x57, 0x8b, 0x46, 0x0c, 0xa8, 0x83, 0x74, 0x6f, 0x8b, 0x7c, 0x24, 0x14, 0x85,
            0xff, 0x74, 0x0a, 0x83, 0xff, 0x01, 0x74, 0x05, 0x83, 0xff, 0x02, 0x75, 0x5d, 0x24, 0xef, 0x83, 0xff, 0x01,
            0x89, 0x46, 0x0c, 0x75, 0x0d, 0x56, 0xe8, 0x80, 0x00, 0x00, 0x00, 0x01, 0x44, 0x24, 0x14, 0x59, 0x33, 0xff,
            0x56, 0xe8, 0x2e, 0x07, 0x00, 0x00, 0x8b, 0x46, 0x0c, 0x59, 0xa8, 0x80, 0x74, 0x07, 0x24, 0xfc, 0x89, 0x46,
            0x0c, 0xeb, 0x14, 0xa8, 0x01, 0x74, 0x10, 0xa8, 0x08, 0x74, 0x0c, 0xf6, 0xc4, 0x04, 0x75, 0x07, 0xc7, 0x46,
            0x18, 0x00, 0x02, 0x00, 0x00, 0x57, 0xff, 0x74, 0x24, 0x14, 0xff, 0x76, 0x10, 0xe8, 0x68, 0x30, 0x00, 0x00,
            0x83, 0xc4, 0x0c, 0x33, 0xc9, 0x83, 0xf8, 0xff, 0x0f, 0x95, 0xc1, 0x49, 0x8b, 0xc1, 0xeb, 0x0e, 0xe8, 0xad,
            0xfd, 0xff, 0xff, 0xc7, 0x00, 0x16, 0x00, 0x00, 0x00, 0x83, 0xc8, 0xff, 0x5f, 0x5e, 0xc3, 0x56, 0x8b, 0x74,
            0x24, 0x08, 0x57, 0x56, 0xe8, 0x72, 0x2b, 0x00, 0x00, 0x56, 0xe8, 0x10, 0x00, 0x00, 0x00, 0x56, 0x8b, 0xf8,
            0xe8, 0xb6, 0x2b, 0x00, 0x00, 0x83, 0xc4, 0x0c, 0x8b, 0xc7, 0x5f, 0x5e, 0xc3, 0x55, 0x8b, 0xec, 0x83, 0xec,
            0x0c, 0x53, 0x56, 0x57, 0x8b, 0x7d, 0x08, 0x33, 0xdb, 0x8b, 0x77, 0x10, 0x39, 0x5f, 0x04, 0x89, 0x75, 0xf4,
            0x7d, 0x03, 0x89, 0x5f, 0x04, 0x6a, 0x01, 0x53, 0x56, 0xe8, 0x00, 0x30, 0x00, 0x00, 0x83, 0xc4, 0x0c, 0x3b,
            0xc3, 0x89, 0x45, 0xfc, 0x7c, 0x5f, 0x8b, 0x4f, 0x0c, 0x66, 0xf7, 0xc1, 0x08, 0x01, 0x75, 0x08, 0x2b, 0x47,
            0x04, 0xe9, 0x1b, 0x01, 0x00, 0x00, 0x8b, 0x07, 0x8b, 0x57, 0x08, 0x8b, 0xd8, 0x2b, 0xda, 0xf6, 0xc1, 0x03,
            0x89, 0x5d, 0xf8, 0x74,
        ];

        let pat = "\
568b742408578b460ca883746f8b7c241485ff740a83ff01740583ff02755d24 0b 2ec8 008c :0000 _fseek (0050: 0D)
568b742408578b460ca883746f8b7c241485ff740a83ff01740583ff02755d24 0b 2ec8 008d :0000 __fseek_lk (0050: 0E)
---
";
        let sigs = FlirtSignatureSet::with_signatures(pat::parse(pat).unwrap());
        let matches = sigs.r#match(&buf[..]);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].get_name().unwrap(), "__fseek_lk");
    }

    #[test]
    fn test_empty_signature_set() {
        assert!(FlirtSignatureSet::with_signatures(vec![]).is_empty());
        assert!(FlirtSignatureSet::with_signatures(vec![])
            .r#match(b"\xAA\xBB\xCC\xDD")
            .is_empty());
    }

    /// build a signature set from byte patterns, like `AABB..DD`.
    /// the name of each signature is its index. the signatures have no CRC16
    /// bytes or tail bytes, so only the byte patterns affect matching.
    fn set_from_patterns(patterns: &[&str]) -> FlirtSignatureSet {
        let pat: String = patterns
            .iter()
            .enumerate()
            .map(|(i, p)| format!("{p} 00 0000 0100 :0000 p{i}\n"))
            .collect();
        FlirtSignatureSet::with_signatures(pat::parse(&format!("{pat}---\n")).unwrap())
    }

    /// match and return the indices of the matching patterns, sorted.
    fn matching(set: &FlirtSignatureSet, buf: &[u8]) -> Vec<usize> {
        let mut ids: Vec<usize> = set
            .r#match(buf)
            .iter()
            .map(|sig| sig.get_name().unwrap()[1..].parse().unwrap())
            .collect();
        ids.sort();
        ids
    }

    #[test]
    fn test_set_match() {
        let set = set_from_patterns(&["AABBCCDD"]);
        assert_eq!(matching(&set, b"\xAA\xBB\xCC\xDD"), vec![0]);
        assert_eq!(matching(&set, b"\xAA\xBB\xCC\xEE"), Vec::<usize>::new());

        // trailing bytes don't matter.
        assert_eq!(matching(&set, b"\xAA\xBB\xCC\xDD\x00"), vec![0]);
        assert_eq!(matching(&set, b"\xAA\xBB\xCC\xDD\x11"), vec![0]);

        // the buffer must be at least as long as the pattern.
        assert_eq!(matching(&set, b"\xAA\xBB\xCC"), Vec::<usize>::new());
        assert_eq!(matching(&set, b""), Vec::<usize>::new());
    }

    #[test]
    fn test_set_match_wildcards() {
        // and the order of the patterns doesn't matter.
        for patterns in [["AABBCC..", "AABBCCDD"], ["AABBCCDD", "AABBCC.."]] {
            let set = set_from_patterns(&patterns);
            assert_eq!(matching(&set, b"\xAA\xBB\xCC\xDD").len(), 2);
            assert_eq!(matching(&set, b"\xAA\xBB\xCC\xEE").len(), 1);
            assert_eq!(matching(&set, b"\xAA\xBB\x00\x00").len(), 0);
        }

        for patterns in [["AABB..DD", "AABBCCDD"], ["AABBCCDD", "AABB..DD"]] {
            let set = set_from_patterns(&patterns);
            assert_eq!(matching(&set, b"\xAA\xBB\xCC\xDD").len(), 2);
            assert_eq!(matching(&set, b"\xAA\xBB\xEE\xDD").len(), 1);
            assert_eq!(matching(&set, b"\xAA\xBB\x00\x00").len(), 0);
        }

        // a wildcard matches any byte, including newline.
        let set = set_from_patterns(&["AA..BB"]);
        for b in 0..=255u8 {
            assert_eq!(matching(&set, &[0xAA, b, 0xBB]), vec![0]);
        }
        // and also the end of the buffer, for example when a short function is
        // at the end of a section.
        let set = set_from_patterns(&["AABB....", "AA..CC"]);
        assert_eq!(matching(&set, b"\xAA\xBB"), vec![0]);
        assert_eq!(matching(&set, b"\xAA\xBB\xCC"), vec![0, 1]);
        assert_eq!(matching(&set, b"\xAA\xBB\xCD"), vec![0]);
        // but a byte element must have a byte in the buffer.
        assert_eq!(matching(&set, b"\xAA"), Vec::<usize>::new());
    }

    #[test]
    fn test_set_match_many() {
        let set = set_from_patterns(&["AABB..DD", "AABBCCDD", "........", "....CCDD"]);
        assert_eq!(matching(&set, b"\xAA\xBB\xCC\xDD"), vec![0, 1, 2, 3]);
        assert_eq!(matching(&set, b"\xAA\xBB\x00\xDD"), vec![0, 2]);
        assert_eq!(matching(&set, b"\xAA\xBB\x00\x00"), vec![2]);
        assert_eq!(matching(&set, b"\x00\x00\xCC\xDD"), vec![2, 3]);
        assert_eq!(matching(&set, b"\x00\x00\x00\x00"), vec![2]);
    }

    #[test]
    fn test_set_match_lengths() {
        // patterns of different lengths, some prefixes of others.
        let set = set_from_patterns(&["AA", "AABB", "AABBCC", "AA..CC", "..BB", "AABBCCDDEE"]);
        assert_eq!(matching(&set, b""), Vec::<usize>::new());
        assert_eq!(matching(&set, b"\xAA"), vec![0]);
        assert_eq!(matching(&set, b"\xAA\xBB"), vec![0, 1, 4]);
        assert_eq!(matching(&set, b"\xAA\xBB\xCC"), vec![0, 1, 2, 3, 4]);
        assert_eq!(matching(&set, b"\xAA\x00\xCC"), vec![0, 3]);
        assert_eq!(matching(&set, b"\x00\xBB\xCC"), vec![4]);
        assert_eq!(matching(&set, b"\xAA\xBB\xCC\xDD\xEE"), vec![0, 1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_set_match_duplicate_patterns() {
        // signatures with the same byte pattern all match.
        let set = set_from_patterns(&["AABB", "AA..", "AABB", "AA..", "AABB"]);
        assert_eq!(matching(&set, b"\xAA\xBB"), vec![0, 1, 2, 3, 4]);
        assert_eq!(matching(&set, b"\xAA\x00"), vec![1, 3]);
    }

    #[test]
    fn test_set_match_pathological() {
        // patterns longer than the usual 32 bytes work too.
        let set = set_from_patterns(&[
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "................................................................",
        ]);
        assert_eq!(matching(&set, &[0xAA; 32]), vec![0, 1]);
        assert_eq!(matching(&set, &[0xAB; 32]), vec![1]);
        assert_eq!(matching(&set, &[0xAA; 31]), vec![1]);
    }

    #[test]
    fn test_is_match_same_as_set() {
        // matching one signature gives the same result as matching the set,
        // including the tail bytes.
        let pat = "\
568b742408578b460ca883746f8b7c241485ff740a83ff01740583ff02755d24 0b 2ec8 008c :0000 _fseek (0050: 0D)
568b742408578b460ca883746f8b7c241485ff740a83ff01740583ff02755d24 0b 2ec8 008d :0000 __fseek_lk (0050: 0E)
---
";
        let sigs = pat::parse(pat).unwrap();
        let set = FlirtSignatureSet::with_signatures(sigs.clone());

        // a buffer with the pattern and CRC16 bytes of both signatures.
        // then, try each tail byte.
        let mut buf = vec![0u8; 0x100];
        for (i, b) in [
            0x56, 0x8b, 0x74, 0x24, 0x08, 0x57, 0x8b, 0x46, 0x0c, 0xa8, 0x83, 0x74, 0x6f, 0x8b, 0x7c, 0x24, 0x14, 0x85,
            0xff, 0x74, 0x0a, 0x83, 0xff, 0x01, 0x74, 0x05, 0x83, 0xff, 0x02, 0x75, 0x5d, 0x24, 0xef, 0x83, 0xff, 0x01,
            0x89, 0x46, 0x0c, 0x75, 0x0d, 0x56, 0xe8,
        ]
        .into_iter()
        .enumerate()
        {
            buf[i] = b;
        }
        for tail in [0x0D, 0x0E, 0x0F] {
            buf[32 + 0x0b + 0x50] = tail;
            let from_set: Vec<&str> = set.r#match(&buf).iter().map(|s| s.get_name().unwrap()).collect();
            let from_one: Vec<&str> = sigs
                .iter()
                .filter(|s| s.is_match(&buf))
                .map(|s| s.get_name().unwrap())
                .collect();
            assert_eq!(from_set, from_one);
            assert_eq!(from_set.len(), if tail == 0x0F { 0 } else { 1 });
        }
    }

    #[test]
    fn test_get_name() {
        let name = |pat: &str| {
            pat::parse(&format!("AABB 00 0000 0002 {pat}\n---"))
                .unwrap()
                .remove(0)
                .get_name()
                .map(String::from)
        };
        assert_eq!(name(":0000 foo"), Some("foo".into()));
        // a local (static) function.
        assert_eq!(name(":0000@ foo"), Some("foo".into()));
        // a public name comes before a local name.
        assert_eq!(name(":0000@ foo :0000 bar"), Some("bar".into()));
        // only names at the start of the function.
        assert_eq!(name(":0010 foo"), None);
        // sigmake's placeholder for modules it couldn't tell apart.
        assert_eq!(name(":0000 ?"), None);
        assert_eq!(name(":0000 ? :0000@ foo"), Some("foo".into()));
    }

    #[test]
    fn test_footer() {
        // the footer starts at the end of the CRC16 block, even for a short pattern.
        let sigs = pat::parse("AABB 00 0000 0030 :0000 foo ....CCDD\n---").unwrap();
        let mut buf = vec![0u8; 0x30];
        buf[0] = 0xAA;
        buf[1] = 0xBB;
        assert!(!sigs[0].is_match(&buf));
        buf[34] = 0xCC;
        buf[35] = 0xDD;
        assert!(sigs[0].is_match(&buf));
        assert_eq!(FlirtSignatureSet::with_signatures(sigs).r#match(&buf).len(), 1);
    }

    #[test]
    fn test_is_match_wildcard_newline() {
        // a wildcard also matches a newline (0x0A).
        let sigs = pat::parse("AA..BB 00 0000 0003 :0000 foo\n---").unwrap();
        let m = &sigs[0];
        for b in 0..=255u8 {
            assert!(m.is_match(&[0xAA, b, 0xBB]));
        }
        assert!(!m.is_match(&[0xAA, 0x00, 0xCC]));
        assert!(!m.is_match(&[0xAA, 0x00]));
    }

    #[test]
    fn test_is_match_function_shorter_than_pattern() {
        // wildcards fill the pattern after the end of the function.
        // the buffer can end there.
        let sigs = pat::parse("AABB.... 00 0000 0002 :0000 foo\n---").unwrap();
        assert!(sigs[0].is_match(&[0xAA, 0xBB]));
        assert!(sigs[0].is_match(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE]));
        assert!(!sigs[0].is_match(&[0xAA]));

        // the function size is larger than the pattern, but less than 32 bytes.
        let sigs = pat::parse("AABB 00 0000 0010 :0000 foo\n---").unwrap();
        assert!(sigs[0].is_match(&[0xAA, 0xBB]));
        assert!(!sigs[0].is_match(&[0xAA, 0xCC]));
    }
}
