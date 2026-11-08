//! parse IDA's compiled FLIRT signature files (.sig).
//!
//! a .sig file is a header, then a tree, which is usually zlib-compressed:
//!
//!   - an internal node has edges to its children. each edge holds a run of pattern elements: bytes or wildcards. the
//!     pattern of a leaf is made from the edges on the path from the root to it.
//!   - a leaf holds the modules (functions) with that pattern, grouped by the CRC16 of the bytes after the pattern.
//!     each module has its size, names, and maybe tail bytes and references to other names.
//!
//! the header's numbers are little-endian. the tree's are big-endian, and most
//! are variable-length (see `Reader::vint16` and `Reader::vint32`).

use anyhow::Result;
use log::trace;
use thiserror::Error;

use super::{FlirtSignature, Name, Symbol, TailByte};
use crate::{ByteSignature, SigElement};

#[derive(Debug, Error)]
pub enum SigError {
    #[error("The sig file is not supported")]
    NotSupported,
    #[error("The sig file compression method is not supported: {0}")]
    CompressionNotSupported(String),
    #[error("The .sig file is corrupt (or unsupported)")]
    CorruptSigFile,
}

fn corrupt() -> anyhow::Error {
    SigError::CorruptSigFile.into()
}

/// reads values from the front of a byte slice.
/// a read past the end is an error: the file is corrupt.
struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Reader<'a> {
        Reader { buf }
    }

    fn bytes(&mut self, count: usize) -> Result<&'a [u8]> {
        if count > self.buf.len() {
            return Err(corrupt());
        }
        let (bytes, rest) = self.buf.split_at(count);
        self.buf = rest;
        Ok(bytes)
    }

    /// read bytes up to (not including) the first one that isn't printable,
    /// or the end.
    fn printable_bytes(&mut self) -> &'a [u8] {
        let count = self.buf.iter().take_while(|&&b| b >= 0x20).count();
        let (bytes, rest) = self.buf.split_at(count);
        self.buf = rest;
        bytes
    }

    fn string(&mut self, length: usize) -> Result<String> {
        String::from_utf8(self.bytes(length)?.to_vec()).map_err(|_| corrupt())
    }

    fn peek_u8(&self) -> Result<u8> {
        self.buf.first().copied().ok_or_else(corrupt)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.bytes(1)?[0])
    }

    fn be_u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.bytes(2)?.try_into()?))
    }

    fn le_u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.bytes(2)?.try_into()?))
    }

    fn le_u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.bytes(4)?.try_into()?))
    }

    /// a variable-length number of up to 15 bits, in one or two bytes:
    ///
    /// ```text
    ///   0xxxxxxx           -> 7 bits
    ///   1xxxxxxx xxxxxxxx  -> 15 bits
    /// ```
    fn vint16(&mut self) -> Result<u16> {
        let first = self.u8()? as u16;
        if first & 0x80 == 0 {
            Ok(first)
        } else {
            Ok(((first & 0x7F) << 8) | self.u8()? as u16)
        }
    }

    /// a variable-length number of up to 32 bits, in one to five bytes:
    ///
    /// ```text
    ///   0xxxxxxx                    -> 7 bits
    ///   10xxxxxx xxxxxxxx           -> 14 bits
    ///   110xxxxx xxxxxxxx [2 bytes] -> 29 bits
    ///   111xxxxx [4 bytes]          -> 32 bits
    /// ```
    fn vint32(&mut self) -> Result<u32> {
        let first = self.u8()? as u32;
        if first & 0x80 == 0 {
            Ok(first)
        } else if first & 0xC0 == 0x80 {
            Ok(((first & 0x7F) << 8) | self.u8()? as u32)
        } else if first & 0xE0 == 0xC0 {
            let high = ((first & 0x3F) << 8) | self.u8()? as u32;
            Ok((high << 16) | self.be_u16()? as u32)
        } else {
            let high = self.be_u16()? as u32;
            Ok((high << 16) | self.be_u16()? as u32)
        }
    }

    /// a count or offset in the tree: a vint16 before version 9, and a vint32 since.
    fn word(&mut self, header: &Header) -> Result<u64> {
        if header.version < 9 {
            Ok(self.vint16()? as u64)
        } else {
            Ok(self.vint32()? as u64)
        }
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Features: u16 {
        const STARTUP        = 0b0000_0001;
        const CTYPE_CRC      = 0b0000_0010;
        const TWO_BYTE_CTYPE = 0b0000_0100;
        const ALT_CTYPE_CRC  = 0b0000_1000;
        const COMPRESSED     = 0b0001_0000;
        const CTYPE_CRC_3V   = 0b0010_0000;
    }
}

/// the fields of the header that parsing the tree needs.
struct Header {
    version:      u8,
    features:     Features,
    /// the number of bytes in each pattern, after which the CRC16 block starts.
    pattern_size: u16,
}

/// read the header, leaving the reader at the start of the tree.
fn header(r: &mut Reader) -> Result<Header> {
    if r.bytes(6)? != b"IDASGN" {
        return Err(corrupt());
    }

    let version = r.u8()?;
    if !(5..=10).contains(&version) {
        return Err(corrupt());
    }

    let _arch = r.u8()?;
    let _file_types = r.le_u32()?;
    let _os_types = r.le_u16()?;
    let _app_types = r.le_u16()?;
    let features = Features::from_bits(r.le_u16()?).ok_or_else(corrupt)?;
    let _old_number_of_modules = r.le_u16()?;
    let _crc16 = r.le_u16()?;
    let _ctype = r.bytes(12)?;
    let library_name_length = r.u8()?;
    let _ctypes_crc16 = r.le_u16()?;

    // later versions add fields.
    if version >= 6 {
        let _number_of_patterns = r.le_u32()?;
    }
    let pattern_size = if version >= 8 { r.le_u16()? } else { 32 };
    if version >= 10 {
        let _unknown = r.le_u16()?;
    }

    let _library_name = r.string(library_name_length as usize)?;

    Ok(Header {
        version,
        features,
        pattern_size,
    })
}

/// the longest pattern accepted. real files use 32 element patterns,
/// and edges hold at most 64 elements.
const MAX_PATTERN_LENGTH: usize = 0x400;

/// read a node and its subtree, appending their signatures to `sigs`.
///
/// `prefix` is the pattern on the path from the root to this node.
fn node(r: &mut Reader, header: &Header, prefix: &[SigElement], sigs: &mut Vec<FlirtSignature>) -> Result<()> {
    let child_count = r.vint16()?;
    if child_count == 0 {
        return leaf(r, header, prefix, sigs);
    }

    for _ in 0..child_count {
        let pattern = [prefix, &edge(r, header)?].concat();

        // since each edge has elements, this bounds the recursion, even for malformed input.
        if pattern.len() > MAX_PATTERN_LENGTH {
            return Err(corrupt());
        }

        node(r, header, &pattern, sigs)?;
    }

    Ok(())
}

/// read the pattern elements of an edge: the number of elements,
/// a mask of which elements are wildcards, then the bytes of the others.
///
/// for example, `1D........0F59` is:
///
/// ```text
///   length:  07
///   mask:    0b0111100 (the first element is the most significant bit)
///   bytes:   1D 0F 59
/// ```
fn edge(r: &mut Reader, header: &Header) -> Result<Vec<SigElement>> {
    let length = if header.version < 10 {
        r.u8()? as u32
    } else {
        r.vint16()? as u32
    };

    let mask: u64 = match length {
        1..=0xF => r.vint16()? as u64,
        0x10..=0x20 => r.vint32()? as u64,
        0x21..=0x40 => {
            let high = r.vint32()? as u64;
            (high << 32) | r.vint32()? as u64
        }
        // 0 has no elements, and dumpsig supports more than 64, but we don't, yet.
        _ => return Err(corrupt()),
    };

    if length < 64 && mask >> length != 0 {
        return Err(corrupt());
    }

    let mut bytes = r.bytes((length - mask.count_ones()) as usize)?.iter();
    let elements = (0..length)
        .map(|i| {
            if mask & (1 << (length - 1 - i)) != 0 {
                SigElement::Wildcard
            } else {
                // there's one byte for each element that isn't a wildcard.
                SigElement::Byte(*bytes.next().expect("one byte per literal"))
            }
        })
        .collect();

    Ok(elements)
}

bitflags! {
    /// what follows a name in a module.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct ParsingFlags: u8 {
        const MORE_PUBLIC_NAMES          = 0b0000_0001;
        const TAIL_BYTES                 = 0b0000_0010;
        const REFERENCED_FUNCTIONS       = 0b0000_0100;
        const MORE_MODULES_WITH_SAME_CRC = 0b0000_1000;
        const MORE_MODULES               = 0b0001_0000;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct NameFlags: u8 {
        const UNK1                 = 0b0000_0001;
        const LOCAL                = 0b0000_0010;
        const UNK2                 = 0b0000_0100;
        const UNRESOLVED_COLLISION = 0b0000_1000;
        const NEGATIVE_OFFSET      = 0b0001_0000;
    }
}

/// read the modules at a leaf, whose pattern is `pattern`,
/// appending their signatures to `sigs`.
///
/// modules are grouped by their CRC16. flags after each module's names say
/// what follows: tail bytes, references, another module with the same CRC16,
/// or another group.
fn leaf(r: &mut Reader, header: &Header, pattern: &[SigElement], sigs: &mut Vec<FlirtSignature>) -> Result<()> {
    loop {
        let size_of_bytes_crc16 = r.u8()?;
        let crc16 = r.be_u16()?;

        let flags = loop {
            let size_of_function = r.word(header)?;
            let (mut names, flags) = names(r, header)?;

            let tail_bytes = if flags.contains(ParsingFlags::TAIL_BYTES) {
                tail_bytes(r, header)?
            } else {
                vec![]
            };

            if flags.contains(ParsingFlags::REFERENCED_FUNCTIONS) {
                names.extend(references(r, header)?);
            }

            let sig = FlirtSignature {
                byte_sig_size: header.pattern_size,
                byte_sig: ByteSignature(pattern.to_vec()),
                size_of_bytes_crc16,
                crc16,
                size_of_function,
                names,
                footer: None,
                tail_bytes,
            };
            trace!("{sig:?}");
            sigs.push(sig);

            if !flags.contains(ParsingFlags::MORE_MODULES_WITH_SAME_CRC) {
                break flags;
            }
        };

        if !flags.contains(ParsingFlags::MORE_MODULES) {
            return Ok(());
        }
    }
}

/// read the names a module defines, and the flags that follow the last one.
fn names(r: &mut Reader, header: &Header) -> Result<(Vec<Symbol>, ParsingFlags)> {
    let mut names = vec![];
    let mut offset = 0i64;

    loop {
        // the offset is relative to the previous name's.
        let delta = r.word(header)? as i64;

        // the name flags are optional: they're present when the next byte
        // isn't printable, since names are.
        let name_flags = if r.peek_u8()? < 0x20 {
            NameFlags::from_bits(r.u8()?).ok_or_else(corrupt)?
        } else {
            NameFlags::empty()
        };

        if name_flags.contains(NameFlags::NEGATIVE_OFFSET) {
            offset -= delta;
        } else {
            offset += delta;
        }

        let name = String::from_utf8(r.printable_bytes().to_vec()).map_err(|_| corrupt())?;
        let name = Name { offset, name };
        if name_flags.contains(NameFlags::LOCAL) {
            names.push(Symbol::Local(name));
        } else {
            names.push(Symbol::Public(name));
        }

        let flags = ParsingFlags::from_bits(r.u8()?).ok_or_else(corrupt)?;
        if !flags.contains(ParsingFlags::MORE_PUBLIC_NAMES) {
            return Ok((names, flags));
        }
    }
}

/// read the tail bytes of a module: bytes that differ between modules with
/// otherwise identical signatures.
fn tail_bytes(r: &mut Reader, header: &Header) -> Result<Vec<TailByte>> {
    // before version 8, there's always one.
    let count = if header.version < 8 { 1 } else { r.word(header)? };

    let mut tail_bytes = vec![];
    for _ in 0..count {
        tail_bytes.push(TailByte {
            // relative to the end of the CRC16 block,
            // that is, from `pattern_size + crc_len` bytes into the function.
            offset: r.word(header)?,
            value:  r.u8()?,
        });
    }

    Ok(tail_bytes)
}

/// read the references of a module: the names of what the module points to,
/// at offsets from its start.
fn references(r: &mut Reader, header: &Header) -> Result<Vec<Symbol>> {
    // before version 8, there's always one.
    let count = if header.version < 8 { 1 } else { r.word(header)? };

    let mut references = vec![];
    for _ in 0..count {
        let offset = r.word(header)? as i64;

        // the name's length, or 0 then a longer length.
        let length = match r.u8()? {
            0 => r.vint16()? as usize,
            length => length as usize,
        };
        let name = r.string(length)?;

        references.push(Symbol::Reference(Name { offset, name }));
    }

    Ok(references)
}

/// inflate the zlib-compressed tree of a compressed .sig file.
fn inflate(compressed: &[u8]) -> Result<Vec<u8>> {
    miniz_oxide::inflate::decompress_to_vec_zlib(compressed).map_err(|e| {
        // I've see possible CMF values:
        //  0xC4 - IDA Pro 7.4/sig/pc/bc31cls.sig
        //  0x0C - IDA Pro 7.4/sig/pc/bc15owl
        //  0x05 - IDA Pro 7.4/sig/pc/bc15c2.sig
        SigError::CompressionNotSupported(e.to_string()).into()
    })
}

/// decompress a .sig file, if it's compressed,
/// returning the header followed by the uncompressed tree.
pub fn unpack_sig(buf: &[u8]) -> Result<Vec<u8>> {
    let mut r = Reader::new(buf);
    let header = header(&mut r)?;

    if header.features.contains(Features::COMPRESSED) {
        let header_size = buf.len() - r.buf.len();
        let mut unpacked = buf[..header_size].to_vec();
        unpacked.extend(inflate(r.buf)?);
        Ok(unpacked)
    } else {
        Ok(buf.to_vec())
    }
}

/// parse a .sig file into FLIRT signatures.
pub fn parse(buf: &[u8]) -> Result<Vec<FlirtSignature>> {
    let mut r = Reader::new(buf);
    let header = header(&mut r)?;

    let inflated;
    let tree = if header.features.contains(Features::COMPRESSED) {
        inflated = inflate(r.buf)?;
        &inflated[..]
    } else {
        r.buf
    };

    let mut sigs = vec![];
    node(&mut Reader::new(tree), &header, &[], &mut sigs)?;
    Ok(sigs)
}
