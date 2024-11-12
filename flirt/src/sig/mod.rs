#![allow(clippy::nonstandard_macro_braces)] // clippy bug, see https://github.com/rust-lang/rust-clippy/issues/7434

use anyhow::Result;
use log::trace;
use nom::{
    branch::alt,
    bytes::complete::{tag, take, take_while},
    combinator::peek,
    number::complete::{be_u16, be_u8, le_u16, le_u32, le_u8},
    IResult,
};
use thiserror::Error;

use super::{FlirtSignature, TailByte};
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

bitflags! {
    struct Features: u16 {
        const STARTUP        = 0b0000_0001;
        const CTYPE_CRC      = 0b0000_0010;
        const TWO_BYTE_CTYPE = 0b0000_0100;
        const ALT_CTYPE_CRC  = 0b0000_1000;
        const COMPRESSED     = 0b0001_0000;
        const CTYPE_CRC_3V   = 0b0010_0000;
    }
}

#[allow(dead_code)]
#[derive(Debug)]
enum HeaderExtra {
    V5,
    V6_7 {
        functions_count: u32,
    },
    V8_9 {
        functions_count: u32,
        pattern_size:    u16,
    },
    V10 {
        functions_count: u32,
        pattern_size:    u16,
        unknown:         u16,
    },
}

impl HeaderExtra {
    /// get the size of this structure in bytes.
    fn get_size(&self) -> usize {
        match self {
            HeaderExtra::V5 | HeaderExtra::V6_7 { .. } => 4,
            HeaderExtra::V8_9 { .. } => 6,
            HeaderExtra::V10 { .. } => 8,
        }
    }
}

#[allow(dead_code)]
#[derive(Debug)]
struct Header {
    // offset 6
    version:      u8,
    // offset 7
    arch:         u8,
    // offset 8
    file_types:   u32,
    // offset 0xC
    os_types:     u16,
    // offset 0xE
    app_types:    u16,
    // offset: 0x10
    features:     Features,
    // offset: 0x14
    crc16:        u16,
    // offset: 0x23
    ctypes_crc16: u16,
    // offset 0x25
    extra:        HeaderExtra,
    library_name: String,
}

impl Header {
    fn get_size(&self) -> usize {
        0x25 + self.extra.get_size() + self.library_name.len()
    }

    fn get_pattern_size(&self) -> u16 {
        match self.extra {
            HeaderExtra::V5 => 32,
            HeaderExtra::V6_7 { .. } => 32,
            HeaderExtra::V8_9 { pattern_size, .. } => pattern_size,
            HeaderExtra::V10 { pattern_size, .. } => pattern_size,
        }
    }
}

fn utf8(input: &[u8], size: u16) -> IResult<&[u8], String> {
    let (input, s) = take(size)(input)?;
    let s = String::from_utf8(s.to_vec()).expect("invalid string");
    Ok((input, s))
}

fn header(input: &[u8]) -> IResult<&[u8], Header> {
    let (input, _) = tag(b"IDASGN")(input)?;

    let (input, version) = alt((
        tag(b"\x0A"),
        tag(b"\x09"),
        tag(b"\x08"),
        tag(b"\x07"),
        tag(b"\x06"),
        tag(b"\x05"),
    ))(input)?;
    let version = version[0];

    let (input, arch) = le_u8(input)?;
    let (input, file_types) = le_u32(input)?;
    let (input, os_types) = le_u16(input)?;
    let (input, app_types) = le_u16(input)?;
    let (input, features) = le_u16(input)?;
    let (input, _) = le_u16(input)?;
    let (input, crc16) = le_u16(input)?;
    let (input, _) = take(12u8)(input)?;
    let (input, library_name_length) = le_u8(input)?;
    let (input, ctypes_crc16) = le_u16(input)?;

    let (input, extra) = match version {
        5 => (input, HeaderExtra::V5),
        6 | 7 => {
            let (input, functions_count) = le_u32(input)?;
            (input, HeaderExtra::V6_7 { functions_count })
        }
        8 | 9 => {
            let (input, functions_count) = le_u32(input)?;
            let (input, pattern_size) = le_u16(input)?;
            (
                input,
                HeaderExtra::V8_9 {
                    functions_count,
                    pattern_size,
                },
            )
        }
        10 => {
            let (input, functions_count) = le_u32(input)?;
            let (input, pattern_size) = le_u16(input)?;
            let (input, unknown) = le_u16(input)?;
            (
                input,
                HeaderExtra::V10 {
                    functions_count,
                    pattern_size,
                    unknown,
                },
            )
        }
        _ => unimplemented!(),
    };

    let (input, library_name) = utf8(input, library_name_length as u16)?;

    Ok((
        input,
        Header {
            version,
            arch,
            file_types,
            os_types,
            app_types,
            features: Features::from_bits(features).expect("invalid features"),
            crc16,
            ctypes_crc16,
            extra,
            library_name,
        },
    ))
}

/// unpack a variable-length integer with max range 16 bits.
fn vint16(input: &[u8]) -> IResult<&[u8], u16> {
    let (input, high) = be_u8(input)?;
    let high: u16 = high as u16;

    if (high & 0x80) != 0x80 {
        Ok((input, high))
    } else {
        let (input, low) = be_u8(input)?;
        let low: u16 = low as u16;
        Ok((input, low + ((high & 0x7F) << 8)))
    }
}

/// unpack a variable-length integer with max range 32 bits.
fn vint32(input: &[u8]) -> IResult<&[u8], u32> {
    let (input, b) = be_u8(input)?;

    if (b & 0x80) != 0x80 {
        return Ok((input, b as u32));
    }

    if (b & 0xC0) != 0xC0 {
        let (input, low) = be_u8(input)?;
        let (high, low) = (b as u32, low as u32);
        return Ok((input, ((high & 0x7F) << 8) + low));
    }

    if (b & 0xE0) != 0xE0 {
        let (input, mid) = be_u8(input)?;
        let (input, low) = be_u16(input)?;
        let (high, mid, low) = (b as u32, mid as u32, low as u32);

        Ok((input, ((((high & 0x3F) << 8) + mid) << 16) + low))
    } else {
        let (input, high) = be_u16(input)?;
        let (input, low) = be_u16(input)?;
        let (high, low) = (high as u32, low as u32);

        Ok((input, (high << 16) + low))
    }
}

/// unpack a variable-length integer with max range 16 bits into a 64 bit
/// number. this is a utility routine for code that must parse into a common
/// number type.
fn vint16_64(input: &[u8]) -> IResult<&[u8], u64> {
    let (input, v) = vint16(input)?;
    let v = v as u64;
    Ok((input, v))
}

/// unpack a variable-length integer with max range 16 bits into a 64 bit
/// number. this is a utility routine for code that must parse into a common
/// number type.
fn vint32_64(input: &[u8]) -> IResult<&[u8], u64> {
    let (input, v) = vint32(input)?;
    let v = v as u64;
    Ok((input, v))
}

/// as of version 10, many fields are now v32 instead of v16.
/// this is a utility method for picking the appropriate unpacker.
fn vword<'a>(input: &'a [u8], header: &Header) -> IResult<&'a [u8], u64> {
    if header.version < 9 {
        vint16_64(input)
    } else {
        vint32_64(input)
    }
}

/// return the number of bits set in the given u64.
///
/// note: only supports up to 64 bits.
/// returns u16 to match `.length` field.
fn count_bits(v: u64) -> u16 {
    let mut count = 0u8;
    for i in 0..64 {
        if ((1u64 << i) & v) != 0 {
            count += 1;
        }
    }
    count as u16
}

/// read a wildcard mask for a subpattern with the given length.
///
/// when a bit is set in the mask, then its considered a wildcard.
/// otherwise, a byte literal is used.
fn wildcard_mask(input: &[u8], length: u16) -> IResult<&[u8], u64> {
    Ok(if length == 0 {
        (input, 0u64)
    } else if length < 0x10 {
        vint16_64(input)?
    } else if length <= 0x20 {
        vint32_64(input)?
    } else if length <= 0x40 {
        let (input, high) = vint32_64(input)?;
        let (input, low) = vint32_64(input)?;
        (input, (high << 32) | low)
    } else {
        // dumpsig does support this, but we don't, yet.
        panic!("mask size too large");
    })
}

bitflags! {
    struct ParsingFlags: u8 {
        const MORE_PUBLIC_NAMES = 0b0000_0001;
        const TAIL_BYTES = 0b0000_0010;
        const REFERENCED_FUNCTIONS = 0b0000_0100;
        const MORE_MODULES_WITH_SAME_CRC = 0b0000_1000;
        const MORE_MODULES = 0b0001_0000;
    }
}

bitflags! {
    struct NameFlags: u8 {
        const UNK1  = 0b0000_0001;
        const LOCAL = 0b0000_0010;
        const UNK2  = 0b0000_0100;
        const UNRESOLVED_COLLISION = 0b0000_1000;
        const NEGATIVE_OFFSET = 0b0001_0000;
    }
}

fn parsing_flags(input: &[u8]) -> IResult<&[u8], ParsingFlags> {
    let (input, b) = be_u8(input)?;
    Ok((input, ParsingFlags::from_bits(b).expect("invalid parsing flags")))
}

/// parse a tail byte definition.
///
/// a tail byte differentiates two (or more) otherwise identical functions
/// by specifying the first byte that differs.
fn tail_bytes<'a>(input: &'a [u8], header: &Header) -> IResult<&'a [u8], Vec<TailByte>> {
    let (input, count) = if header.version < 8 {
        (input, 1)
    } else {
        vword(input, header)?
    };

    let mut ret = vec![];
    let mut input = input;

    // seems like a bug in clippy to warn on this
    #[allow(clippy::same_item_push)]
    for _ in 0..count {
        // this offset is relative to the start of the function.
        // it is *not* relative to the prior offset.
        let (input_, offset) = vword(input, header)?;
        let (input_, value) = be_u8(input_)?;

        ret.push(TailByte { offset, value });
        input = input_;
    }

    Ok((input, ret))
}

#[derive(Debug)]
struct ReferencedName {
    offset: u64,
    name:   String,
}

/// parse a referenced name definition.
///
/// a referenced name is a pointer within the function body to another named
/// function. i'm not yet sure if this is used to match the current function, to
/// differentiate it, or propagate the referenced name to the other function.
/// i think its probably the former.
///
/// note: i'm not yet sure how the pointer itself will be encoded. is it always
/// a global offset?
fn referenced_names<'a>(input: &'a [u8], header: &Header) -> IResult<&'a [u8], Vec<ReferencedName>> {
    let (input, count) = if header.version < 8 {
        (input, 1)
    } else {
        vword(input, header)?
    };

    let mut ret = vec![];
    let mut input = input;
    // seems like a bug in clippy to warn on this
    #[allow(clippy::same_item_push)]
    for _ in 0..count {
        // this offset is relative to the start of the function.
        // it is *not* relative to the prior offset.
        let (input_, offset) = vword(input, header)?;

        let (input_, size) = be_u8(input_)?;

        // when size is zero, then read a vint16 with the true size.
        let (input_, size) = if size == 0x0 {
            let (input_, size) = vint16(input_)?;
            (input_, size)
        } else {
            (input_, size as u16)
        };

        let (input_, name) = utf8(input_, size)?;

        ret.push(ReferencedName { offset, name });
        input = input_;
    }

    Ok((input, ret))
}

#[derive(Debug)]
struct Name {
    offset: i64,
    flags:  NameFlags,
    name:   String,
}

/// parse a name definition.
///
/// this is a name that can be set for functions that match the current rule.
/// usually, they are found at relative offset 0x0 from the rule match,
/// but its possible for this offset to be non-zero.
/// apparently its possible to specify a negative offset, but that's not
/// supported here.
fn name<'a>(input: &'a [u8], header: &Header, base_offset: i64) -> IResult<&'a [u8], (Name, ParsingFlags)> {
    let (input, relative_offset) = vword(input, header)?;

    // note: this field is only optionally present.
    // it is present if the value of the byte is less than 0x20.
    // otherwise, expect to parse the name as ASCII.
    let (input, name_flags) = if peek(be_u8)(input)?.1 < 0x20 {
        be_u8(input)?
    } else {
        (input, 0u8)
    };
    let name_flags = NameFlags::from_bits(name_flags).expect("invalid name flags");

    // offset was parsed before, but can be interpreted only after name_flags.
    let offset = if name_flags.intersects(NameFlags::NEGATIVE_OFFSET) {
        base_offset - (relative_offset as i64)
    } else {
        base_offset + (relative_offset as i64)
    };

    let (input, s) = take_while(|b| b >= 0x20)(input)?;
    let pname = String::from_utf8(s.to_vec()).expect("invalid name");

    let (input, pflags) = parsing_flags(input)?;

    Ok((
        input,
        (
            Name {
                offset,
                flags: name_flags,
                name: pname,
            },
            pflags,
        ),
    ))
}

fn leaf<'a>(input: &'a [u8], header: &Header, prefix: Vec<SigElement>) -> IResult<&'a [u8], Vec<FlirtSignature>> {
    let mut flags: ParsingFlags;
    let mut input = input;
    let mut ret = vec![];

    loop {
        // module

        let (input_, crc_len) = be_u8(input)?;
        input = input_;
        let (input_, crc) = be_u16(input)?;
        input = input_;
        trace!("crc: {:02x} {:04x}", crc_len, crc);

        loop {
            // module with crc
            let mut offset = 0i64;

            let (input_, function_size) = vword(input, header)?;
            input = input_;
            trace!("size: {:04x}", function_size);

            let mut names = vec![];

            loop {
                // name

                let (input_, (name, flags_)) = name(input, header, offset)?;
                input = input_;
                offset = name.offset;
                flags = flags_;
                trace!("name: {:x?}", name);
                trace!("flags: {:?}", flags);

                if name.flags.intersects(NameFlags::LOCAL) {
                    names.push(super::Symbol::Local(super::Name {
                        offset: name.offset,
                        name:   name.name,
                    }));
                } else {
                    names.push(super::Symbol::Public(super::Name {
                        offset: name.offset,
                        name:   name.name,
                    }));
                }

                if !flags.intersects(ParsingFlags::MORE_PUBLIC_NAMES) {
                    break;
                };
            }

            let (input_, tbytes) = if flags.intersects(ParsingFlags::TAIL_BYTES) {
                tail_bytes(input, header)?
            } else {
                (input, vec![])
            };
            if !tbytes.is_empty() {
                trace!("tail bytes: {:x?}", tbytes);
            }
            input = input_;

            if flags.intersects(ParsingFlags::REFERENCED_FUNCTIONS) {
                let (input_, ref_names) = referenced_names(input, header)?;
                input = input_;
                trace!("references: {:x?}", ref_names);

                for ref_name in ref_names.into_iter() {
                    names.push(super::Symbol::Reference(super::Name {
                        offset: ref_name.offset as i64,
                        name:   ref_name.name,
                    }));
                }
            }

            ret.push(FlirtSignature {
                byte_sig_size: header.get_pattern_size(),
                byte_sig: ByteSignature(prefix.clone()),
                size_of_bytes_crc16: crc_len,
                crc16: crc,
                size_of_function: function_size,
                names,
                footer: None,
                tail_bytes: tbytes,
            });

            if !flags.intersects(ParsingFlags::MORE_MODULES_WITH_SAME_CRC) {
                break;
            };
        }

        if !flags.intersects(ParsingFlags::MORE_MODULES) {
            break;
        };
    }

    Ok((input, ret))
}

/// prefix_length: number of pattern bytes covered by parent nodes.
fn node<'a>(input: &'a [u8], header: &Header, prefix: Vec<SigElement>) -> IResult<&'a [u8], Vec<FlirtSignature>> {
    let (input, child_count) = vint16(input)?;
    let mut input = input;
    let mut ret = vec![];

    trace!("child count: {:#x}", child_count);

    if child_count == 0 {
        return leaf(input, header, prefix);
    }

    for _ in 0..child_count {
        let (input_, length) = if header.version < 10 {
            let (input, length) = be_u8(input)?;
            (input, length as u16)
        } else {
            vint16(input)?
        };
        input = input_;
        trace!("length: {:#x}", length);

        let (input_, mask) = wildcard_mask(input, length)?;
        input = input_;
        trace!("wildcard_mask: {:#x}", mask);

        let remaining_bytes = length - count_bits(mask);
        let (input_, byte_literals) = take(remaining_bytes)(input)?;
        input = input_;
        trace!("byte_literals: {:02x?}", byte_literals);

        // expected pattern:
        //  literals:  1D........0F59D80F2825........0F280D........660F5BD30F283D
        //  mask:       0 1 1 1 1 0 0 0 0 0 0 1 1 1 1 0 0 0 1 1 1 1 0 0 0 0 0 0 0
        //              01111000000111100011110000000 == 0xf03c780
        //  bits set:  0xC
        //  remaining: (0x1D - 0xC) = 0x11 = number of literals
        //
        // got bytes:
        //   1D CF 03 C7 80 1D 0F 59 D8 0F 28 25 0F 28 0D 66 0F 5B D3 0F 28 3D
        //   -- ----------- --------------------------------------------------
        //      0xf03c780

        let mut pattern = Vec::with_capacity(prefix.len() + length as usize);
        pattern.extend(prefix.iter());

        let mut j: usize = remaining_bytes as usize;
        for i in 0..length as u64 {
            if (mask & (1 << i)) > 0 {
                pattern.push(SigElement::Wildcard)
            } else {
                pattern.push(SigElement::Byte(byte_literals[j - 1]));
                j -= 1;
            }
        }

        // we have:
        //  [ prefix1 prefix2   C B A ]
        // and we need to reverse the current pattern to end up like:
        //  [ prefix1 prefix2   A B C ]
        pattern[prefix.len()..].reverse();

        let (input_, sigs) = node(input, header, pattern)?;
        input = input_;
        ret.extend(sigs.into_iter());
    }

    Ok((input, ret))
}

/// parse an (unpacked) .sig file into FLIRT signatures.
///
/// see `unpack_sig`.
fn sig(input: &[u8]) -> Result<Vec<FlirtSignature>> {
    //nom::util::dbg_dmp(...);
    let (input, header) = match header(input) {
        Err(_) => return Err(SigError::CorruptSigFile.into()),
        Ok((input, header)) => (input, header),
    };

    trace!("header: {:#?}", header);

    let (_input, sigs) = match node(input, &header, vec![]) {
        Err(_) => return Err(SigError::CorruptSigFile.into()),
        Ok((input, sigs)) => (input, sigs),
    };

    Ok(sigs)
}

pub fn unpack_sig(input: &[u8]) -> Result<Vec<u8>> {
    match header(input) {
        Ok((compressed, header)) => {
            /*
            println!("{:02x?}", &input[..0x50]);
            println!("{:02x?}", &compressed[..0x50]);
            */

            if header.features.intersects(Features::COMPRESSED) {
                let header_buf = &input[..header.get_size()];
                match inflate::inflate_bytes_zlib(compressed) {
                    Ok(decompressed) => {
                        // stitch together the header with the decompressed payload
                        let mut buf = vec![];
                        buf.extend(header_buf);
                        buf.extend(decompressed);
                        Ok(buf)
                    }
                    Err(e) => {
                        // I've see possible CMF values:
                        //  0xC4 - IDA Pro 7.4/sig/pc/bc31cls.sig
                        //  0x0C - IDA Pro 7.4/sig/pc/bc15owl
                        //  0x05 - IDA Pro 7.4/sig/pc/bc15c2.sig
                        Err(SigError::CompressionNotSupported(e).into())
                    }
                }
            } else {
                Ok(input.to_vec())
            }
        }
        Err(_) => Err(SigError::CorruptSigFile.into()),
    }
}

pub fn parse(buf: &[u8]) -> Result<Vec<FlirtSignature>> {
    sig(&unpack_sig(buf)?)
}
