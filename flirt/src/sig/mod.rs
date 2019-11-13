use log::{debug, error};
use nom::IResult;
use nom::bytes::complete::{tag, take_while};
use nom::bytes::complete::take;
use nom::number::complete::le_u8;
use nom::number::complete::be_u8;
use nom::number::complete::le_u16;
use nom::number::complete::be_u16;
use nom::number::complete::le_u32;
use nom::combinator::peek;
use nom::branch::alt;
use failure::{Error, Fail};
use bitflags;
use inflate;

use super::{FlirtSignature};

#[derive(Debug, Fail)]
pub enum SigError {
    #[fail(display = "The pattern is not supported")]
    NotSupported,
    #[fail(display = "The .sig file is corrupt (or unsupported)")]
    CorruptSigFile,
}

bitflags! {
    struct Features: u16 {
        const STARTUP = 0b00000001;
        const CTYPE_CRC = 0b00000010;
        const TWO_BYTE_CTYPE = 0b00000100;
        const ALT_CTYPE_CRC = 0b00001000;
        const COMPRESSED = 0b00010000;
        const CTYPE_CRC_3V = 0b00100000;
    }
}

#[derive(Debug)]
enum HeaderExtra {
    V5,
    V6_7 {
        functions_count: u32,
    },
    V8_9 {
        functions_count: u32,
        pattern_size: u16,
    },
    V10 {
        functions_count: u32,
        pattern_size: u16,
        unknown: u16,
    },
}

#[derive(Debug)]
struct Header {
    // offset 6
    version: u8,
    // offset 7
    arch: u8,
    // offset 8
    file_types: u32,
    // offset 0xC
    os_types: u16,
    // offset 0xE
    app_types: u16,
    // offset: 0x10
    features: Features,
    // offset: 0x11
    crc16: u16,
    // offset: 0x13
    ctypes_crc16: u16,
    // offset 0x15
    extra: HeaderExtra,
    library_name: String,
}

fn utf8(input: &[u8], size: u8) -> IResult<&[u8], String> {
    let (input, s) = take(size)(input)?;
    let s = String::from_utf8(s.to_vec()).expect("invalid string");
    Ok((input, s))
}

fn header(input: &[u8]) -> IResult<&[u8], Header> {
    let (input, _) = tag(b"IDASGN")(input)?;

    let (input, version) = alt((
        tag(b"\x0A"),
        tag(b"\x09"),
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
        },
        8 | 9 => {
            let (input, functions_count) = le_u32(input)?;
            let (input, pattern_size) = le_u16(input)?;
            (input, HeaderExtra::V8_9 { functions_count, pattern_size })
        },
        10 => {
            let (input, functions_count) = le_u32(input)?;
            let (input, pattern_size) = le_u16(input)?;
            let (input, unknown) = le_u16(input)?;
            (input, HeaderExtra::V10 { functions_count, pattern_size, unknown })
        }
        _ => unimplemented!(),
    };

    let (input, library_name) = utf8(input, library_name_length)?;

    Ok((input, Header{
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
    }))
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
        return Ok((input, ((((high & 0x3F) << 8) + mid) << 16) + low))
    }

    else {
        let (input, high) = be_u16(input)?;
        let (input, low) = be_u16(input)?;
        let (high, low) = (high as u32, low as u32);
        return Ok((input, (high << 16) + low));
    }
}

/// unpack a variable-length integer with max range 16 bits into a 64 bit number.
/// this is a utility routine for code that must parse into a common number type.
fn vint16_64(input: &[u8]) -> IResult<&[u8], u64> {
    let (input, v) = vint16(input)?;
    let v = v as u64;
    Ok((input, v))
}

/// unpack a variable-length integer with max range 16 bits into a 64 bit number.
/// this is a utility routine for code that must parse into a common number type.
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
        const MORE_PUBLIC_NAMES = 0b00000001;
        const TAIL_BYTES = 0b00000010;
        const REFERENCED_FUNCTIONS = 0b00000100;
        const MORE_MODULES_WITH_SAME_CRC = 0b00001000;
        const MORE_MODULES = 0b00010000;
    }
}

bitflags! {
    struct NameFlags: u8 {
        const UNK1 = 0b00000001;
        const LOCAL = 0b00000010;
        const UNK2 = 0b00000100;
        const UNRESOLVED_COLLISION = 0b00001000;
        const NEGATIVE_OFFSET = 0b00010000;
    }
}

fn parsing_flags(input: &[u8]) -> IResult<&[u8], ParsingFlags> {
    let (input, b) = be_u8(input)?;
    Ok((input, ParsingFlags::from_bits(b).expect("invalid parsing flags")))
}

#[derive(Debug)]
struct TailByte {
    // this can probably be negative?
    offset: u64,
    value: u8,
}

/// parse a tail byte definition.
///
/// a tail byte differentiates two (or more) otherwise identical functions
/// by specifying the first byte that differs.
///
/// note: unknown from where the offset is relative.
/// note: unknown if there can be more than one tail byte (suspected).
fn tail_byte<'a>(input: &'a [u8], header: &Header) -> IResult<&'a [u8], TailByte> {
    // is this really what this means?
    let (input, count) = be_u8(input)?;
    if count > 1 {
        unimplemented!("unexpected tail byte count > 1");
    }

    // TODO: is this relative to the prior offset?
    let (input, offset) = vword(input, header)?;

    let (input, value) = be_u8(input)?;

    Ok((input, TailByte {
        offset,
        value,
    }))
}

#[derive(Debug)]
struct ReferencedName {
    // this can probably be negative?
    offset: u64,
    name: String,
}

/// parse a referenced name definition.
///
/// a referenced name is a pointer within the function body to another named function.
/// i'm not yet sure if this is used to match the current function, to differentiate it,
/// or propagate the referenced name to the other function.
/// i think its probably the former.
///
/// note: i'm not yet sure how the pointer itself will be encoded. is it always a global offset?
///
/// note: unknown from where the offset is relative.
/// note: unknown if there can be more than one (suspected).
fn referenced_names<'a>(input: &'a [u8], header: &Header) -> IResult<&'a [u8], Vec<ReferencedName>> {
    // if version < 8, then this isn't used.
    let (input, count) = vword(input, header)?;
    if count > 1 {
        unimplemented!("unexpected referenced name count > 1");
        // TODO: check the below logic of placing $count into array.
    }

    let mut ret = vec![];
    let mut input = input;
    for _ in 0..count {
        // TODO: is this relative to the prior offset?
        let (input_, offset) = vword(input, header)?;

        let (input_, size) = be_u8(input_)?;

        let (input_, name) = utf8(input_, size)?;

        ret.push(ReferencedName{
            offset,
            name,
        });
        input = input_;
    }

    Ok((input, ret))
}

#[derive(Debug)]
struct Name {
    offset: u64,
    flags: NameFlags,
    name: String,
}

/// parse a name definition.
///
/// this is a name that can be set for functions that match the current rule.
/// usually, they are found at relative offset 0x0 from the rule match,
/// but its possible for this offset to be non-zero.
/// apparently its possible to specify a negative offset, but that's not supported here.
fn name<'a>(input: &'a [u8], header: &Header, base_offset: u64) -> IResult<&'a [u8], (Name, ParsingFlags)> {
    let (input, relative_offset) = vword(input, header)?;
    let offset = base_offset + relative_offset;

    // note: this field is only optionally present.
    let (input, name_flags) = if peek(be_u8)(input)?.1 < 0x20 {
        be_u8(input)?
    } else {
        (input, 0u8)
    };
    let name_flags = NameFlags::from_bits(name_flags).expect("invalid name flags");
    if name_flags.intersects(NameFlags::NEGATIVE_OFFSET) {
        unimplemented!("name negative offset");
    };

    let (input, s) = take_while(|b| b >= 0x20)(input)?;
    let pname = String::from_utf8(s.to_vec()).expect("invalid name");

    let (input, pflags) = parsing_flags(input)?;

    Ok((input, (Name {
        offset,
        flags: name_flags,
        name: pname
    }, pflags)))
}

fn leaf<'a>(input: &'a [u8], header: &Header) -> IResult<&'a [u8], Vec<FlirtSignature>> {
    let mut flags: ParsingFlags;
    let mut input = input;

    loop {
        // module

        let (input_, crc_len) = be_u8(input)?;
        input = input_;
        let (input_, crc) = be_u16(input)?;
        input = input_;
        debug!("crc: {:02x} {:04x}", crc_len, crc);

        loop {
            // module with crc
            let mut offset = 0u64;

            let (input_, function_size) = vword(input, header)?;
            input = input_;
            debug!("size: {:04x}", function_size);

            loop {
                // name

                let (input_, (name, flags_)) = name(input, header, offset)?;
                input = input_;
                offset = name.offset;
                flags = flags_;
                debug!("name: {:x?}", name);

                if ! flags.intersects(ParsingFlags::MORE_PUBLIC_NAMES) { break };
            }

            if flags.intersects(ParsingFlags::TAIL_BYTES) {
                let (input_, tbyte) = tail_byte(input, header)?;
                input = input_;
                debug!("tail byte: {:x?}", tbyte);
            }

            if flags.intersects(ParsingFlags::REFERENCED_FUNCTIONS) {
                let (input_, ref_names) = referenced_names(input, header)?;
                input = input_;
                debug!("references: {:x?}", ref_names);
            }

            if ! flags.intersects(ParsingFlags::MORE_MODULES_WITH_SAME_CRC) { break };
        }

        if ! flags.intersects(ParsingFlags::MORE_MODULES) { break };
    }

    Ok((input, vec![]))
}

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

/// prefix_length: number of pattern bytes covered by parent nodes.
fn node<'a>(input: &'a [u8], header: &Header) -> IResult<&'a [u8], Vec<FlirtSignature>> {
    let (input, child_count) = vint16(input)?;
    let mut input = input;

    debug!("child count: {:#x}", child_count);

    if child_count == 0 {
        return leaf(input, header);
    }

    for _ in 0..child_count {

        let (input_, length) = if header.version < 10 {
            let (input, length) = be_u8(input)?;
            (input, length as u16)
        } else {
            vint16(input)?
        };
        input = input_;
        debug!("length: {:#x}", length);

        let (input_, mask) = wildcard_mask(input, length)?;
        input = input_;
        debug!("wildcard_mask: {:#x}", mask);

        let remaining_bytes = length - count_bits(mask);
        let (input_, byte_literals) = take(remaining_bytes)(input)?;
        input = input_;
        debug!("byte_literals: {:02x?}", byte_literals);

        let (input_, sigs) = node(input, header)?;
        input = input_;
        // TODO: merge sigs together
    }

    // TODO: return sigs
    Ok((input, vec![]))
}

/// parse an (unpacked) .sig file into FLIRT signatures.
///
/// see `unpack_sig`.
fn sig(input: &[u8]) -> Result<Vec<FlirtSignature>, Error> {
    //nom::util::dbg_dmp(...);
    let (input, header) = match header(input) {
        Err(_) => return Err(SigError::CorruptSigFile.into()),
        Ok((input, header)) => (input, header)
    };

    debug!("header: {:#?}", header);

    let (_input, sigs) = match node(input, &header) {
        Err(_) => return Err(SigError::CorruptSigFile.into()),
        Ok((input, sigs)) => (input, sigs)
    };

    Ok(sigs)
}

fn unpack_sig(input: &[u8]) -> Result<Vec<u8>, Error> {
    if let Ok((payload, header)) = header(input) {
        if header.features.intersects(Features::COMPRESSED) {
            match inflate::inflate_bytes_zlib(payload) {
                Ok(buf) => {
                    // TODO: need to stitch the header buf back on
                    Ok(buf)
                },
                Err(e) => {
                    error!("error: {:?}", e);
                    Err(SigError::CorruptSigFile.into())
                }
            }
        } else {
            Ok(input.to_vec())
        }
    } else {
        Err(SigError::CorruptSigFile.into())
    }
}

pub fn parse(buf: &[u8]) -> Result<Vec<FlirtSignature>, Error> {
    sig(&unpack_sig(buf)?)
}
