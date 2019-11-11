use log::{debug};
use nom::IResult;
use nom::bytes::complete::tag;
use nom::bytes::complete::take;
use nom::number::complete::le_u8;
use nom::number::complete::le_u16;
use nom::number::complete::le_u32;
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
    version: u8,
    arch: u8,
    file_types: u32,
    os_types: u16,
    app_types: u16,
    features: Features,
    crc16: u16,
    ctypes_crc16: u16,
    extra: HeaderExtra,
    library_name: String,
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

    let (input, library_name) = take(library_name_length)(input)?;
    let library_name = String::from_utf8(library_name.to_vec()).expect("invalid library name");

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

/// parse a .sig file into FLIRT signatures.
fn sig(input: &[u8]) -> IResult<&[u8], Vec<FlirtSignature>> {
    //nom::util::dbg_dmp(...);
    let (input, header) = header(input)?;

    debug!("header: {:#?}", header);

    let buf;
    let payload = if header.features.intersects(Features::COMPRESSED) {
        buf = inflate::inflate_bytes_zlib(input).expect("failed to inflate");
        &buf
    } else {
        input
    };
    // TODO: figure out owned/unowned here
    let input = &input[input.len() - 1..];

    Ok((input, vec![]))
}

pub fn parse(buf: &[u8]) -> Result<Vec<FlirtSignature>, Error> {
    if let Ok((_, sigs)) = sig(buf) {
        Ok(sigs)
    } else {
        Err(SigError::CorruptSigFile.into())
    }
}
