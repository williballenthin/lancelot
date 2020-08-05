// from: https://github.com/Maktm/FLIRTDB/blob/1f5763535e02d7cccf2f90a96a8ebaa36e9b2495/cmt/windows/libcmt_15_msvc_x86.pat#L355
//
//    3B0D........F27502F2C3F2E9...................................... 00 0000
// 0011 :0000 @__security_check_cookie@4 :000B@ $failure$4 ^0002
// ___security_cookie ^000D ___report_gsfailure    ^^^^        ^^^^^^^^^^^^^^
// bytes        ^^^^^^^^                 relocations
//
//                                                                     00 0000
// 0011                                                                     ^^
// number of bytes crc16'd
// ^^^^ crc16
// ^^^^ size of fn
//
//
// :0000 @__security_check_cookie@4
// ^^^^^ offset of match
// ^^^^^^^^^^^^^^^^^^^^^^^^^^ name
//
//
// :000B@ $failure$4
// ^^^^^^ local offset
// ^^^^^^^^^^ local name
//
//
// ^0002 ___security_cookie
// ^^^^^ reference offset
// ^^^^^^^^^^^^^^^^^^ reference name

use anyhow::Result;
use log::trace;
use nom::{
    branch::alt,
    bytes::complete::{tag, take_till1, take_while, take_while_m_n},
    combinator::{map, map_res, opt, peek},
    multi::{many0, many1},
    sequence::pair,
    IResult,
};
use thiserror::Error;

use super::{ByteSignature, FlirtSignature, Name, Offset, SigElement, Symbol, TailByte};

#[derive(Debug, Error)]
pub enum PatError {
    #[error("The pattern is not supported")]
    NotSupported,
    #[error("The .pat file is corrupt (or unsupported)")]
    CorruptPatFile,
}

fn whitespace(input: &str) -> IResult<&str, &str> {
    take_while(|c| c == ' ')(input)
}

fn is_hex_digit(c: char) -> bool {
    c.is_digit(16)
}

fn from_hex(input: &str) -> Result<u8, std::num::ParseIntError> {
    u8::from_str_radix(input, 16)
}

/// parse a single hex byte, like `AB`
fn hex(input: &str) -> IResult<&str, u8> {
    map_res(take_while_m_n(2, 2, is_hex_digit), from_hex)(input)
}

fn hex_byte(input: &str) -> IResult<&str, u8> {
    let (input, v) = hex(input)?;
    Ok((input, v))
}

fn hex_word(input: &str) -> IResult<&str, u16> {
    let (input, v1) = hex(input)?;
    let (input, v2) = hex(input)?;
    let v: u16 = ((v1 as u16) << 8) | (v2 as u16);
    Ok((input, v))
}

/// parse a single byte signature element, which is either a hex byte or a
/// wildcard.
fn sig_element(input: &str) -> IResult<&str, SigElement> {
    alt((map(hex, SigElement::Byte), map(tag(".."), |_| SigElement::Wildcard)))(input)
}

/// parse byte signature elements, hex or wildcard.
fn byte_signature(input: &str) -> IResult<&str, ByteSignature> {
    let (input, elems) = many1(sig_element)(input)?;
    Ok((input, ByteSignature(elems)))
}

/// parse a hex-encoded offset, like `0000`
/// max is 0x8000.
/// TODO: this can be negative.
fn hex_offset(input: &str) -> IResult<&str, u16> {
    hex_word(input)
}

/// parse a public offset, like `:0000`
fn public_offset(input: &str) -> IResult<&str, u16> {
    let (input, _) = tag(":")(input)?;
    let (input, offset) = hex_offset(input)?;
    let (input, _) = peek(tag(" "))(input)?;

    Ok((input, offset))
}

/// parse a local offset, like `:000B@`
fn local_offset(input: &str) -> IResult<&str, u16> {
    let (input, _) = tag(":")(input)?;
    let (input, offset) = hex_offset(input)?;
    let (input, _) = tag("@")(input)?;

    Ok((input, offset))
}

/// parse an external reference, like `^0002`
fn reference_offset(input: &str) -> IResult<&str, u16> {
    let (input, _) = tag("^")(input)?;
    let (input, offset) = hex_offset(input)?;

    Ok((input, offset))
}

fn offset(input: &str) -> IResult<&str, Offset> {
    alt((
        // this must go first, because it has trailing `@`,
        // otherwise, the same as public.
        map(local_offset, Offset::Local),
        map(public_offset, Offset::Public),
        map(reference_offset, Offset::Reference),
    ))(input)
}

fn symbol_name(input: &str) -> IResult<&str, &str> {
    take_till1(|c| c == ' ' || c == '\n')(input)
}

/// parse a (offset, symbol) pair.
///
/// note: this also consumes trailing spaces so that a sequence of these can be
/// easily parsed.
fn symbol(input: &str) -> IResult<&str, Symbol> {
    let (input, offset) = offset(input)?;
    let (input, _) = whitespace(input)?;
    let (input, name) = symbol_name(input)?;
    let (input, _) = opt(whitespace)(input)?;
    match offset {
        Offset::Public(v) => Ok((
            input,
            Symbol::Public(Name {
                name:   name.to_string(),
                offset: v as i64,
            }),
        )),
        Offset::Local(v) => Ok((
            input,
            Symbol::Local(Name {
                name:   name.to_string(),
                offset: v as i64,
            }),
        )),
        Offset::Reference(v) => Ok((
            input,
            Symbol::Reference(Name {
                name:   name.to_string(),
                offset: v as i64,
            }),
        )),
    }
}

fn symbols(input: &str) -> IResult<&str, Vec<Symbol>> {
    many1(symbol)(input)
}

// like: `(0012: 87)`
fn tail_byte(input: &str) -> IResult<&str, TailByte> {
    let (input, _) = tag("(")(input)?;
    let (input, offset) = hex_offset(input)?;
    let (input, _) = whitespace(input)?;
    let (input, value) = hex_byte(input)?;
    let (input, _) = tag(")")(input)?;

    Ok((
        input,
        TailByte {
            offset: offset as u64,
            value,
        },
    ))
}

fn tail_bytes(input: &str) -> IResult<&str, Vec<TailByte>> {
    match opt(many1(tail_byte))(input)? {
        (input, Some(tail_bytes)) => Ok((input, tail_bytes)),
        (input, None) => Ok((input, vec![])),
    }
}

fn pat_signature(input: &str) -> IResult<&str, FlirtSignature> {
    let (input, byte_sig) = byte_signature(input)?;
    let (input, _) = whitespace(input)?;
    trace!("sig: {:?}", byte_sig);

    let (input, size_of_bytes_crc16) = hex_byte(input)?;
    let (input, _) = whitespace(input)?;
    trace!("crc16 len: {:02x}", size_of_bytes_crc16);

    let (input, crc16) = hex_word(input)?;
    let (input, _) = whitespace(input)?;
    trace!("crc16: {:04x}", crc16);

    let (input, size_of_function) = hex_word(input)?;
    let (input, _) = whitespace(input)?;
    trace!("function size: {:04x}", size_of_function);

    let (input, names) = symbols(input)?;
    trace!("names: {:?}", names);

    // i'm not sure which of these comes first, footer pattern or tail bytes.
    // are they both actually valid in a .pat file!?!
    // pat.txt only describes the footer pattern (which it calls "tail bytes").
    // whereas the .sig file format uses (offset, value) tuples for tail bytes,
    // and dumpsig.exe uses a format like `(AAAA: BB)` for these.

    let (input, _) = opt(whitespace)(input)?;
    let (input, footer) = opt(byte_signature)(input)?;
    trace!("footer: {:?}", footer);

    let (input, _) = opt(whitespace)(input)?;
    let (input, tail_bytes) = tail_bytes(input)?;
    trace!("tail bytes: {:02x?}", tail_bytes);

    Ok((
        input,
        FlirtSignature {
            byte_sig,
            size_of_bytes_crc16,
            crc16,
            size_of_function: size_of_function as u64,
            names,
            footer,
            tail_bytes,
        },
    ))
}

/// parse a .pat file into FLIRT signatures.
fn pat(input: &str) -> IResult<&str, Vec<FlirtSignature>> {
    // each signature is newline separated.
    // drop the newline after we've parsed it.
    let pat_sig_line = map(pair(pat_signature, alt((tag("\r\n"), tag("\n")))), |p| p.0);
    let (input, sigs) = many0(pat_sig_line)(input)?;

    // the file ends with `---`.
    let (input, _) = tag("---")(input)?;

    // TODO: assert there is nothing left in the file

    Ok((input, sigs))
}

/// ```
/// use flirt::pat;
/// let pat_buf = "3B0D........F27502F2C3F2E9...................................... 00 0000 0011 :0000 @__security_check_cookie@4 :000B@ $failure$4 ^0002 ___security_cookie ^000D ___report_gsfailure\n---";
/// assert_eq!(pat::parse(pat_buf).unwrap().len(), 1);
/// ```
pub fn parse(buf: &str) -> Result<Vec<FlirtSignature>> {
    if let Ok((_, sigs)) = pat(buf) {
        Ok(sigs)
    } else {
        Err(PatError::CorruptPatFile.into())
    }
}
