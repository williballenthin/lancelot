// from: https://github.com/Maktm/FLIRTDB/blob/1f5763535e02d7cccf2f90a96a8ebaa36e9b2495/cmt/windows/libcmt_15_msvc_x86.pat#L355
//
//    3B0D........F27502F2C3F2E9...................................... 00 0000 0011 :0000 @__security_check_cookie@4 :000B@ $failure$4 ^0002 ___security_cookie ^000D ___report_gsfailure
//    ^^^^        ^^^^^^^^^^^^^^   bytes
//        ^^^^^^^^                 relocations
//
//                                                                     00 0000 0011
//                                                                     ^^ number of bytes crc16'd
//                                                                        ^^^^ crc16
//                                                                             ^^^^ size of fn
//
//                                                                                  :0000 @__security_check_cookie@4
//                                                                                  ^^^^^ offset of match
//                                                                                        ^^^^^^^^^^^^^^^^^^^^^^^^^^ name
//
//                                                                                                                   :000B@ $failure$4
//                                                                                                                   ^^^^^^ local offset
//                                                                                                                          ^^^^^^^^^^ local name
//
//                                                                                                                                     ^0002 ___security_cookie
//                                                                                                                                     ^^^^^ reference offset
//                                                                                                                                           ^^^^^^^^^^^^^^^^^^ reference name

use nom::IResult;
use nom::multi::count;
use nom::multi::many1;
use nom::bytes::complete::tag;
use nom::bytes::complete::take;
use nom::bytes::complete::take_while_m_n;
use nom::branch::alt;
use nom::combinator::map;
use nom::combinator::map_res;
use nom::combinator::peek;
use failure::{Error, Fail};

use super::FlirtSignature;


#[derive(Debug, Fail)]
pub enum PatError {
    #[fail(display = "The pattern is not supported")]
    NotSupported,
    #[fail(display = "foo")]
    Foo,
}


fn is_hex_digit(c: char) -> bool {
  c.is_digit(16)
}

fn from_hex(input: &str) -> Result<u8, std::num::ParseIntError> {
  u8::from_str_radix(input, 16)
}

/// parse a single hex byte, like `AB`
fn hex(input: &str) -> IResult<&str, u8> {
    map_res(
        take_while_m_n(2, 2, is_hex_digit),
        from_hex
    )(input)
}

fn u8le(input: &str) -> IResult<&str, u8> {
    let (input, v) = hex(input)?;
    Ok((input, v))
}

fn u16le(input: &str) -> IResult<&str, u16> {
    let (input, v1) = hex(input)?;
    let (input, v2) = hex(input)?;
    let v: u16 = ((v2 as u16) << 2) | (v1 as u16);
    Ok((input, v))
}

#[derive(Debug)]
enum SigElement {
    Byte(u8),
    Wildcard,
}

/// parse a single byte signature element, which is either a hex byte or a wildcard.
fn sig_element(input: &str) -> IResult<&str, SigElement> {
    alt((
        map(
            hex,
            |v| SigElement::Byte(v)
        ),
        map(
            tag(".."),
            |v: &str| SigElement::Wildcard
        )
    ))(input)
}

/// parse 32 byte signature elements, hex or wildcard.
fn byte_signature(input: &str) -> IResult<&str, Vec<SigElement>> {
    // TODO: maybe unroll this
    // TODO: map into ByteSignature
    count(sig_element, 32)(input)
}

fn public_offset(input: &str) -> IResult<&str, u16> {
    let (input, _) = tag(":")(input)?;
    let (input, offset) = u16le(input)?;
    let (input, _) = peek(tag(" "))(input)?;

    Ok((input, offset))
}

fn local_offset(input: &str) -> IResult<&str, u16> {
    let (input, _) = tag(":")(input)?;
    let (input, offset) = u16le(input)?;
    let (input, _) = tag("@")(input)?;

    Ok((input, offset))
}

fn reference_offset(input: &str) -> IResult<&str, u16> {
    let (input, _) = tag("^")(input)?;
    let (input, offset) = u16le(input)?;
    let (input, _) = tag("@")(input)?;

    Ok((input, offset))
}

pub fn _parse(input: &str) -> IResult<&str, ()> {
    let (input, sig) = byte_signature(input)?;
    let (input, _) = many1(tag(" "))(input)?;
    println!("sig: {:?}", sig);

    let (input, size_of_bytes_crc16) = u8le(input)?;
    let (input, _) = many1(tag(" "))(input)?;
    println!("crc16 len: {:02x}", size_of_bytes_crc16);

    let (input, crc16) = u16le(input)?;
    let (input, _) = many1(tag(" "))(input)?;
    println!("crc16: {:04x}", crc16);

    let (input, fnsize) = u16le(input)?;
    let (input, _) = many1(tag(" "))(input)?;
    println!("function size: {:04x}", fnsize);

    Ok((input, ()))
}


/// ```
/// use flirt::pat;
/// pat::parse("3B0D........F27502F2C3F2E9...................................... 00 0000 0011 :0000 @__security_check_cookie@4 :000B@ $failure$4 ^0002 ___security_cookie ^000D ___report_gsfailure");
///
/// assert!(false);
/// ```
pub fn parse(buf: &str) -> Result<(), Error> {
    println!("{:?}", _parse(buf));

    Err(PatError::Foo.into())
}



