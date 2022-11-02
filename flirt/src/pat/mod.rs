#![allow(clippy::nonstandard_macro_braces)] // clippy bug, see https://github.com/rust-lang/rust-clippy/issues/7434

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

fn is_not_newline(c: char) -> bool {
    c != '\r' && c != '\n'
}

fn is_hex_digit(c: char) -> bool {
    c.is_ascii_hexdigit()
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

/// at least four hex characters, but maybe more, and can be an odd number.
/// see test `test_large_function`.
fn hex_word_plus(input: &str) -> IResult<&str, u64> {
    let (input, nibbles) = take_while(is_hex_digit)(input)?;
    let mut v = 0u64;
    let nibbles = nibbles.chars().map(|c| match c {
        '0' => 0,
        '1' => 1,
        '2' => 2,
        '3' => 3,
        '4' => 4,
        '5' => 5,
        '6' => 6,
        '7' => 7,
        '8' => 8,
        '9' => 9,
        'A' | 'a' => 0xA,
        'B' | 'b' => 0xB,
        'C' | 'c' => 0xC,
        'D' | 'd' => 0xD,
        'E' | 'e' => 0xE,
        'F' | 'f' => 0xF,
        _ => panic!("unexpect hex digit"),
    });

    for nibble in nibbles {
        v <<= 4;
        v |= nibble as u64;
    }

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
/// this value can be greater than one word. if so, it does not necessarily have
/// an even number of digits. TODO: this can be negative.
fn hex_offset(input: &str) -> IResult<&str, u64> {
    hex_word_plus(input)
}

/// parse a public offset, like `:0000`
fn public_offset(input: &str) -> IResult<&str, u64> {
    let (input, _) = tag(":")(input)?;
    let (input, offset) = hex_offset(input)?;
    let (input, _) = peek(tag(" "))(input)?;

    Ok((input, offset))
}

/// parse a local offset, like `:000B@`
fn local_offset(input: &str) -> IResult<&str, u64> {
    let (input, _) = tag(":")(input)?;
    let (input, offset) = hex_offset(input)?;
    let (input, _) = tag("@")(input)?;

    Ok((input, offset))
}

/// parse an external reference, like `^0002`
fn reference_offset(input: &str) -> IResult<&str, u64> {
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
    let (input, _) = tag(":")(input)?;
    let (input, _) = whitespace(input)?;
    let (input, value) = hex_byte(input)?;
    let (input, _) = tag(")")(input)?;

    Ok((input, TailByte { offset, value }))
}

fn tail_bytes(input: &str) -> IResult<&str, Vec<TailByte>> {
    match opt(many1(pair(tail_byte, opt(tag(" ")))))(input)? {
        (input, Some(tail_bytes)) => Ok((input, tail_bytes.into_iter().map(|p| p.0).collect())),
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

    let (input, size_of_function) = hex_word_plus(input)?;
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
            byte_sig_size: 32, // TODO: fixme, this is not static
            byte_sig,
            size_of_bytes_crc16,
            crc16,
            size_of_function,
            names,
            footer,
            tail_bytes,
        },
    ))
}

fn comment(input: &str) -> IResult<&str, ()> {
    // comments are an extension of the .pat file format
    // but enable us to provide a header with license information.
    let (input, _) = tag("#")(input)?;
    let (input, _) = take_while(is_not_newline)(input)?;

    Ok((input, ()))
}

fn line(input: &str) -> IResult<&str, Option<FlirtSignature>> {
    if let Ok((input, _)) = comment(input) {
        return Ok((input, None));
    }

    match pat_signature(input) {
        Ok((input, sig)) => Ok((input, Some(sig))),
        Err(e) => Err(e),
    }
}

/// parse a .pat file into FLIRT signatures.
fn pat(input: &str) -> IResult<&str, Vec<FlirtSignature>> {
    // each signature is newline separated.
    // drop the newline after we've parsed it.
    let maybe_pat = map(pair(line, alt((tag("\r\n"), tag("\n")))), |p| p.0);
    let (input, sigs) = many0(maybe_pat)(input)?;

    // the file ends with `---`.
    let (input, _) = tag("---")(input)?;

    // TODO: assert there is nothing left in the file

    Ok((input, sigs.into_iter().flatten().collect()))
}

/// ```
/// use lancelot_flirt::pat;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pat_parse() {
        parse("---").unwrap();

        parse("\
3B0D........F27502F2C3F2E9...................................... 00 0000 0011 :0000 @__security_check_cookie@4 :000B@ $failure$4 ^0002 ___security_cookie ^000D ___report_gsfailure
---
        ").unwrap();

        parse(
            "\
# foo
---
        ",
        )
        .unwrap();

        parse("\
# foo
3B0D........F27502F2C3F2E9...................................... 00 0000 0011 :0000 @__security_check_cookie@4 :000B@ $failure$4 ^0002 ___security_cookie ^000D ___report_gsfailure
---
        ").unwrap();
    }

    #[test]
    fn test_pat_tail_bytes() {
        parse("\
0330020028000000000000007f........16547f........1a5816547f 00 0000 0034 :0000 ???__E??_R3?$_Iosb@H@std@@8@@YMXXZ@?A0x7094697c@@$$FYMXXZ ^000d 040002DD (0003: 17)
0330020028000000000000007f........16547f........1a5816547f 00 0000 0034 :0000 ???__E??_R3?$_Iosb@H@std@@8@@YMXXZ@?A0xb8f7dd2a@@$$FYMXXZ ^000d 040002EB (0003: 17)
---
        ").unwrap();

        parse("\
033002004b000000000000007f........7f........547f........1a581654 01 087b 0057 :0000 ???__E??_R17?0A@EA@?$_Iosb@H@std@@8@@YMXXZ@?A0x4b1bc67a@@$$FYMXXZ ^0012 040001BF (0006: 1E) (0010: 15)
---
        ").unwrap();
    }

    #[test]
    fn test_large_function() {
        // large function size field
        parse(
            "\
3c14a918d430e77901b6ed5ffc95ba75102562772b73fb79c65537a5765f9018 ff 3041 2989a :0000 foo
---
        ",
        )
        .unwrap();

        // large name offset
        parse("\
3c14a918d430e77901b6ed5ffc95ba75102562772b73fb79c65537a5765f9018 ff 3041 2989a :0000 ecp_nistz256_precomputed :25100 ecp_nistz256_mul_by_2 :251a0 ecp_nistz256_div_by_2 :25280 ecp_nistz256_mul_by_3 :25380 ecp_nistz256_add :25420 ecp_nistz256_sub :254c0 ecp_nistz256_neg :25560 ecp_nistz256_ord_mul_mont :258e0 ecp_nistz256_ord_sqr_mont :26300 ecp_nistz256_to_mont :26340 ecp_nistz256_mul_mont :26640 ecp_nistz256_sqr_mont :26ce0 ecp_nistz256_from_mont :26e00 ecp_nistz256_scatter_w5 :26e60 ecp_nistz256_gather_w5 :26fc0 ecp_nistz256_scatter_w7 :27000 ecp_nistz256_gather_w7 :272a0 ecp_nistz256_avx2_gather_w7 :27580 ecp_nistz256_point_double :278c0 ecp_nistz256_point_add :28020 ecp_nistz256_point_add_affine
---
        ").unwrap();
    }
}
