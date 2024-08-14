/// ## purpose
/// to match multiple byte patterns against a byte slice in parallel.
/// we should get all valid matches at the end.
/// does not have to support scanning across the byte slice, only anchored at
/// the start. need support for single character wild cards (`.`).
///
/// implemented via [RegexSet](https://docs.rs/regex/1.3.9/regex/struct.RegexSet.html)
///
/// > Match multiple (possibly overlapping) regular expressions in a single
/// > scan.
/// > A regex set corresponds to the union of two or more regular expressions.
/// > That is, a regex set will match text where at least one of its constituent
/// > regular expressions matches. A regex set as its formulated here provides a
/// > touch more power:  it will also report which regular expressions in the
/// > set match. Indeed, this is the key difference between regex sets and a
/// > single Regex with many alternates, since only one alternate can match at a
/// > time.
use anyhow::Result;
use nom::{
    branch::alt,
    bytes::complete::{tag, take_while_m_n},
    combinator::{map, map_res},
    multi::many1,
    IResult,
};

// u16 because we need 257 possible values, all unsigned.
#[derive(Copy, Clone, Hash, Eq, PartialEq)]
pub struct Symbol(pub u16);

// impl note: value 256 is WILDCARD.
pub const WILDCARD: Symbol = Symbol(0x100);

// byte values map directly into their Symbol indices.
impl std::convert::From<u8> for Symbol {
    fn from(v: u8) -> Self {
        Symbol(v as u16)
    }
}

impl std::fmt::Display for Symbol {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if self.0 == WILDCARD.0 {
            write!(f, "..")
        } else {
            write!(f, r"{:02X}", self.0)
        }
    }
}

// a pattern is just a sequence of symbols.
#[derive(Hash, PartialEq, Eq, Clone)]
pub struct Pattern(pub Vec<Symbol>);

impl std::fmt::Display for Pattern {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let parts: Vec<String> = self.0.iter().map(|s| format!("{s}")).collect();
        write!(f, "{}", parts.join(""))
    }
}

impl std::fmt::Debug for Pattern {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self}")
    }
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

/// parse a single byte signature element, which is either a hex byte or a
/// wildcard.
fn sig_element(input: &str) -> IResult<&str, Symbol> {
    alt((map(hex, Symbol::from), map(tag(".."), |_| WILDCARD)))(input)
}

/// parse byte signature elements, hex or wildcard.
fn byte_signature(input: &str) -> IResult<&str, Pattern> {
    let (input, elems) = many1(sig_element)(input)?;
    Ok((input, Pattern(elems)))
}

/// parse a pattern from a string like `AABB..DD`.
impl std::convert::From<&str> for Pattern {
    fn from(v: &str) -> Self {
        byte_signature(v).expect("failed to parse pattern").1
    }
}

pub struct PatternSet {
    patterns: Vec<Pattern>,
    dt:       super::decision_tree::DecisionTree,
}

impl std::fmt::Debug for PatternSet {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        for pattern in self.patterns.iter() {
            writeln!(f, "  - {pattern}")?;
        }
        Ok(())
    }
}

impl PatternSet {
    pub fn r#match(&self, buf: &[u8]) -> Vec<&Pattern> {
        self.dt
            .matches(buf)
            .into_iter()
            .map(|i| &self.patterns[i as usize])
            .collect()
    }

    pub fn builder() -> PatternSetBuilder {
        PatternSetBuilder { patterns: vec![] }
    }

    pub fn from_patterns(patterns: Vec<Pattern>) -> PatternSet {
        PatternSetBuilder { patterns }.build()
    }
}

pub struct PatternSetBuilder {
    patterns: Vec<Pattern>,
}

impl PatternSetBuilder {
    pub fn add_pattern(&mut self, pattern: Pattern) {
        self.patterns.push(pattern)
    }

    pub fn build(self) -> PatternSet {
        // should not be possible to generate invalid regex from a pattern
        // otherwise, programming error.
        // must reject invalid patterns when deserializing from pat/sig.

        let mut patterns = vec![];
        for pattern in self.patterns.iter() {
            patterns.push(format!("{pattern}"));
        }

        let dt = super::decision_tree::DecisionTree::new(&patterns);

        PatternSet {
            patterns: self.patterns,
            dt,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_build() {
        PatternSet::builder().build();
    }

    // patterns:
    //   - pat0: aabbccdd
    #[test]
    fn test_add_one_pattern() {
        let mut b = PatternSet::builder();
        b.add_pattern(Pattern::from("AABBCCDD"));

        println!("{:?}", b.build());
    }

    // patterns:
    //   - pat0: aabbccdd
    //   - pat1: aabbcccc
    #[test]
    fn test_add_two_patterns() {
        let mut b = PatternSet::builder();
        b.add_pattern(Pattern::from("AABBCCDD"));
        b.add_pattern(Pattern::from("AABBCCCC"));

        println!("{:?}", b.build());
    }

    // patterns:
    //   - pat0: aabbccdd
    //   - pat1: aabbcc..
    #[test]
    fn test_add_one_wildcard() {
        let mut b = PatternSet::builder();
        b.add_pattern(Pattern::from("AABBCCDD"));
        b.add_pattern(Pattern::from("AABBCC.."));

        println!("{:?}", b.build());
    }

    // we don't match when we don't have any patterns.
    #[test]
    fn test_match_empty() {
        let pattern_set = PatternSet::builder().build();
        assert_eq!(pattern_set.r#match(b"\xAA\xBB\xCC\xDD").len(), 0);
    }

    // we match things we want to, and don't match other data.
    #[test]
    fn test_match_one() {
        let mut b = PatternSet::builder();
        b.add_pattern(Pattern::from("AABBCCDD"));
        let pattern_set = b.build();

        // true positive
        assert_eq!(pattern_set.r#match(b"\xAA\xBB\xCC\xDD").len(), 1);
        // true negative
        assert_eq!(pattern_set.r#match(b"\xAA\xBB\xCC\xEE").len(), 0);
    }

    // we match from the beginning of the buffer onwards,
    // ignoring trailing bytes beyond the length of the pattern.
    #[test]
    fn test_match_long() {
        let mut b = PatternSet::builder();
        b.add_pattern(Pattern::from("AABBCCDD"));
        let pattern_set = b.build();

        assert_eq!(pattern_set.r#match(b"\xAA\xBB\xCC\xDD\x00").len(), 1);
        assert_eq!(pattern_set.r#match(b"\xAA\xBB\xCC\xDD\x11").len(), 1);
    }

    // we can match when there are single character wildcards present,
    // and order of the pattern declarations should not matter.
    #[test]
    fn test_match_one_tail_wildcard() {
        let mut b = PatternSet::builder();
        b.add_pattern(Pattern::from("AABBCC.."));
        b.add_pattern(Pattern::from("AABBCCDD"));
        let pattern_set = b.build();

        assert_eq!(pattern_set.r#match(b"\xAA\xBB\xCC\xDD").len(), 2);
        assert_eq!(pattern_set.r#match(b"\xAA\xBB\xCC\xEE").len(), 1);
        assert_eq!(pattern_set.r#match(b"\xAA\xBB\x00\x00").len(), 0);

        // order of patterns should not matter
        let mut b = PatternSet::builder();
        b.add_pattern(Pattern::from("AABBCCDD"));
        b.add_pattern(Pattern::from("AABBCC.."));
        let pattern_set = b.build();

        assert_eq!(pattern_set.r#match(b"\xAA\xBB\xCC\xDD").len(), 2);
        assert_eq!(pattern_set.r#match(b"\xAA\xBB\xCC\xEE").len(), 1);
        assert_eq!(pattern_set.r#match(b"\xAA\xBB\x00\x00").len(), 0);
    }

    // wildcards can be found in the middle of patterns, too.
    #[test]
    fn test_match_one_middle_wildcard() {
        let pattern_set = PatternSet::from_patterns(vec![Pattern::from("AABB..DD"), Pattern::from("AABBCCDD")]);

        assert_eq!(pattern_set.r#match(b"\xAA\xBB\xCC\xDD").len(), 2);
        assert_eq!(pattern_set.r#match(b"\xAA\xBB\xEE\xDD").len(), 1);
        assert_eq!(pattern_set.r#match(b"\xAA\xBB\x00\x00").len(), 0);

        // order of patterns should not matter
        let pattern_set = PatternSet::from_patterns(vec![Pattern::from("AABBCCDD"), Pattern::from("AABB..DD")]);

        assert_eq!(pattern_set.r#match(b"\xAA\xBB\xCC\xDD").len(), 2);
        assert_eq!(pattern_set.r#match(b"\xAA\xBB\xEE\xDD").len(), 1);
        assert_eq!(pattern_set.r#match(b"\xAA\xBB\x00\x00").len(), 0);
    }

    // we can have an arbitrary mix of wildcards and literals.
    #[test]
    fn test_match_many() {
        let pattern_set = PatternSet::from_patterns(vec![
            Pattern::from("AABB..DD"),
            Pattern::from("AABBCCDD"),
            Pattern::from("........"),
            Pattern::from("....CCDD"),
        ]);
        assert_eq!(pattern_set.r#match(b"\xAA\xBB\xCC\xDD").len(), 4);
        assert_eq!(pattern_set.r#match(b"\xAA\xBB\x00\xDD").len(), 2);
        assert_eq!(pattern_set.r#match(b"\xAA\xBB\x00\x00").len(), 1);
        assert_eq!(pattern_set.r#match(b"\x00\x00\xCC\xDD").len(), 2);
        assert_eq!(pattern_set.r#match(b"\x00\x00\x00\x00").len(), 1);
    }

    #[test]
    fn test_match_pathological_case() {
        let pattern_set = PatternSet::from_patterns(vec![
            Pattern::from("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            Pattern::from("................................................................"),
        ]);
        assert_eq!(pattern_set.r#match(b"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA").len(), 2);
    }
}
