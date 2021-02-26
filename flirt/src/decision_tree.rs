use std::collections::BTreeMap;

use anyhow::Result;
use bitvec::prelude::*;
use nom::{
    branch::alt,
    bytes::complete::{tag, take_while_m_n},
    combinator::{map, map_res},
    multi::many1,
    IResult,
};

// u16 because we need 257 possible values, all unsigned.
#[derive(Copy, Clone, Hash, Eq, PartialEq)]
pub enum Symbol {
    Byte(u8),
    Wildcard,
}

// byte values map directly into their Symbol indices.
impl std::convert::From<u8> for Symbol {
    fn from(v: u8) -> Self {
        Symbol::Byte(v)
    }
}

impl std::fmt::Display for Symbol {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Symbol::Byte(b) => write!(f, r"\x{:02X}", b),
            Symbol::Wildcard => write!(f, ".."),
        }
    }
}

// a pattern is just a sequence of symbols.
#[derive(Hash, PartialEq, Eq, Clone)]
pub struct Pattern(pub Vec<Symbol>);

impl std::fmt::Display for Pattern {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        for symbol in self.0.iter() {
            write!(f, "{}", symbol)?;
        }
        Ok(())
    }
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

/// parse a single byte signature element, which is either a hex byte or a
/// wildcard.
fn sig_element(input: &str) -> IResult<&str, Symbol> {
    alt((map(hex, Symbol::from), map(tag(".."), |_| Symbol::Wildcard)))(input)
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

// index into `DecisionTree.patterns`.
type PatternId = usize;

// index into a Pattern to a symbol in question.
type SymbolIndex = usize; // u8::MAX or less

enum Node {
    Leaf {
        // the matching patterns.
        patterns: Vec<PatternId>,
    },
    Branch {
        // the index of the symbol to use to branch.
        index:   SymbolIndex,
        // decision values
        choices: BTreeMap<u8, Node>,
    },
}

const MAX_PATTERN_SIZE: usize = 32;

fn build_decision_tree(patterns: &[Pattern]) -> Node {
    fn pick_best_symbol_index(
        patterns: &[Pattern],
        pattern_ids: &[PatternId],
        dead_symbol_indices: &BitArray,
    ) -> Option<SymbolIndex> {
        let mut values_seen_by_symbol_index = [bitarr![0; 256]; MAX_PATTERN_SIZE];

        for pattern_id in pattern_ids.iter() {
            // safety: pattern_ids contains only indices into patterns.
            let pattern = unsafe { patterns.get_unchecked(*pattern_id as usize) };

            for (symbol_index, symbol) in pattern.0.iter().enumerate() {
                match symbol {
                    Symbol::Byte(b) => {
                        // safety: symbol_index <= MAX_PATTERN_SIZE
                        // safety: b must be <= u8::MAX (255), which is size of bitarr! as constructed
                        // above.
                        unsafe {
                            values_seen_by_symbol_index
                                .get_unchecked_mut(symbol_index)
                                .set_unchecked(*b as usize, true);
                        }
                    }
                    Symbol::Wildcard => {}
                }
            }
        }

        let distinct_values_by_symbol_index: Vec<usize> = values_seen_by_symbol_index
            .iter()
            .map(|values_seen| values_seen.count_ones())
            .collect();

        distinct_values_by_symbol_index
            .iter()
            .enumerate()
            .filter(|(_, count)| **count != 0)
            .filter(|(i, _)| !*dead_symbol_indices.get(*i).expect("invalid alive index"))
            .max_by(|(_, a), (_, b)| a.partial_cmp(b).expect("no floats"))
            .map(|(i, _)| i)
    }

    fn build_decision_tree_inner(
        patterns: &[Pattern],
        pattern_ids: Vec<PatternId>,
        mut dead_symbol_indices: BitArray,
    ) -> Node {
        if pattern_ids.len() == 1 {
            return Node::Leaf { patterns: pattern_ids };
        }

        if let Some(symbol_index) = pick_best_symbol_index(patterns, &pattern_ids, &dead_symbol_indices) {
            // safety: symbol_index <= MAX_PATTERN_SIZE
            unsafe { dead_symbol_indices.set_unchecked(symbol_index, true) };

            let mut choices: BTreeMap<u8, Vec<PatternId>> = Default::default();

            for pattern_id in pattern_ids.iter() {
                // safety: pattern_ids contains only indices into patterns.
                let pattern = unsafe { patterns.get_unchecked(*pattern_id as usize) };

                // safety: symbol_index <= MAX_PATTERN_SIZE
                let symbol = unsafe { pattern.0.get_unchecked(symbol_index) };

                match symbol {
                    Symbol::Byte(b) => {
                        choices.entry(*b).or_default().push(*pattern_id);
                    }
                    Symbol::Wildcard => {
                        for b in 0..u8::MAX {
                            choices.entry(b).or_default().push(*pattern_id);
                        }
                    }
                }
            }

            let choices: BTreeMap<u8, Node> = choices
                .into_iter()
                .map(|(k, v)| {
                    let v = build_decision_tree_inner(patterns, v, dead_symbol_indices.clone());
                    (k, v)
                })
                .collect();

            Node::Branch {
                index: symbol_index,
                choices,
            }
        } else {
            Node::Leaf { patterns: pattern_ids }
        }
    }

    let mut pattern_ids = vec![];
    for id in 0..patterns.len() {
        pattern_ids.push(id);
    }

    let dead_symbol_indices = bitarr![0; MAX_PATTERN_SIZE];

    build_decision_tree_inner(patterns, pattern_ids, dead_symbol_indices)
}

pub struct DecisionTree {
    patterns: Vec<Pattern>,
    root:     Node,
}

impl DecisionTree {
    pub fn new<T: AsRef<str>>(patterns: &[T]) -> DecisionTree {
        for pattern in patterns.iter() {
            //assert!(pattern.as_ref().len() * 2 < MAX_PATTERN_SIZE);
        }

        let patterns: Vec<Pattern> = patterns.iter().map(|p| Pattern::from(p.as_ref())).collect();
        let root = build_decision_tree(&patterns);

        DecisionTree { patterns, root }
    }

    pub fn r#match(&self, haystack: &[u8]) -> Vec<usize> {
        // list of indices passed into `new` that match.
        vec![]
    }
}

impl std::fmt::Debug for DecisionTree {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fn write_indent(f: &mut std::fmt::Formatter, indent: usize) -> std::fmt::Result {
            for _ in 0..indent {
                write!(f, " ")?;
            }

            Ok(())
        }

        fn rec(f: &mut std::fmt::Formatter, indent: usize, node: &Node) -> std::fmt::Result {
            match node {
                Node::Leaf { patterns } => {
                    write_indent(f, indent)?;
                    writeln!(f, "{} patterns", patterns.len())?;
                }
                Node::Branch { index, choices } => {
                    write_indent(f, indent)?;
                    writeln!(f, "index {}", index)?;

                    for (choice, node) in choices.iter() {
                        write_indent(f, indent + 1)?;
                        writeln!(f, "choice {:02X}", choice)?;

                        rec(f, indent + 2, node)?;
                    }
                }
            }

            Ok(())
        }

        rec(f, 0, &self.root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let dt = DecisionTree::new(PATTERNS);
        println!("{:?}", dt);
        assert!(false);
    }

    const PATTERNS: &'static [&'static str] = &[
        "558bec33c0505050ff751cff7518ff7514ff7510ff750cff7508ff15",
        "558bec33c050506804010000ff750c6affff750850e8........50ff15",
        "558bec33c05333db40395d0c7c46565785c0743e8b450c03c3992bc28bf08b45",
        "558bec33c0565739410c76158b71088b7d088bd6393a74114083c2043b410c72",
        "558bec33c0568bf1890689460489460889460ce8........ff75088bcee8",
        "558bec33c0568bf1b9ffffff0f578b7d08094e0489461089461889460c8b4604",
        "558bec33c05dc20800",
        "558bec33c05dc3",
        "558bec33c066a1........2500010000f7d81bc0405dc3",
        "558bec33c066a1........2500020000f7d81bc0405dc3",
        "558bec33c066a1........2500040000f7d81bc0405dc3",
        "558bec33c066a1........25001000005dc3",
        "558bec33c066a1........25002000005dc3",
        "558bec33c066a1........2580000000f7d81bc0405dc3",
        "558bec33c066a1........83e001f7d81bc0405dc3",
        "558bec33c066a1........83e002f7d81bc0405dc3",
        "558bec33c066a1........83e004f7d81bc0405dc3",
        "558bec33c066a1........83e008f7d81bc0405dc3",
        "558bec33c066a1........83e010f7d81bc0405dc3",
        "558bec33c066a1........83e06033c983f8600f95c18bc15dc3",
        "558bec33c066a1........85c0750c6a00e8........83c404eb1368",
        "558bec33c0833d........000f95c05dc3",
        "558bec33c0837d08000f95c05dc3",
        "558bec33c0837d100a75063945087d01408b4d0c50ff75108b4508e8",
        "558bec33c0837d100a75083945087d036a015850ff7510ff750cff7508e8",
        "558bec33c0837d140a75063945087d014050ff75148b450cff7510ff7508e8",
        "558bec33c0837d140a75063945087d01408b4d0c50ff75148b4508ff7510e8",
        "558bec33c0837d140a750f39450c7f0a7c05394508730333c04050ff75148b45",
        "558bec33c0837d140a750f39450c7f0a7c0539450873036a015850ff7514ff75",
        "558bec33c0837d180a750f39450c7f0a7c05394508730333c040578b7d1050ff",
        "558bec33c0837d180a750f39450c7f0a7c05394508730333c0408b55148b4d10",
        "558bec33c083ec1038450874036a02586802001f00506a006a00e8........83",
        "558bec33c083ec1040807d080074036a03586802001f00506a006a00e8",
        "558bec33c08b4d10e314578b7d088a450cf2aeb80000000075038d47ff5fc9c3",
        "558bec33c0a0........83e00185c0750f8a0d........80c901880d",
        "558bec33c0c701........408941048941088b450889410c8b450c8941108bc1",
        "558bec33c0c701........408941048941088b450889410c8bc15dc20400",
        "558bec33c0f74508ffffff7f7501405dc3",
        "558bec33c98bc10b450c74163bc97506837d0cff740c6a01ff7504e8",
        "558bec33c9bac59d1c81394d0c7617568b75080fb6043133d069d29301000141",
        "558bec33c9e8........5dc3",
        "558bec33d2385508c781a0000000000000000f95c28d412c8d14550200000087",
        "558bec33d25639510c76118b41088b7508393490740d423b510c72f532c05e5d",
        "558bec33d2817d0c0000f07f750939550875166a01eb3c817d0c0000f0ff7509",
        "558bec33d2817d0c0000f07f750a395508751733c0405dc3817d0c0000f0ff75",
        "558bec33d2817d0c0000f07f750a395508751833c0405dc3817d0c0000f0ff75",
        "558bec33d28bc239450c76118b4d0866391174094083c1023b450c72f25dc3",
        "558bec33d2b9c59d1c8139550c7617568b75080fb6043233c169c89301000142",
        "558bec33d2c781a0000000000000003855088d412c0f95c28d14550200000087",
        "558bec510fae5dfc8365fcc00fae55fc8b45fc50e8........83c4048be55dc3",
        "558bec510fae5dfc8365fcc00fae55fc8b4dfc33c0f6c13f7432f6c10174036a",
        "558bec510fb605........85c074238b0d........51e8........83c4048945",
        "558bec510fb605........85c0743068........ff15........8945fc817dfc",
        "558bec510fb6450850e8........83c40485c074090fbe4d08894dfceb0d0fbe",
        "558bec510fb6450850e8........83c40485c075120fb64d0883f95f7409c745",
        "558bec510fb64510508b4d0c518b550852ff15........85c07409c745fc0000",
        "558bec510fb645ff508b4d0851e8........83c4088be55dc3",
        "558bec510fb705........3dffff000074200fb70d........81e1ffff000066",
        "558bec510fb705........3dffff000074230fb70d........81e1ffff000066",
        "558bec510fb745082500ff000075200fb74d0881e1ff00000051e8........83",
        "558bec510fb745082500ff00007547833d........017e1a6a040fb74d0881e1",
        "558bec510fb745082500ff000085c07547833d........017e1a6a040fb74d08",
        "558bec510fb745083d000100007d160fb7450c0fb74d088b15........0fb70c",
        "558bec510fb745083d800000007309c745fc01000000eb07c745fc000000008b",
    ];
}
