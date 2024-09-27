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
use smallvec::SmallVec;

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
            Symbol::Byte(b) => write!(f, r"{b:02X}"),
            Symbol::Wildcard => write!(f, ".."),
        }
    }
}
// a pattern is just a sequence of symbols.
#[derive(Hash, PartialEq, Eq, Clone)]
pub struct Pattern(pub smallvec::SmallVec<[Symbol; MAX_PATTERN_SIZE]>);

impl Pattern {
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn is_match(&self, haystack: &[u8]) -> bool {
        for (i, symbol) in self.0.iter().enumerate() {
            match symbol {
                Symbol::Wildcard => continue,
                Symbol::Byte(b) => {
                    if let Some(bb) = haystack.get(i) {
                        if b != bb {
                            return false;
                        }
                        continue;
                    } else {
                        return false;
                    }
                }
            }
        }
        true
    }
}

impl std::fmt::Display for Pattern {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        for symbol in self.0.iter() {
            write!(f, "{symbol}")?;
        }
        Ok(())
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
    alt((map(hex, Symbol::from), map(tag(".."), |_| Symbol::Wildcard)))(input)
}

/// parse byte signature elements, hex or wildcard.
fn byte_signature(input: &str) -> IResult<&str, Pattern> {
    let (input, elems) = many1(sig_element)(input)?;
    Ok((input, Pattern(SmallVec::from(elems))))
}

/// parse a pattern from a string like `AABB..DD`.
impl std::convert::From<&str> for Pattern {
    fn from(v: &str) -> Self {
        byte_signature(v).expect("failed to parse pattern").1
    }
}

// index into `DecisionTree.patterns`.
type PatternId = u32;

// index into a Pattern to a symbol in question.
type SymbolIndex = u8; // u8::MAX or less

// the maximum number of patterns to store in leaf nodes.
// by reducing this number, the tree depth increases, but limits the number of
// validation scans. by increasing this number, we we trade less memory for
// slower matching speed.
const LEAF_SIZE: usize = 1;

struct VecMap<K: Eq, V> {
    // perf:
    // keep k and v together, rather than splitting across two vecs.
    // apparently the overhead of the second vec outweights benefits of packing.
    //
    // perf: using smallvec here doesn't help.
    inner: Vec<(K, V)>,
}

impl<K: Eq, V> Default for VecMap<K, V> {
    fn default() -> Self {
        VecMap {
            inner: Default::default(),
        }
    }
}

impl<K: Eq, V> VecMap<K, V> {
    /// may panic if k is already present.
    pub fn insert(&mut self, k: K, v: V) {
        debug_assert!(!self.inner.iter().any(|(kk, _)| k == *kk));

        self.inner.push((k, v));
    }

    pub fn iter(&self) -> impl Iterator<Item = &(K, V)> {
        self.inner.iter()
    }

    pub fn get(&self, k: &K) -> Option<&V> {
        for (kk, vv) in self.iter() {
            if k == kk {
                return Some(vv);
            }
        }

        None
    }
}

impl<K: Eq, V> std::iter::FromIterator<(K, V)> for VecMap<K, V> {
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        let mut m: VecMap<K, V> = Default::default();

        let iter = iter.into_iter();

        if let (_, Some(upper)) = iter.size_hint() {
            m.inner.reserve(upper);
        }

        for (k, v) in iter {
            m.insert(k, v);
        }

        m
    }
}

enum Node {
    Leaf {
        /// the matching patterns.
        //
        // perf: smallvec[_; 5] chosen empirically.
        // might be explained by vec being 3 * u64, which is 6 * PatternId (u32).
        // but smallvec needs one byte to flag inline or pointer, so space for 5 pattern ids.
        patterns: SmallVec<[PatternId; 5]>,
    },
    Branch {
        /// the index of the symbol to use to branch.
        index:   SymbolIndex,
        /// decision values. if the value is seen, transition to the child node.
        // conceptually, this is a btree, but since we dont a expect a large branching factor,
        // especially near the leaves, we dont want the overhead of a full btree node (64 elements?).
        choices: VecMap<u8, Box<Node>>,
        /// there may be patterns that match anythere here.
        /// rather than create a choice for each of the ~200 remaining values,
        /// place them all into other.
        /// if this is not None, then this node captures all remaining values.
        other:   Option<Box<Node>>,
    },
}

// this is the default pattern size for FLIRT signatures.
// i haven't seen longer patterns. if we do, then make this configurable.
// use this to use inline bitarrays below, but can easily migrate to bitvec if
// necessary.
const MAX_PATTERN_SIZE: usize = 32;

impl Node {
    /// build a tree of `Node` with the given patterns.
    fn new(patterns: &[Pattern]) -> Node {
        /// pick the best choice symbol index to split at.
        ///
        /// there are two fitness functions, in this order of priority:
        ///  1. avoid splitting where there are many wildcards, and
        ///  2. try to split where there are many distinct values.
        ///
        /// (2) is intuitive: we want to maximize the branching factor of each
        /// node. the more branches we have from each node, the
        /// shallower the tree will be.
        ///
        /// (1) we learned our lesson with - when we split where there are
        /// wildcards, all those wildcard patterns get passed down each
        /// brach. if there are many wildcards, then each split doesn't
        /// do much good, since each branch has at least #wildcard
        /// patterns in it - the tree explodes!
        fn pick_best_symbol_index(patterns: &[Pattern], pattern_ids: &[PatternId]) -> Option<SymbolIndex> {
            // number of wildcards seen at each symbol index.
            let mut wildcards_by_symbol_index = [0u32; MAX_PATTERN_SIZE];

            // set of values seen at each symbol index.
            // each set is a 256-bit bitarray, index corresponding to a byte value.
            // use `set.count_ones()` to see how many distinct values seen at a symbol
            // index.
            let mut values_seen_by_symbol_index = [bitarr![0; 256]; MAX_PATTERN_SIZE];

            for pattern_id in pattern_ids.iter() {
                if let Some(pattern) = patterns.get(*pattern_id as usize) {
                    for (symbol_index, symbol) in pattern.0.iter().enumerate() {
                        match symbol {
                            Symbol::Byte(b) => {
                                if let Some(values_seen) = values_seen_by_symbol_index.get_mut(symbol_index) {
                                    values_seen.set(*b as usize, true);
                                }
                            }
                            Symbol::Wildcard => {
                                if let Some(wildcard_count) = wildcards_by_symbol_index.get_mut(symbol_index) {
                                    *wildcard_count += 1;
                                }
                            }
                        }
                    }
                }
            }

            // construct and sort vector of the following tuples:
            //
            //   (wildcard_count, -distinct_value_count, symbol_index)
            //
            // which orders:
            //   1. minimizes wildcards
            //   2. maximizes distinct values
            let mut fitness_by_symbol_index: Vec<(u32, usize, usize)> = wildcards_by_symbol_index
                .iter()
                .cloned()
                .enumerate()
                .map(|(i, wildcard_count)| (wildcard_count, values_seen_by_symbol_index[i].count_ones(), i))
                // if all patterns have a wildcard at an index, then the count will be 0. no good.
                // if all patterns have the same byte an at index, then the count will be 1. no good.
                // this means that indices that have already been used will not be chosen again.
                .filter(|(_, distinct_values, _)| *distinct_values >= 2)
                // invert the distinct value count, so as we sort from low to high, the index with most distinct values
                // comes first.
                .map(|(wildcard_count, distinct_values, i)| (wildcard_count, 256 - distinct_values, i))
                .collect();

            fitness_by_symbol_index.sort_unstable();

            // take the first entry
            fitness_by_symbol_index.iter().map(|(_, _, i)| *i as u8).next()
        }

        /// recursively build a tree from the given patterns, specified by
        /// `pattern_ids`.
        fn build_decision_tree_inner(patterns: &[Pattern], pattern_ids: Vec<PatternId>) -> Node {
            if pattern_ids.len() < LEAF_SIZE {
                let mut pattern_ids = pattern_ids;
                pattern_ids.shrink_to_fit();
                return Node::Leaf {
                    patterns: SmallVec::from(pattern_ids),
                };
            }

            if let Some(symbol_index) = pick_best_symbol_index(patterns, &pattern_ids) {
                let mut choices: BTreeMap<u8, Vec<PatternId>> = Default::default();
                let mut wildcards: Vec<PatternId> = Default::default();

                for pattern_id in pattern_ids.into_iter() {
                    if let Some(pattern) = patterns.get(pattern_id as usize) {
                        match pattern.0.get(symbol_index as usize) {
                            Some(Symbol::Byte(b)) => {
                                choices.entry(*b).or_default().push(pattern_id);
                            }
                            Some(Symbol::Wildcard) => wildcards.push(pattern_id),
                            _ => {}
                        }
                    }
                }

                let other = if !wildcards.is_empty() {
                    for (_, v) in choices.iter_mut() {
                        v.extend(wildcards.iter());
                    }
                    Some(Box::new(build_decision_tree_inner(patterns, wildcards)))
                } else {
                    None
                };

                let choices: VecMap<u8, Box<Node>> = choices
                    .into_iter()
                    .map(|(k, v)| (k, Box::new(build_decision_tree_inner(patterns, v))))
                    .collect();

                Node::Branch {
                    index: symbol_index,
                    choices,
                    other,
                }
            } else {
                Node::Leaf {
                    patterns: SmallVec::from(pattern_ids),
                }
            }
        }

        let pattern_ids = patterns.iter().enumerate().map(|(i, _)| i as PatternId).collect();
        build_decision_tree_inner(patterns, pattern_ids)
    }

    fn get_child(&self, b: u8) -> Option<&Node> {
        if let Node::Branch { choices, other, .. } = self {
            if let Some(node) = choices.get(&b) {
                return Some(node);
            }

            if let Some(node) = other {
                return Some(node);
            }
        }

        None
    }

    pub fn matches(&self, buf: &[u8]) -> Vec<PatternId> {
        let mut node = self;

        loop {
            match node {
                Node::Leaf { patterns } => return patterns.to_vec(),
                Node::Branch { index, .. } => {
                    if let Some(b) = buf.get(*index as usize) {
                        if let Some(next) = node.get_child(*b) {
                            node = next;
                            continue;
                        }

                        return vec![];
                    } else {
                        // since we bucket the patterns by size in the decision tree,
                        // all input buffers passed here should be at least as large
                        // as all patterns.
                        //
                        // if we reach here its a programming error.
                        panic!("buffer too small for pattern")
                    }
                }
            }
        }
    }
}

pub struct DecisionTree {
    patterns: Vec<Pattern>,
    // mapping from pattern size to root node.
    // each bucket contains only the patterns of that size.
    // during matching, need to do a match against each bucket with the haystack size and smaller.
    buckets:  BTreeMap<usize, (Vec<PatternId>, Node)>,
}

impl DecisionTree {
    pub fn new<T: AsRef<str>>(patterns: &[T]) -> DecisionTree {
        let patterns: Vec<Pattern> = patterns.iter().map(|p| Pattern::from(p.as_ref())).collect();
        for pattern in patterns.iter() {
            assert!(pattern.0.len() <= MAX_PATTERN_SIZE);
        }

        // bucket size -> ([patternid], [patterns])
        let mut buckets: BTreeMap<usize, (Vec<PatternId>, Vec<Pattern>)> = Default::default();
        for pattern in patterns.iter() {
            let _ = buckets.entry(pattern.len()).or_default();
        }

        for (pattern_id, pattern) in patterns.iter().enumerate() {
            for (&size, bucket) in buckets.iter_mut() {
                if pattern.len() == size {
                    bucket.0.push(pattern_id as PatternId);
                    bucket.1.push(pattern.clone());
                }
            }
        }

        let buckets: BTreeMap<usize, (Vec<PatternId>, Node)> =
            buckets.into_iter().map(|(k, (a, b))| (k, (a, Node::new(&b)))).collect();

        DecisionTree { patterns, buckets }
    }

    pub fn matches(&self, haystack: &[u8]) -> Vec<PatternId> {
        // we may be passed a haystack that is much larger than we actually need.
        // so we need to match against patterns with all sizes less than that.
        // and we can't assume that the haystack contains just the target function.
        // see: https://github.com/williballenthin/lancelot/issues/112#issuecomment-802026030
        // in which Hex-Rays distributes a signature that matches across multiple
        // functions.

        let mut patterns = vec![];
        for (_size, (pattern_ids, root)) in self.buckets.range(0..=haystack.len()) {
            patterns.extend(
                root.matches(haystack)
                    .iter()
                    .cloned()
                    // translate from bucket pattern id to global pattern id
                    .map(|pattern_id| pattern_ids[pattern_id as usize])
                    // validation scan - ensure the pattern matches completely.
                    .filter(|pattern_id| self.patterns[*pattern_id as usize].is_match(haystack)),
            );
        }

        patterns
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

        fn rec(
            f: &mut std::fmt::Formatter,
            patterns: &[Pattern],
            bucket: &[PatternId],
            indent: usize,
            node: &Node,
        ) -> std::fmt::Result {
            match node {
                Node::Leaf { patterns: pattern_ids } => {
                    write_indent(f, indent)?;
                    writeln!(f, "{} patterns", pattern_ids.len())?;

                    for pattern_id in pattern_ids.iter() {
                        let index = bucket[*pattern_id as usize];
                        let pattern = &patterns[index as usize];

                        write_indent(f, indent + 1)?;
                        writeln!(f, "{pattern}")?;
                    }
                }
                Node::Branch { index, choices, other } => {
                    write_indent(f, indent)?;
                    writeln!(f, "index {index}")?;

                    for (choice, node) in choices.iter() {
                        write_indent(f, indent + 1)?;
                        writeln!(f, "choice {choice:02X}")?;

                        rec(f, patterns, bucket, indent + 2, node)?;
                    }

                    if let Some(other) = other {
                        write_indent(f, indent + 1)?;
                        writeln!(f, "choice ..")?;

                        rec(f, patterns, bucket, indent + 2, other)?;
                    }
                }
            }

            Ok(())
        }

        for (size, (bucket, root)) in self.buckets.iter() {
            writeln!(f, "size: {size}")?;
            rec(f, &self.patterns, bucket, 2, root)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{io::Read, ops::Not, path::PathBuf};

    use super::*;

    fn init_logging() {
        let log_level = log::LevelFilter::Debug;
        fern::Dispatch::new()
            .format(move |out, message, record| {
                out.finish(format_args!(
                    "{} [{:5}] {} {}",
                    chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                    record.level(),
                    if log_level == log::LevelFilter::Trace {
                        record.target()
                    } else {
                        ""
                    },
                    message
                ))
            })
            .level(log_level)
            .chain(std::io::stderr())
            .filter(|metadata| !metadata.target().starts_with("goblin::pe"))
            .apply()
            .expect("failed to configure logging");
    }

    #[test]
    fn test_new() {
        let _dt = DecisionTree::new(PATTERNS);
        //println!("\n{:?}", dt);
        //assert!(false);
    }

    #[test]
    fn test_matches() {
        let dt = DecisionTree::new(PATTERNS);

        // empty, too short
        assert_eq!(dt.matches(b""), vec![]);

        // exact match
        assert_eq!(dt.matches(b"\x55\x8B\xEC\x33\xC0\x5D\xC3"), vec![7]);

        // too short to match anything
        assert_eq!(dt.matches(b"\x55"), vec![]);
        assert_eq!(dt.matches(b"\x55\x8B\xEC\x33\xC0\x5D"), vec![]);

        // suffix doesn't matter
        assert_eq!(dt.matches(b"\x55\x8B\xEC\x33\xC0\x5D\xC3\xAA"), vec![7]);
        assert_eq!(dt.matches(b"\x55\x8B\xEC\x33\xC0\x5D\xC3\xBB"), vec![7]);
    }

    #[test]
    fn test_wildcard() {
        let dt = DecisionTree::new(PATTERNS);

        // these all match, with the variable bytes in the middle ignored
        assert_eq!(
            dt.matches(b"\x55\x8B\xEC\x33\xC0\x66\xA1!!!!\x25\x00\x01\x00\x00\xF7\xD8\x1B\xC0\x40\x5D\xC3"),
            vec![8]
        );
        assert_eq!(
            dt.matches(b"\x55\x8B\xEC\x33\xC0\x66\xA1!1!!\x25\x00\x01\x00\x00\xF7\xD8\x1B\xC0\x40\x5D\xC3"),
            vec![8]
        );
        assert_eq!(
            dt.matches(b"\x55\x8B\xEC\x33\xC0\x66\xA1!2!!\x25\x00\x01\x00\x00\xF7\xD8\x1B\xC0\x40\x5D\xC3"),
            vec![8]
        );
        assert_eq!(
            dt.matches(b"\x55\x8B\xEC\x33\xC0\x66\xA1!3!!\x25\x00\x01\x00\x00\xF7\xD8\x1B\xC0\x40\x5D\xC3"),
            vec![8]
        );

        // but this doesn't match, because we've grown the variable bytes too much
        assert_eq!(
            dt.matches(b"\x55\x8B\xEC\x33\xC0\x66!!!!!!\x00\x01\x00\x00\xF7\xD8\x1B\xC0\x40\x5D\xC3"),
            vec![]
        );
    }

    #[test]
    fn test_perf() {
        init_logging();

        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("benches");
        path.push("patterns.txt");

        let mut f = std::fs::File::open(path).unwrap();
        let mut s = String::new();
        f.read_to_string(&mut s).unwrap();
        let patterns: Vec<&str> = s.split("\n").filter(|s| s.is_empty().not()).collect();

        let _ = DecisionTree::new(&patterns);
    }

    const PATTERNS: &[&str] = &[
        "558bec33c0505050ff751cff7518ff7514ff7510ff750cff7508ff15",
        "558bec33c050506804010000ff750c6affff750850e8........50ff15",
        "558bec33c05333db40395d0c7c46565785c0743e8b450c03c3992bc28bf08b45",
        "558bec33c0565739410c76158b71088b7d088bd6393a74114083c2043b410c72",
        "558bec33c0568bf1890689460489460889460ce8........ff75088bcee8",
        "558bec33c0568bf1b9ffffff0f578b7d08094e0489461089461889460c8b4604",
        /* 6 */
        "558bec33c05dc20800",
        /* 7 */
        "558bec33c05dc3",
        /* 8 */
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
