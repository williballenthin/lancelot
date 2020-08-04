use std::collections::HashSet;
/// ## purpose
/// to match multiple byte patterns against a byte slice in parallel.
/// we should get all valid matches at the end.
/// does not have to support scanning across the byte slice, only anchored at
/// the start. need support for single character wild cards (`.`).
/// all patterns are the same length
/// (if this needs to change, maybe pad shorter patterns with wildcards).
///
/// ## design:
/// we'll build an NFA with symbols for:
///   - all valid byte values (0-255), and
///   - a wildcard
///
/// a transition table will have 257 columns, one for each of the above symbols,
/// including wildcard. the transition table has a row for each state.
/// entries in each column indicate valid transitions.
/// an entry of `0` indicates "invalid".
/// if a row contains only invalid entries, then its a "terminal state".
/// there's a list associated with each row of "alive" patterns;
/// for a terminal state, these are the patterns that matched.
///
///
/// ### example (no wildcards)
///
/// input patterns:
///
///   p0: A B C D
///   p1: A D C B
///
/// transition table:
///
///   __  A B C D
///   0 | 1        alive: p0, p1
///   1 |   2   4  alive: p0, p1
///   2 |     3    alive: p0
///   3 |          terminal, alive: p0
///   4 |     5    alive: p1
///   5 |          terminal, alive: p1
///
/// ## TODO:
/// check out [RegexSet](https://docs.rs/regex/1.3.9/regex/struct.RegexSet.html)
///
/// > Match multiple (possibly overlapping) regular expressions in a single
/// scan. >
/// > A regex set corresponds to the union of two or more regular expressions.
/// > That is, a regex set will match text where at least one of its constituent
/// > regular expressions matches. A regex set as its formulated here provides a
/// touch more power: >  it will also report which regular expressions in the
/// set match. > Indeed, this is the key difference between regex sets and a
/// single Regex with many alternates, > since only one alternate can match at a
/// time.
use std::collections::VecDeque;

use bitvec::prelude::*;
use log::trace;
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

// convert to usize so we can index into `State.transitions`.
impl std::convert::Into<usize> for Symbol {
    fn into(self) -> usize {
        self.0 as usize
    }
}

impl std::fmt::Display for Symbol {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if self.0 == WILDCARD.0 {
            write!(f, "..")
        } else {
            write!(f, "{:02x}", self.0)
        }
    }
}

impl std::fmt::Debug for Symbol {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

// a pattern is just a sequence of symbols.
#[derive(Hash, PartialEq, Eq, Clone)]
pub struct Pattern(pub Vec<Symbol>);

impl std::fmt::Display for Pattern {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let parts: Vec<String> = self.0.iter().map(|s| format!("{}", s)).collect();
        write!(f, "{}", parts.join(""))
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

// u32 because we need a fairly large range: these transition tables can have
// many rows. positive values are indexes to a transition table row.
// the zero value indicates an invalid transition, and rows are initially filled
// with this.
#[derive(Copy, Clone)]
struct Transition(u32);

impl Default for Transition {
    fn default() -> Self {
        Transition(0)
    }
}

impl std::fmt::Display for Transition {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:x}", self.0)
    }
}

impl std::fmt::Debug for Transition {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

// convert to usize so we can index into `StateTable.states`.
impl std::convert::Into<usize> for Transition {
    fn into(self) -> usize {
        self.0 as usize
    }
}

impl Transition {
    fn is_valid(self) -> bool {
        self.0 != 0
    }
}

struct State {
    // 257 to cover the max range of a symbol.
    transitions: [Transition; 257],
    // indices with the bit set indicates the corresponding index in `NFA.patterns` is alive.
    alive:       BitVec,
}

impl State {
    fn new(capacity: u32) -> State {
        State {
            transitions: [Default::default(); 257],
            alive:       bitvec![0; capacity as usize],
        }
    }

    // a state is terminal if it has no valid transitions from it.
    fn is_terminal(&self) -> bool {
        self.transitions
            .iter()
            .find(|&transition| transition.is_valid())
            .is_none()
    }
}

struct StateTable {
    // total number of patterns in NFA.
    //
    // we have to know this before we start constructing the table,
    // that's why we use the Builder pattern.
    capacity: u32,
    states:   Vec<State>,
}

impl StateTable {
    /// add a new state to the end of the existing table.
    /// return the index of the state as a `Transition`.
    fn add_state(&mut self) -> Transition {
        let index = self.states.len() as u32; // TODO: danger
        self.states.push(State::new(self.capacity));
        Transition(index)
    }

    fn initial_state(&self) -> Transition {
        Transition(0)
    }
}

pub struct NFA {
    table:    StateTable,
    patterns: Vec<Pattern>,
}

impl NFA {
    pub fn r#match(&self, buf: &[u8]) -> Vec<&Pattern> {
        // to match against the patterns, we make transitions
        // from state to state using bytes from the input buffer.
        //
        // for example, consider the following transition table:
        //
        //       A B C D *
        //   0 | 1
        //   1 |   2   4
        //   2 |     3
        //   3 |
        //   4 |     5
        //   5 |
        //
        // the start state is state 0.
        // if we see an input byte of A, then we go to state 1.
        // any other byte does not match any pattern,
        // so we can exit with no match
        //
        // at a given state, there are up to two subsequent steps
        // that we must follow (and we must follow both):
        //
        //   - the transition for the literal byte, and
        //   - the transition for a wildcard
        //
        // the only computation state for any step is:
        //   1. the current state, and
        //   2. the remaining bytes to match against
        //
        // we maintain a queue of these `Steps`,
        // pushing Steps when there is a transition to follow,
        // and popping from the front.
        #[derive(Debug)]
        struct Step<'a> {
            /// the index to the state that we need to match next.
            state_pointer: Transition,
            /// the remaining bytes that need to be matched.
            buf:           &'a [u8],
        };

        // the set of pattern indices that have been matched.
        let mut matches: HashSet<usize> = HashSet::new();
        // the queue of matching steps that remain to be done.
        let mut q: VecDeque<Step> = VecDeque::new();

        q.push_front(Step {
            state_pointer: self.table.initial_state(),
            buf,
        });

        while let Some(step) = q.pop_front() {
            trace!("match step: {:?}", step);

            let state: &State = &self.table.states[Into::<usize>::into(step.state_pointer)];

            if state.is_terminal() {
                // if its a terminal state, then we've found matches.
                // any patterns that were still alive at this state are matches.
                trace!("match: found terminal state: {}", step.state_pointer);

                let match_indices = state
                    .alive
                    .iter()
                    .enumerate()
                    .filter(|(_, &is_alive)| is_alive)
                    .map(|(i, _)| i);

                for i in match_indices {
                    trace!("match index: {}", i);
                    matches.insert(i);
                }

                continue;
            }

            if step.buf.is_empty() {
                // there are no remaining input bytes, yet we're at a non-terminal state.
                // therefore, the input buffer is shorter than the pattern,
                // so it can't match.
                continue;
            }

            // two paths to attempt to follow:
            //  1. the literal symbol
            //  2. a wildcard
            let input_byte = step.buf[0];
            for &index in [input_byte as usize, WILDCARD.into()].iter() {
                let transition = state.transitions[index];
                if transition.is_valid() {
                    trace!("match: found transition to {} for input {:02x}", transition, input_byte);
                    q.push_front(Step {
                        state_pointer: transition,
                        buf:           &step.buf[1..],
                    })
                }
            }
        }

        trace!("match: matching against state:\n{:?}", self);

        matches.iter().map(|&i| &self.patterns[i]).collect()
    }

    pub fn builder() -> NFABuilder {
        NFABuilder { patterns: vec![] }
    }

    pub fn from_patterns(patterns: Vec<Pattern>) -> NFA {
        NFABuilder { patterns }.build()
    }
}

// output looks something like:
//
//     patterns:
//       - pat0: aabbccdd
//       - pat1: aabbcccc
//
//     transition table:
//
//           aa  bb  cc  dd  ..
//       0:  1                   alive: pat0 pat1
//       1:      2               alive: pat0 pat1
//       2:          3           alive: pat0 pat1
//       3:          5   4       alive: pat0 pat1
//       4:                      matches: pat0
//       5:                      matches: pat1
// ````
impl std::fmt::Debug for NFA {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        writeln!(f, "patterns:")?;
        for (i, pattern) in self.patterns.iter().enumerate() {
            writeln!(f, "  - pat{}: {}", i, pattern)?;
        }
        writeln!(f)?;

        // TODO: compute these dynamically
        let symbols = [Symbol(0xAA), Symbol(0xBB), Symbol(0xCC), Symbol(0xDD), WILDCARD];
        writeln!(f, "transition table:")?;
        write!(f, "     ")?;
        for symbol in symbols.iter() {
            write!(f, " {} ", symbol)?;
        }
        writeln!(f)?;

        for (i, state) in self.table.states.iter().enumerate() {
            write!(f, "  {:>2}:", i)?;

            for &symbol in symbols.iter() {
                let transition = state.transitions[Into::<usize>::into(symbol)];
                if transition.is_valid() {
                    write!(f, " {:>2} ", transition.0)?;
                } else {
                    write!(f, "    ")?;
                }
            }

            if state.alive.iter().any(|&b| b) {
                if state.is_terminal() {
                    write!(f, "  matches:")?;
                } else {
                    write!(f, "  alive:")?;
                }
                for (i, &is_alive) in state.alive.iter().enumerate() {
                    if is_alive {
                        write!(f, " pat{}", i)?;
                    }
                }
            }
            writeln!(f)?;
        }

        Ok(())
    }
}

pub struct NFABuilder {
    patterns: Vec<Pattern>,
}

impl NFABuilder {
    pub fn add_pattern(&mut self, pattern: Pattern) {
        self.patterns.push(pattern)
    }

    pub fn build(self) -> NFA {
        let mut nfa = NFA {
            table:    StateTable {
                capacity: self.patterns.len() as u32, // TODO: danger.
                states:   vec![],
            },
            patterns: self.patterns,
        };

        let start_state = nfa.table.add_state();

        #[derive(Debug)]
        struct Step<'a> {
            /// the index to the state that we need to add the next symbol.
            state_pointer: Transition,
            /// the index of the pattern we're currently processing.
            pattern_index: usize,
            /// the remaining symbols that need to be added.
            symbols:       &'a [Symbol],
        };

        let mut q: VecDeque<Step> = VecDeque::new();
        for (pattern_index, pattern) in nfa.patterns.iter().enumerate() {
            q.push_back(Step {
                state_pointer: start_state,
                pattern_index,
                symbols: &pattern.0[..],
            })
        }

        while let Some(step) = q.pop_front() {
            trace!("state:\n{:?}", nfa);
            trace!("step: {:?}", step);

            // syntax ref: https://stackoverflow.com/a/41208016/87207
            let state = &mut nfa.table.states[Into::<usize>::into(step.state_pointer)];

            // this state is already explored by this pattern.
            if *state.alive.get(step.pattern_index).unwrap() {
                continue;
            }

            // mark the current pattern as "alive" at the given state.
            state.alive.set(step.pattern_index, true);

            if step.symbols.is_empty() {
                // this is terminal.
                continue;
            }

            // fetch the symbol to insert, like AA
            let symbol = step.symbols[0];

            // fetch the cell from the state table,
            // this will either:
            //
            //   1. be invalid, which means we have to set it, or
            //   2. be already set to an existing transition
            //
            // if the value is unset, then we need to allocate a new row,
            // and point this cell towards it.
            let transition: Transition = state.transitions[Into::<usize>::into(symbol)];

            let next_state = if transition.is_valid() {
                // there is already a pointer to a state
                transition
            } else {
                // need to alloc a new state
                let next_state = nfa.table.add_state();

                let mut state = &mut nfa.table.states[Into::<usize>::into(step.state_pointer)];

                state.transitions[Into::<usize>::into(step.symbols[0])] = next_state;

                next_state
            };
            q.push_back(Step {
                state_pointer: next_state,
                pattern_index: step.pattern_index,
                symbols:       &step.symbols[1..],
            });

            // if its a wildcard, then must follow any existing literal transitions, too
            if symbol == WILDCARD {
                let state = &mut nfa.table.states[Into::<usize>::into(step.state_pointer)];

                for &literal_transition in state.transitions.iter() {
                    if literal_transition.is_valid() {
                        q.push_back(Step {
                            state_pointer: literal_transition,
                            pattern_index: step.pattern_index,
                            symbols:       &step.symbols[1..],
                        })
                    }
                }
            }
        }

        trace!("final state:\n{:?}", nfa);

        nfa
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_build() {
        NFA::builder().build();
    }

    // patterns:
    //   - pat0: aabbccdd
    //
    // transition table:
    //
    //  aa  bb  cc  dd  ..
    //  0:  1                   alive: pat0
    //  1:      2               alive: pat0
    //  2:          3           alive: pat0
    //  3:              4       alive: pat0
    //  4:                      matches: pat0
    #[test]
    fn test_add_one_pattern() {
        let mut b = NFA::builder();
        b.add_pattern(Pattern::from("AABBCCDD"));

        let nfa = b.build();
        println!("{:?}", nfa);
    }

    // patterns:
    //   - pat0: aabbccdd
    //   - pat1: aabbcccc
    //
    // transition table:
    //
    //  aa  bb  cc  dd  ..
    //  0:  1                   alive: pat0 pat1
    //  1:      2               alive: pat0 pat1
    //  2:          3           alive: pat0 pat1
    //  3:          5   4       alive: pat0 pat1
    //  4:                      matches: pat0
    //  5:                      matches: pat1
    #[test]
    fn test_add_two_patterns() {
        let mut b = NFA::builder();
        b.add_pattern(Pattern::from("AABBCCDD"));
        b.add_pattern(Pattern::from("AABBCCCC"));

        let nfa = b.build();
        println!("{:?}", nfa);
    }

    // patterns:
    //   - pat0: aabbccdd
    //   - pat1: aabbcc..
    //
    // transition table:
    //       aa  bb  cc  dd  ..
    //    0:  1                   alive: pat0 pat1
    //    1:      2               alive: pat0 pat1
    //    2:          3           alive: pat0 pat1
    //    3:              4   5   alive: pat0 pat1
    //    4:                      matches: pat0 pat1
    //    5:                      matches: pat1
    #[test]
    fn test_add_one_wildcard() {
        let mut b = NFA::builder();
        b.add_pattern(Pattern::from("AABBCCDD"));
        b.add_pattern(Pattern::from("AABBCC.."));

        let nfa = b.build();
        println!("{:?}", nfa);
    }

    // we don't match when we don't have any patterns.
    #[test]
    fn test_match_empty() {
        let nfa = NFA::builder().build();
        assert_eq!(nfa.r#match(b"\xAA\xBB\xCC\xDD").len(), 0);
    }

    // we match things we want to, and don't match other data.
    #[test]
    fn test_match_one() {
        let mut b = NFA::builder();
        b.add_pattern(Pattern::from("AABBCCDD"));
        let nfa = b.build();

        // true positive
        assert_eq!(nfa.r#match(b"\xAA\xBB\xCC\xDD").len(), 1);
        // true negative
        assert_eq!(nfa.r#match(b"\xAA\xBB\xCC\xEE").len(), 0);
    }

    // we match from the beginning of the buffer onwards,
    // ignoring trailing bytes beyond the length of the pattern.
    #[test]
    fn test_match_long() {
        let mut b = NFA::builder();
        b.add_pattern(Pattern::from("AABBCCDD"));
        let nfa = b.build();

        assert_eq!(nfa.r#match(b"\xAA\xBB\xCC\xDD\x00").len(), 1);
        assert_eq!(nfa.r#match(b"\xAA\xBB\xCC\xDD\x11").len(), 1);
    }

    // we can match when there are single character wildcards present,
    // and order of the pattern declarations should not matter.
    #[test]
    fn test_match_one_tail_wildcard() {
        let mut b = NFA::builder();
        b.add_pattern(Pattern::from("AABBCC.."));
        b.add_pattern(Pattern::from("AABBCCDD"));
        let nfa = b.build();

        assert_eq!(nfa.r#match(b"\xAA\xBB\xCC\xDD").len(), 2);
        assert_eq!(nfa.r#match(b"\xAA\xBB\xCC\xEE").len(), 1);
        assert_eq!(nfa.r#match(b"\xAA\xBB\x00\x00").len(), 0);

        // order of patterns should not matter
        let mut b = NFA::builder();
        b.add_pattern(Pattern::from("AABBCCDD"));
        b.add_pattern(Pattern::from("AABBCC.."));
        let nfa = b.build();

        assert_eq!(nfa.r#match(b"\xAA\xBB\xCC\xDD").len(), 2);
        assert_eq!(nfa.r#match(b"\xAA\xBB\xCC\xEE").len(), 1);
        assert_eq!(nfa.r#match(b"\xAA\xBB\x00\x00").len(), 0);
    }

    // wildcards can be found in the middle of patterns, too.
    #[test]
    fn test_match_one_middle_wildcard() {
        let nfa = NFA::from_patterns(vec![Pattern::from("AABB..DD"), Pattern::from("AABBCCDD")]);

        assert_eq!(nfa.r#match(b"\xAA\xBB\xCC\xDD").len(), 2);
        assert_eq!(nfa.r#match(b"\xAA\xBB\xEE\xDD").len(), 1);
        assert_eq!(nfa.r#match(b"\xAA\xBB\x00\x00").len(), 0);

        // order of patterns should not matter
        let nfa = NFA::from_patterns(vec![Pattern::from("AABBCCDD"), Pattern::from("AABB..DD")]);

        assert_eq!(nfa.r#match(b"\xAA\xBB\xCC\xDD").len(), 2);
        assert_eq!(nfa.r#match(b"\xAA\xBB\xEE\xDD").len(), 1);
        assert_eq!(nfa.r#match(b"\xAA\xBB\x00\x00").len(), 0);
    }

    // we can have an arbitrary mix of wildcards and literals.
    #[test]
    fn test_match_many() {
        let nfa = NFA::from_patterns(vec![
            Pattern::from("AABB..DD"),
            Pattern::from("AABBCCDD"),
            Pattern::from("........"),
            Pattern::from("....CCDD"),
        ]);
        assert_eq!(nfa.r#match(b"\xAA\xBB\xCC\xDD").len(), 4);
        assert_eq!(nfa.r#match(b"\xAA\xBB\x00\xDD").len(), 2);
        assert_eq!(nfa.r#match(b"\xAA\xBB\x00\x00").len(), 1);
        assert_eq!(nfa.r#match(b"\x00\x00\xCC\xDD").len(), 2);
        assert_eq!(nfa.r#match(b"\x00\x00\x00\x00").len(), 1);
    }

    #[test]
    fn test_match_pathological_case() {
        let nfa = NFA::from_patterns(vec![
            // 10 symbols - 65 states
            // 15 symbols - 135 states
            // 17 symbols - 170 states
            // 19 symbols - 209 states
            // 22 symbols - 278 states
            // 25 symbols - 253 states
            // 30 symbols - 498 states
            // 32 symbols - 562 states
            Pattern::from("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            Pattern::from("................................................................"),
        ]);
        println!("{:?}", nfa);
        assert_eq!(nfa.r#match(b"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA").len(), 2);
    }
}
