/// ## purpose
/// to match multiple byte patterns against a byte slice in parallel.
/// we should get all valid matches at the end.
/// does not have to support scanning across the byte slice, only anchored at the start.
/// need support for single character wild cards (`.`).
/// all patterns are the same length
/// (if this needs to change, maybe pad shorter patterns with wildcards).
///
/// ## design:
/// we'll build an NFA with symbols for:
///   - all valid byte values (0-255), and
///   - a wildcard
///
/// a transition table will have 256 columns, one for each of the above symbols, including wildcard.
/// the transition table has a row for each state.
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
///       A B C D
///   0 | 1        alive: p0, p1
///   1 |   2   4  alive: p0, p1
///   2 |     3    alive: p0
///   3 |          terminal, alive: p0
///   4 |     5    alive: p1
///   5 |          terminal, alive: p1
///


// u16 because we need 256 possible values, all unsigned.
struct Symbol(u16);

// impl note: value 256 is WILDCARD.
pub const WILDCARD: Symbol = Symbol(0x100);

// byte values map directly into their Symbol indices.
impl std::convert::From<u8> for Symbol {
    fn from(v: u8) -> Self {Symbol(v as u16)}
}

// convert to usize so we can index into `TransitionTableRow.columns`.
impl std::convert::Into<usize> for Symbol {
    fn into(self) -> usize {self.0 as usize}
}

// a pattern is just a sequence of symbols.
struct Pattern(Vec<Symbol>);

// u32 because we need a fairly large range: these transition tables can have many rows.
// positive values are indexes to a transition table row.
// the zero value indicates an invalid transition, and rows are initially filled with this.
struct Transition(u32);

impl Default for Transition {
    fn default() -> Self {Transition(0)}
}

impl Transition {
    fn is_valid(&self) -> bool {
        self.0 == 0
    }
}

struct State {
    // 256 to cover the max range of a symbol.
    transitions: [Transition; 256],
    // indices with the bit set indicates the corresponding index in `NFA.patterns` is alive.
    alive: BitVec,
}

impl State {
    // a state is terminal if it has no valid transitions from it.
    fn is_terminal(&self) -> bool {
        self.transitions.find(|&transition| transition.is_valid()).is_none()
    }
}

struct StateTable {
    states: Vec<State>,
}

pub struct NFA {
    table: StateTable,
    patterns: Vec<Pattern>,
}

impl NFA {
    pub fn r#match(&self, buf: &[u8]) -> Vec<&Pattern> {
        // TODO
        vec![]
    }
}

pub struct NFABuilder {
    patterns: Vec<Pattern>
}

impl NFABuilder {
    pub fn add_pattern(&mut self, pattern: Pattern) {
        self.patterns.push(pattern)
    }

    pub fn build(self) -> NFA {
        // TODO
    }
}
