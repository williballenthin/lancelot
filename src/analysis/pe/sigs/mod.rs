/// scan for known byte signatures that identify constructs such as functions.
///
/// uses the Ghidra signature definitions from here:
///  - https://github.com/NationalSecurityAgency/ghidra/tree/79d8f164f8bb8b15cfb60c5d4faeb8e1c25d15ca/Ghidra/Processors/x86/data/patterns
///
/// implementation notes:
///   - this seems to be quite slow in debug mode (3s to process k32.dll), but fast enough in release (0.05s)

use std::cmp;
use std::io::Write;
use std::collections::HashMap;
use std::collections::HashSet;

use md5;
use log::{debug};
use regex::bytes::Regex;
use goblin::{Object};
use failure::{Error};
use rust_embed::{RustEmbed};
use xml::reader::{EventReader, XmlEvent, ParserConfig};

use super::super::{Analyzer};
use super::super::super::loader::Permissions;
use super::super::super::workspace::Workspace;


/// split the given string into chunks of the given length.
///
/// ```
/// use lancelot::analysis::pe::sigs::str_chunks;
/// assert_eq!(str_chunks("abcd", 1), vec!["a", "b", "c", "d"]);
/// assert_eq!(str_chunks("abcd", 2), vec!["ab", "cd"]);
/// assert_eq!(str_chunks("abcde", 2), vec!["ab", "cd", "e"]);
/// ```
pub fn str_chunks(s: &str, len: usize) -> Vec<&str> {
    let mut v = vec![];
    let mut cur = s;
    while !cur.is_empty() {
        let (chunk, rest) = cur.split_at(cmp::min(len, cur.len()));
        v.push(chunk);
        cur = rest;
    }
    v
}

pub fn render_byte(term: &str) -> Result<String, Error> {
    if term.len() != 8 {
        panic!("unexpected binary pattern length: {} {}", term, term.len());
    }

    // example, given:
    //
    //   term  = 0011..0.
    //
    // then:
    //
    //   v     = 00110000
    //   mask  = 00001101
    //   !mask = 11110010
    //
    // and results are:
    //
    //   00110000 0x30
    //   00110001 0x31
    //   00110100 0x34
    //   00110101 0x35
    //   00111000 0x38
    //   00111001 0x39
    //   00111100 0x3C
    //   00111101 0x3D

    // the non-wildcard value
    let mut v: u8 = 0;
    // the wildcard mask
    let mut mask: u8 = 0;

    for (i, c) in term.chars().rev().enumerate() {
        if c == '0' {
            v |= 0 << i;
        } else if c == '1' {
            v |= 1 << i;
        } else if c == '.' {
            mask |= 1 << i;
        } else {
            panic!("unexpected pattern character: {}", term)
        }
    }

    // because we're working with 8-bit values (bytes),
    //  we can pretty quickly enumerate all of them.
    // so, scan all the possible byte values and collect
    //  the unique values that match the wildcard mask.
    let candidates: HashSet<u8> = (0..255)
        .filter(|&b| (b & mask) == b)
        .map(|b| b & mask)
        .collect();

    if candidates.len() > 1 {
        // now we can generate the possible values.
        // this is `v | $candidate-mask-values`
        let mut out: Vec<String> = candidates.iter()
            .map(|c| c | (v & (!mask)))
            .map(|c| format!("\\x{:02X}", c))
            .collect();
        out.sort();
        Ok(format!("({})", out.join("|")))
    } else {
        Ok(format!("\\x{:02X}", v))
    }
}

/// render the given pattern term (single word) from a ghidra spec
///  into a binary regular expression.
///
/// terms should be:
///   - if hex, prefixed with `0x`
///   - if hex, even lengthed
///   - if hex, only full byte wildcard (nothing like `0xA.`)
///   - if binary, length is multiple of 8 (one byte)
///
/// ```
/// use lancelot::analysis::pe::sigs::render_pattern_term;
///
/// assert_eq!(render_pattern_term("", "0xAA").unwrap(), "\\xAA");
/// assert_eq!(render_pattern_term("", "0xaa").unwrap(), "\\xAA");
/// assert_eq!(render_pattern_term("", "0xAABB").unwrap(), "(\\xAA\\xBB)");
///
/// assert_eq!(render_pattern_term("", "0xAA..").unwrap(), "(\\xAA.)");
/// assert_eq!(render_pattern_term("", "0xAA..BB").unwrap(), "(\\xAA.\\xBB)");
///
/// assert_eq!(render_pattern_term("", "00000000").unwrap(), "\\x00");
/// assert_eq!(render_pattern_term("", "00000001").unwrap(), "\\x01");
/// assert_eq!(render_pattern_term("", "10000000").unwrap(), "\\x80");
///
/// assert_eq!(render_pattern_term("", "0000000.").unwrap(), "(\\x00|\\x01)");
/// assert_eq!(render_pattern_term("", "000000..").unwrap(), "(\\x00|\\x01|\\x02|\\x03)");
/// assert_eq!(render_pattern_term("", "0011..0.").unwrap(), "(\\x30|\\x31|\\x34|\\x35|\\x38|\\x39|\\x3C|\\x3D)");
///
/// assert_eq!(render_pattern_term("", "0000000.00000000").unwrap(), "((\\x00|\\x01)\\x00)");
/// ```
pub fn render_pattern_term(id: &str, term: &str) -> Result<String, Error> {
    if term == "*" {
        Ok(format!("(?P<{}_mark>(!!!!)*)", id))
    } else if term.starts_with("0x") {
        // handle hex-encoded byte

        // skip leading `0x`
        let term = &term[2..];

        let mut out = vec![];

        for byte in str_chunks(term, 2) {
            if byte == ".." {
                // collapse two `.` for the two nibbles in a hex char
                // down to a single byte-wise wildcard.
                out.push(".".to_string())
            } else if byte.contains(".") {
                // don't support things like `0xA.`
                panic!("unsupported pattern: half-wild byte")
            } else {
                out.push("\\x".to_string());
                out.push(byte.to_uppercase());
            }
        }

        if term.len() > 2 {
            Ok(format!("({})", out.join("")))
        } else {
            Ok(format!("{}", out.join("")))
        }
    } else if term.chars().all(|c| ['0', '1', '.'].contains(&c)) {
        // handle binary pattern

        let mut out = vec![];
        for byte in str_chunks(term, 8) {
            // process one byte (8 bits) at a time
            out.push(render_byte(byte)?);
        }

        if term.len() > 8 {
            Ok(format!("({})", out.join("")))
        } else {
            Ok(format!("{}", out.join("")))
        }

    } else {
        panic!("unexpected pattern character: {}", term)
    }
}

/// render the given pattern from a ghidra spec
///  into a binary regular expression.
/// the spec is a sequence of terms, whitespace separated.
pub fn render_pattern(id: &str, pattern: &str) -> Result<String, Error> {
    let parts: Result<Vec<String>, Error> = pattern
        .split_whitespace()
        .map(|term| render_pattern_term(id, term))
        .collect();
    let parts = parts?;
    Ok(format!("{}", parts.join("")))
}


/// represents a pattern spec that can be rendered into a binary regular expression.
pub trait Pattern {
    /// compute an identifier for this rule.
    /// unless there is an explicit name, derive the identifier from the contents of the patterns.
    fn id(&self) -> &str;

    /// render the pattern as a string containing a regular expression pattern.
    fn to_regex(&self) -> Result<String, Error>;

    /// fetch the capturing group name that identifies the function start offset within a match.
    fn get_mark(&self) -> &str;
}


/// represents a single `pattern` from the ghidra descriptor xml.
/// e.g. from:
///
/// <pattern>
///   <data>0x558bec</data>  <!-- PUSH EBP : MOV EBP,ESP -->
///   <funcstart after="data" /> <!-- must be something defined right before this, or no memory -->
/// </pattern>
pub struct SinglePattern {
    data: String,
    pub attrs: HashMap<String, String>,
    id: String,
    mark: String,
}

impl SinglePattern {
    pub fn new(data: String, attrs: HashMap<String, String>) -> SinglePattern {
        let mut m = md5::Context::new();
        m.write(data.as_bytes()).unwrap();
        let id = format!("{:x}", m.compute());
        let id = format!("pattern_{}", &id[..8]);

        let mark = if data.chars().find(|&c| c == '*').is_some() {
            format!("{}_mark", id)
        } else {
            id.clone()
        };

        SinglePattern {
            data,
            attrs,
            id,
            mark,
        }
    }
}

impl Pattern for SinglePattern {

    fn id(&self) -> &str {
        &self.id
    }

    /// ```
    /// use std::collections::HashMap;
    /// use lancelot::analysis::pe::sigs::Pattern;
    /// use lancelot::analysis::pe::sigs::SinglePattern;
    /// let p = SinglePattern::new("0xcc".to_string(), HashMap::new());
    /// assert_eq!(p.to_regex().unwrap(), "(?P<pattern_37e0788a>\\xCC)");
    /// ```
    fn to_regex(&self) -> Result<String, Error> {
        Ok(format!("(?P<{}>{})", self.id(), render_pattern(&self.id(), &self.data)?))
    }

    fn get_mark(&self) -> &str {
        &self.mark
    }
}

pub struct PatternPairs {
    prepatterns: Vec<String>,
    postpatterns: Vec<String>,
    pub attrs: HashMap<String, String>,
    id: String,
    mark: String,
}

impl PatternPairs {
    pub fn new(prepatterns: Vec<String>,
               postpatterns: Vec<String>,
               attrs: HashMap<String, String>) -> PatternPairs {

        let mut m = md5::Context::new();
        for pattern in prepatterns.iter() {
            m.write(pattern.as_bytes()).unwrap();
        }
        for pattern in postpatterns.iter() {
            m.write(pattern.as_bytes()).unwrap();
        }
        let id = format!("{:x}", m.compute());
        let id = format!("pattern_{}", &id[..8]);

        let mark = format!("{}_postpatterns", id);

        PatternPairs {
            prepatterns,
            postpatterns,
            attrs,
            id,
            mark,
        }
    }
}

impl Pattern for PatternPairs {
    fn id(&self) -> &str {
        &self.id
    }

    /// ```
    /// use std::collections::HashMap;
    /// use lancelot::analysis::pe::sigs::Pattern;
    /// use lancelot::analysis::pe::sigs::PatternPairs;
    /// let p = PatternPairs::new(
    ///   vec!["0xAA".to_string(), "0xBB".to_string()],
    ///   vec!["0xCC".to_string(), "0xDD".to_string()],
    ///   HashMap::new(),
    /// );
    /// assert_eq!(p.to_regex().unwrap(),
    ///            "(?P<pattern_b6a8a902>((\\xAA)|(\\xBB))(?P<pattern_b6a8a902_postpatterns>((\\xCC)|(\\xDD))))");
    /// ```
    fn to_regex(&self) -> Result<String, Error> {
        let mut prepatterns = vec![];
        for pp in self.prepatterns.iter() {
            prepatterns.push(format!("({})", render_pattern(&self.id(), pp)?));
        }
        let mut postpatterns = vec![];
        for pp in self.postpatterns.iter() {
            postpatterns.push(format!("({})", render_pattern(&self.id(), pp)?));
        }

        // don't tag the prepatterns with a named group,
        // as its just yet another thing that gets tracked, but we dont' use.
        Ok(format!("(?P<{}>({})(?P<{}_postpatterns>({})))",
                   self.id(),
                   prepatterns.join("|"),
                   self.id(),
                   postpatterns.join("|")))
    }

    fn get_mark(&self) -> &str {
        &self.mark
    }
}


#[derive(RustEmbed)]
#[folder = "src/analysis/pe/sigs/patterns"]
pub struct Assets;

struct Node {
    tag: String,
    attrs: HashMap<String, String>,
    text: String,
    children: Vec<Box<Node>>,
}

impl Node {
    fn get_children(&self, tag: &str) -> Vec<&Box<Node>> {
        self.children.iter().filter(|n| &n.tag == tag).collect()
    }
    fn get_child(&self, tag: &str) -> Option<&Box<Node>> {
        self.children.iter().filter(|n| &n.tag == tag).next()
    }
}

fn parse_xml(doc: &[u8]) -> Result<Node, Error> {
    let mut path: Vec<Node> = vec![];

    let parser = EventReader::new_with_config(doc, ParserConfig::new()
        .trim_whitespace(true)
        .whitespace_to_characters(true)
        .ignore_comments(true));

    for e in parser {
        match e {
            Ok(XmlEvent::StartDocument { .. }) => {
                path.push(Node{
                    tag: "root".to_string(),
                    attrs: HashMap::new(),
                    text: "".to_string(),
                    children: vec![],
                })
            },
            Ok(XmlEvent::StartElement { name, attributes, .. }) => {
                let mut attrs: HashMap<String, String> = HashMap::new();
                for kv in attributes.iter() {
                    attrs.insert(kv.name.local_name.clone(), kv.value.clone());
                }

                let node = Node {
                    tag: name.local_name.clone(),
                    attrs: attrs,
                    text: "".to_string(),
                    children: vec![],
                };

                path.push(node);
            }
            Ok(XmlEvent::Characters(s)) => {
                let l = path.len();
                let node = &mut path[l-1];
                node.text = s.clone();
            }
            Ok(XmlEvent::EndElement { .. }) => {
                let node = path.pop().unwrap();
                let l = path.len();
                let parent = &mut path[l-1];
                parent.children.push(Box::new(node));
            }
            Ok(XmlEvent::EndDocument { .. }) => {
                if path.len() != 1 {
                    panic!("bad doc length")
                }

                // this is the happy path
                return Ok(path.pop().unwrap());
            }
            Err(_) => {
                panic!("invalid document");
            }
            _ => {}
        }
    }
    panic!("bad doc length");
}

impl Assets {
    fn get_patternconstraints() -> Result<Node, Error> {
        parse_xml(&Assets::get("patternconstraints.xml").unwrap())
    }

    /// fetch text nodes from the xml path:
    ///
    ///   patternconstraints / language[id=$language] / compiler[id=$compiler] / patternfile
    ///
    /// ```
    /// use lancelot::analysis::pe::sigs::Assets;
    /// let patterns = Assets::get_patternfiles("x86:LE:32:default", "windows").unwrap();
    /// assert_eq!(patterns, vec!["x86win_patterns.xml"]);
    /// ```
    pub fn get_patternfiles(language: &str, compiler: &str) -> Result<Vec<String>, Error> {
        let mut patternfiles = vec![];

        // well this is pretty ugly...
        // also, sorry for the extra allocations.

        for constraints_node in Assets::get_patternconstraints()?.children.iter().filter(
            |n| &n.tag == "patternconstraints") {
            for language_node in constraints_node.children.iter().filter(
                |n| &n.tag == "language" && n.attrs.get("id") == Some(&language.to_string())) {
                for compiler_node in language_node.children.iter().filter(
                    |n| &n.tag == "compiler" && n.attrs.get("id") == Some(&compiler.to_string())) {
                    for patternfile_node in compiler_node.children.iter().filter(
                        |n| &n.tag == "patternfile") {
                        patternfiles.push(patternfile_node.text.clone());
                    }
                }
            }
        }
        Ok(patternfiles)
    }

    /// ```
    /// use lancelot::analysis::pe::sigs::Assets;
    /// let patterns = Assets::get_singlepatterns("x86:LE:32:default", "windows").unwrap();
    /// assert_eq!(patterns.len(), 10);
    /// ```
    pub fn get_singlepatterns(language: &str, compiler: &str) -> Result<Vec<SinglePattern>, Error> {
        let mut ret = vec![];

        for patternfile in Assets::get_patternfiles(language, compiler)?.iter() {
            let doc = Assets::get(patternfile).unwrap();
            for patternlist_node in parse_xml(&doc)?.children.iter().filter(
                |n| &n.tag == "patternlist") {

                for pattern_node in patternlist_node.children.iter().filter(
                    |n| &n.tag == "pattern") {

                    let data = pattern_node.get_child("data").unwrap().text.clone();
                    let fstart = pattern_node.get_child("funcstart").unwrap().attrs.clone();

                    ret.push(SinglePattern::new(data, fstart));
                }
            }
        }

        Ok(ret)
    }

    /// ```
    /// use lancelot::analysis::pe::sigs::Assets;
    /// let patterns = Assets::get_patternpairs("x86:LE:32:default", "windows").unwrap();
    /// assert_eq!(patterns.len(), 4);
    /// ```
    pub fn get_patternpairs(language: &str, compiler: &str) -> Result<Vec<PatternPairs>, Error> {
        let mut ret = vec![];

        for patternfile in Assets::get_patternfiles(language, compiler)?.iter() {
            let doc = Assets::get(patternfile).unwrap();
            for patternlist_node in parse_xml(&doc)?.children.iter().filter(
                |n| &n.tag == "patternlist") {

                for pattern_node in patternlist_node.children.iter().filter(
                    |n| &n.tag == "patternpairs") {

                    let mut prepatterns = vec![];
                    let mut postpatterns = vec![];

                    let prepattern_node = pattern_node.get_child("prepatterns").unwrap();
                    let postpattern_node = pattern_node.get_child("postpatterns").unwrap();

                    for data_node in prepattern_node.get_children("data").iter() {
                        prepatterns.push(data_node.text.clone());
                    }

                    for data_node in postpattern_node.get_children("data").iter() {
                        postpatterns.push(data_node.text.clone());
                    }

                    let fstart = if let Some(fstart) = postpattern_node.get_child("funcstart") {
                        fstart.attrs.clone()
                    } else if let Some(fstart) = postpattern_node.get_child("possiblefuncstart") {
                        let mut attrs = fstart.attrs.clone();
                        attrs.insert("possiblefuncstart".to_string(), "true".to_string());
                        attrs
                    } else {
                        HashMap::new()
                    };

                    ret.push(PatternPairs::new(prepatterns, postpatterns, fstart));
                }
            }
        }

        Ok(ret)
    }


    /// ```
    /// use lancelot::analysis::pe::sigs::Assets;
    /// let patterns = Assets::get_patterns("x86:LE:32:default", "windows").unwrap();
    /// assert_eq!(patterns.len(), 9);
    /// ```
    pub fn get_patterns(language: &str, compiler: &str) -> Result<Vec<Box<dyn Pattern>>, Error> {
        let mut ret: Vec<Box<dyn Pattern>> = vec![];

        for pattern in Assets::get_singlepatterns(language, compiler)?.into_iter() {
            // blacklist of non-supported funcstart attributes

            if pattern.attrs.contains_key("possiblefuncstart") {
                continue;
            }

            if pattern.attrs.contains_key("after") {
                // must be something defined right before this, or no memory
                continue
            }

            if pattern.attrs.contains_key("validcode") {
                continue
            }

            ret.push(Box::new(pattern));
        }

        for pattern in Assets::get_patternpairs(language, compiler)?.into_iter() {
            // blacklist of non-supported funcstart attributes

            if pattern.attrs.contains_key("possiblefuncstart") {
                continue;
            }

            if pattern.attrs.contains_key("after") {
                // must be something defined right before this, or no memory
                continue
            }

            if pattern.attrs.contains_key("validcode") {
                continue
            }

            ret.push(Box::new(pattern));
        }

        Ok(ret)
    }
}

pub struct ByteSigAnalyzer {}

impl ByteSigAnalyzer {
    pub fn new() -> ByteSigAnalyzer {
        ByteSigAnalyzer {}
    }
}


impl ByteSigAnalyzer {
    fn is_64(&self, ws: &Workspace) -> bool {
        match Object::parse(&ws.buf) {
            Ok(Object::PE(pe)) => pe.is_64,
            _ => panic!("can't analyze unexpected format"),
        }
    }
}

impl Analyzer for ByteSigAnalyzer {
    fn get_name(&self) -> String {
        "byte signature analyzer".to_string()
    }

    /// ```
    /// use lancelot::rsrc::*;
    /// use lancelot::arch::*;
    /// use lancelot::analysis::Analyzer;
    /// use lancelot::workspace::Workspace;
    /// use lancelot::analysis::pe::ByteSigAnalyzer;
    ///
    /// let mut ws = Workspace::from_bytes("k32.dll", &get_buf(Rsrc::K32))
    ///    .disable_analysis()
    ///    .load().unwrap();
    ///
    /// ByteSigAnalyzer::new().analyze(&mut ws).unwrap();
    /// assert!(ws.get_functions().find(|&&rva| rva == RVA(0x1010)).is_some());
    /// ```
    fn analyze(&self, ws: &mut Workspace) -> Result<(), Error> {
        let mut patterns: HashMap<String, Box<dyn Pattern>> = HashMap::new();

        let language = match self.is_64(ws) {
            true =>  "x86:LE:64:default",
            false => "x86:LE:32:default",
        };

        for pattern in Assets::get_patterns(language, "windows")?.into_iter() {
            patterns.insert(pattern.id().to_string(), pattern);
        }

        // join each of the component regular expressions into a master case expression, like:
        //
        //     (?-u)($one|$two|$three|...)
        //
        // the `(?-u)` disables unicode mode, which lets us match raw byte values.
        let mega_pattern = format!("(?-u)({})",
                patterns.values()
                    .map(|pattern| pattern.to_regex())
                    .collect::<Result<Vec<String>, Error>>()?
                    .join("|"));
        let re = Regex::new(&mega_pattern).unwrap();

        let mut functions = vec![];

        for section in ws.module.sections.iter().filter(|section| section.perms.intersects(Permissions::X)) {
            for capture in re.captures_iter(&section.buf) {
                for pattern in patterns.values() {
                    if let Some(mat) = capture.name(pattern.get_mark()) {
                        let rva = section.addr + mat.start();
                        functions.push(rva);
                    }
                }
            }
        }

        for rva in functions.iter() {
            debug!("found function by signature: {:#x}", rva);
            ws.make_function(*rva).unwrap();
            ws.analyze().unwrap();
        }

        Ok(())
    }
}
