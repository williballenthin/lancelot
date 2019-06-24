/// scan for known byte signatures that identify constructs such as functions.
///
/// uses the Ghidra signature definitions from here:
///  - https://github.com/NationalSecurityAgency/ghidra/tree/79d8f164f8bb8b15cfb60c5d4faeb8e1c25d15ca/Ghidra/Processors/x86/data/patterns

use std::cmp;
use std::io::Write;
use std::marker::PhantomData;
use std::collections::HashMap;
use std::collections::HashSet;

use md5;
use failure::{Error};
use rust_embed::{RustEmbed};
use xml::reader::{EventReader, XmlEvent, ParserConfig};

use super::super::super::arch::Arch;
use super::super::super::workspace::Workspace;
use super::super::{Analyzer};


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

/// ```
/// use lancelot::analysis::pe::sigs::render_pattern_term;
///
/// assert_eq!(render_pattern_term("0xAA").unwrap(), "\\xAA");
/// assert_eq!(render_pattern_term("0xaa").unwrap(), "\\xAA");
/// assert_eq!(render_pattern_term("0xAABB").unwrap(), "\\xAA\\xBB");
///
/// assert_eq!(render_pattern_term("0xAA..").unwrap(), "\\xAA.");
/// assert_eq!(render_pattern_term("0xAA..BB").unwrap(), "\\xAA.\\xBB");
///
/// assert_eq!(render_pattern_term("00000000").unwrap(), "\\x00");
/// assert_eq!(render_pattern_term("00000001").unwrap(), "\\x01");
/// assert_eq!(render_pattern_term("10000000").unwrap(), "\\x80");
///
/// assert_eq!(render_pattern_term("0000000.").unwrap(), "(\\x00|\\x01)");
/// assert_eq!(render_pattern_term("000000..").unwrap(), "(\\x00|\\x01|\\x02|\\x03)");
/// assert_eq!(render_pattern_term("0011..0.").unwrap(), "(\\x30|\\x31|\\x34|\\x35|\\x38|\\x39|\\x3C|\\x3D)");
/// ```
pub fn render_pattern_term(term: &str) -> Result<String, Error> {
    if term.starts_with("0x") {
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

        Ok(format!("{}", out.join("")))
    } else if term.chars().all(|c| ['0', '1', '.'].contains(&c)) {
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

    } else {
        panic!("unexpected pattern character: {}", term)
    }
}

pub fn render_pattern(pattern: &str) -> Result<String, Error> {
    let parts: Result<Vec<String>, Error> = pattern.split_whitespace().map(render_pattern_term).collect();
    Ok(format!("({})", parts?.join("|")))
}

pub trait Pattern {
    /// compute an identifier for this rule.
    /// unless there is an explicit name, derive the identifier from the contents of the patterns.
    fn id(&self) -> String;

    /// render the pattern as a string containing a regular expression pattern.
    fn to_regex(&self) -> Result<String, Error>;
}

/// represents a single `pattern` from the ghidra descriptor xml.
/// e.g. from:
///
/// <pattern>
///   <data>0x558bec</data>  <!-- PUSH EBP : MOV EBP,ESP -->
///   <funcstart after="data" /> <!-- must be something defined right before this, or no memory -->
/// </pattern>
pub struct SinglePattern {
    pub data: String,
    pub funcstart: HashMap<String, String>,
}

impl Pattern for SinglePattern {
    fn id(&self) -> String {
        let mut m = md5::Context::new();
        m.write(self.data.as_bytes()).unwrap();
        let id = format!("{:x}", m.compute());
        format!("pattern-{}", &id[..8])
    }

    /// ```
    /// use std::collections::HashMap;
    /// use lancelot::analysis::pe::sigs::Pattern;
    /// use lancelot::analysis::pe::sigs::SinglePattern;
    /// let p = SinglePattern {
    ///   data: "0xcc".to_string(),
    ///   funcstart: HashMap::new(),
    /// };
    /// assert_eq!(p.to_regex().unwrap(), "(?<pattern-37e0788a>(\\xCC))");
    /// ```
    fn to_regex(&self) -> Result<String, Error> {
        Ok(format!("(?<{}>{})", self.id(), render_pattern(&self.data)?))
    }
}

pub struct PatternPairs {
    pub prepatterns: Vec<String>,
    pub postpatterns: Vec<String>,
    pub funcstart: HashMap<String, String>,
}

impl Pattern for PatternPairs {
    fn id(&self) -> String {
        let mut m = md5::Context::new();
        for pattern in self.prepatterns.iter() {
            m.write(pattern.as_bytes()).unwrap();
        }
        for pattern in self.postpatterns.iter() {
            m.write(pattern.as_bytes()).unwrap();
        }
        let id = format!("{:x}", m.compute());
        format!("pattern-{}", &id[..8])
    }

    fn to_regex(&self) -> Result<String, Error> {
        Ok("foo".to_string())
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
        self.children.iter().filter(|n| n.tag == tag).collect()
    }
    fn get_child(&self, tag: &str) -> Option<&Box<Node>> {
        self.children.iter().filter(|n| n.tag == tag).next()
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
            Err(e) => {
                println!("Error: {}", e);
                break;
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
            |n| n.tag == "patternconstraints") {
            for language_node in constraints_node.children.iter().filter(
                |n| n.tag == "language" && n.attrs.get("id") == Some(&language.to_string())) {
                for compiler_node in language_node.children.iter().filter(
                    |n| n.tag == "compiler" && n.attrs.get("id") == Some(&compiler.to_string())) {
                    for patternfile_node in compiler_node.children.iter().filter(
                        |n| n.tag == "patternfile") {
                        patternfiles.push(patternfile_node.text.clone());
                    }
                }
            }
        }
        Ok(patternfiles)
    }

    /// ```
    /// use lancelot::analysis::pe::sigs::Assets;
    /// let patterns = Assets::get_patterns("x86:LE:32:default", "windows").unwrap();
    /// assert_eq!(patterns.len(), 9);
    /// assert_eq!(patterns[0].data, "0x558bec");
    /// ```
    pub fn get_patterns(language: &str, compiler: &str) -> Result<Vec<SinglePattern>, Error> {
        let mut ret = vec![];

        for patternfile in Assets::get_patternfiles(language, compiler)?.iter() {
            let doc = Assets::get(patternfile).unwrap();
            for patternlist_node in parse_xml(&doc)?.children.iter().filter(
                |n| n.tag == "patternlist") {

                for pattern_node in patternlist_node.children.iter().filter(
                    |n| n.tag == "pattern") {

                    let data = pattern_node.get_child("data").unwrap().text.clone();
                    let fstart = pattern_node.get_child("funcstart").unwrap().attrs.clone();

                    ret.push(SinglePattern {
                        data: data,
                        funcstart: fstart,
                    })
                }
            }
        }

        Ok(ret)
    }

    /// ```
    /// use lancelot::analysis::pe::sigs::Assets;
    /// let patterns = Assets::get_patternpairs("x86:LE:32:default", "windows").unwrap();
    /// assert_eq!(patterns.len(), 4);
    /// assert_eq!(patterns[0].prepatterns[0], "0xcc");
    /// ```
    pub fn get_patternpairs(language: &str, compiler: &str) -> Result<Vec<PatternPairs>, Error> {
        let mut ret = vec![];

        for patternfile in Assets::get_patternfiles(language, compiler)?.iter() {
            let doc = Assets::get(patternfile).unwrap();
            for patternlist_node in parse_xml(&doc)?.children.iter().filter(
                |n| n.tag == "patternlist") {

                for pattern_node in patternlist_node.children.iter().filter(
                    |n| n.tag == "patternpairs") {

                    let mut prepatterns = vec![];
                    let mut postpatterns = vec![];

                    let prepattern_node = pattern_node.get_child("prepatterns").unwrap();
                    let postpattern_node = pattern_node.get_child("postpatterns").unwrap();

                    println!("patternpair:");

                    for data_node in prepattern_node.get_children("data").iter() {
                        println!("prepattern: {}", data_node.text);
                        prepatterns.push(data_node.text.clone());
                    }

                    for data_node in postpattern_node.get_children("data").iter() {
                        println!("postpattern: {}", data_node.text);
                        postpatterns.push(data_node.text.clone());
                    }

                    let fstart = if let Some(fstart) = postpattern_node.get_child("funcstart") {
                        fstart.attrs.clone()
                    } else if let Some(fstart) = postpattern_node.get_child("possiblefuncstart") {
                        fstart.attrs.clone()
                    } else {
                        HashMap::new()
                    };

                    ret.push(PatternPairs {
                        prepatterns,
                        postpatterns,
                        funcstart: fstart,
                    })
                }
            }
        }

        Ok(ret)
    }
}

pub struct ByteSigAnalyzer<A: Arch> {
    // This Analyzer must have a type parameter for it
    //  to implement Analyzer<A>.
    // however, it doesn't actually use this type itself.
    // so, we use a phantom data marker which has zero type,
    //  to ensure there is not an unused type parameter,
    //  which is a compile error.
    _phantom: PhantomData<A>,
}

impl<A: Arch> ByteSigAnalyzer<A> {
    pub fn new() -> ByteSigAnalyzer<A> {
        ByteSigAnalyzer {
            _phantom: PhantomData {},
        }
    }
}

impl<A: Arch + 'static> Analyzer<A> for ByteSigAnalyzer<A> {
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
    /// let mut ws = Workspace::<Arch64>::from_bytes("k32.dll", &get_buf(Rsrc::K32))
    ///    .disable_analysis()
    ///    .load().unwrap();
    ///
    /// ByteSigAnalyzer::<Arch64>::new().analyze(&mut ws).unwrap();
    /// ```
    fn analyze(&self, ws: &mut Workspace<A>) -> Result<(), Error> {
        let patterns = Assets::get_patterns("x86:LE:32:default", "windows")?;

        Ok(())
    }
}
