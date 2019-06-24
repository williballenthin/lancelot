/// scan for known byte signatures that identify constructs such as functions.
///
/// uses the Ghidra signature definitions from here:
///  - https://github.com/NationalSecurityAgency/ghidra/tree/79d8f164f8bb8b15cfb60c5d4faeb8e1c25d15ca/Ghidra/Processors/x86/data/patterns

use std::marker::PhantomData;
use std::collections::HashMap;

use failure::{Error};
use rust_embed::{RustEmbed};
use xml::reader::{EventReader, XmlEvent, ParserConfig};

use super::super::super::arch::Arch;
use super::super::super::workspace::Workspace;
use super::super::{Analyzer};


pub struct Pattern {
    pub data: String,
    pub funcstart: HashMap<String, String>,
}

pub struct PatternPairs {
    pub prepatterns: Vec<String>,
    pub postpatterns: Vec<String>,
    pub funcstart: HashMap<String, String>,
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
    pub fn get_patterns(language: &str, compiler: &str) -> Result<Vec<Pattern>, Error> {
        let mut ret = vec![];

        for patternfile in Assets::get_patternfiles(language, compiler)?.iter() {
            let doc = Assets::get(patternfile).unwrap();
            for patternlist_node in parse_xml(&doc)?.children.iter().filter(
                |n| n.tag == "patternlist") {

                for pattern_node in patternlist_node.children.iter().filter(
                    |n| n.tag == "pattern") {

                    let data = pattern_node.get_child("data").unwrap().text.clone();
                    let fstart = pattern_node.get_child("funcstart").unwrap().attrs.clone();

                    ret.push(Pattern {
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
    /// assert!(false);
    /// ```
    fn analyze(&self, ws: &mut Workspace<A>) -> Result<(), Error> {
        let patterns = Assets::get_patterns("x86:LE:32:default", "windows")?;

        Ok(())
    }
}
