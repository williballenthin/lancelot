use std::fmt;

use super::arch;

// TODO: figure out how to use failure for error (or some other pattern)
#[derive(Debug)]
pub enum Error {
    NotAnInstruction,
    LongInstruction,
}

/// FlowMeta is metadata that describes code flow for an instruction.
///
/// The metadata is packed into a single byte, with the expectation that,
///  there may be one `FlowMeta` instance for each (code) offset in a program.
/// However, the you should not be worried about the representation, just the interface.
#[derive(Debug)]
pub struct FlowMeta(u8);

impl FlowMeta {
    /// Create a new FlowMeta.
    ///
    /// Args:
    ///   - insn_length: size of instruction, or 0 if not an instruction, or 0xF if 0xF or larger.
    ///   - does_fallthrough: is there a fallthrough code flow to the next instruction?
    ///   - has_xrefs_from: are there code xrefs from this instruction (non-fallthrough)?
    pub fn new(insn_length: u8, does_fallthrough: bool, has_xrefs_from: bool) -> FlowMeta {
        let len = if insn_length >= 0xF {
            // instrunction length too long
            0x0F
        } else if insn_length == 0x0 {
            // not an instruction
            0x00
        } else {
            // good flow
            insn_length & 0x0F
        };

        let fallthrough = if does_fallthrough {
            0b0001_0000
        } else {
            0b0000_0000
        };

        let xfrom = if has_xrefs_from {
            0b0010_0000
        } else {
            0b0000_0000
        };

        FlowMeta(len | fallthrough | xfrom)
    }

    /// Fetch the cached length of the instruction.
    ///
    /// If longer than 14 bytes, then will return `Error::LongInstruction` and you'll have to decode
    ///  the instruction yourself.
    ///
    /// Errors:
    ///   - NotAnInstruction
    ///   - LongInstruction
    ///
    /// ```
    /// use matches::matches;
    /// use lancelot::flowmeta::*;
    /// assert_eq!(FlowMeta::new(0x01, true, true).get_insn_length().unwrap(),
    ///            0x01);
    /// assert!(matches!(FlowMeta::new(0x00, true, true).get_insn_length().err().unwrap(),
    ///                  Error::NotAnInstruction));
    /// assert!(matches!(FlowMeta::new(0x0F, true, true).get_insn_length().err().unwrap(),
    ///                  Error::LongInstruction));
    /// ```
    pub fn get_insn_length(&self) -> Result<u8, Error> {
        let v = self.0 & 0b0000_1111;
        match v {
            0x00 => Err(Error::NotAnInstruction),
            0x0F => Err(Error::LongInstruction),
            v @ _ => Ok(v)
        }
    }

    /// Does the instruction fallthrough?
    pub fn does_fallthrough(&self) -> bool {
        self.0 & 0b0001_0000 > 0
    }

    /// Does the instruction have flow xrefs from it?
    /// This does not include the fallthrough flow.
    pub fn has_xrefs_from(&self) -> bool {
        self.0 & 0b0010_0000 > 0
    }

    /// Does the instruction have flow xrefs to it?
    ///
    /// ```
    /// use lancelot::flowmeta::*;
    /// assert_eq!(FlowMeta::new(0x01, false, false).has_xrefs_to(), false);
    /// ```
    pub fn has_xrefs_to(&self) -> bool {
        self.0 & 0b0100_0000 > 0
    }

    /// Set the bit indicating that there are flow xrefs to this instruction.
    ///
    /// ```
    /// use lancelot::flowmeta::*;
    /// let mut m = FlowMeta::new(0x01, false, false);
    /// assert_eq!(m.has_xrefs_to(), false);
    ///
    /// m.set_xrefs_to();
    /// assert_eq!(m.has_xrefs_to(), true);
    /// ```
    pub fn set_xrefs_to(&mut self) {
        self.0 = self.0 | 0b0100_0000;
    }

    /// Unset the bit indicating that there are flow xrefs to this instruction.
    ///
    /// ```
    /// use lancelot::flowmeta::*;
    /// let mut m = FlowMeta::new(0x01, false, false);
    /// assert_eq!(m.has_xrefs_to(), false);
    ///
    /// m.set_xrefs_to();
    /// assert_eq!(m.has_xrefs_to(), true);
    ///
    /// m.unset_xrefs_to();
    /// assert_eq!(m.has_xrefs_to(), false);
    /// ```
    pub fn unset_xrefs_to(&mut self) {
        self.0 = self.0 & 0b1011_1111
    }
}

impl fmt::Display for FlowMeta {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "FlowMeta{{length: {}, fallthrough: {}, xrefs to: {}, xrefs from: {}}}",
               match self.get_insn_length() {
                   Ok(v) => format!("0x{:x}", v),
                   Err(Error::LongInstruction) => "more than 0xE".to_string(),
                   Err(Error::NotAnInstruction) => "not an instruction".to_string(),
               },
               self.does_fallthrough(),
               self.has_xrefs_to(),
               self.has_xrefs_from())
    }
}
