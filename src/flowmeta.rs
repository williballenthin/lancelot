use std::fmt;

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
#[derive(Debug, Clone, Copy)]
pub struct FlowMeta(u8);

impl FlowMeta {
    // layout:
    //
    //     +-+-+-+-+-+-+-+-+
    //     |A|B|C|D|   E   |
    //     +-+-+-+-+-+-+-+-+
    //
    //  A - unused
    //  B - has xrefs to
    //  C - has xrefs from
    //  D - does fallthrough
    //  E - insn size

    pub fn zero() -> FlowMeta {
        FlowMeta(0x0)
    }

    /// Fetch the cached length of the instruction.
    ///
    /// If longer than 14 bytes, then will return `Error::LongInstruction` and you'll have to decode
    ///  the instruction yourself.
    ///
    /// Errors:
    ///   - NotAnInstruction
    ///   - LongInstruction
    pub fn get_insn_length(&self) -> Result<u8, Error> {
        let v = self.0 & 0b0000_1111;
        match v {
            0x00 => Err(Error::NotAnInstruction),
            0x0F => Err(Error::LongInstruction),
            v @ _ => Ok(v)
        }
    }

    /// ```
    /// use matches::matches;
    /// use lancelot::flowmeta::*;
    ///
    /// let mut m = FlowMeta::zero();
    ///
    /// m.set_insn_length(0);
    /// assert_eq!(m.is_insn(), false);
    /// assert!(matches!(m.get_insn_length().err().unwrap(), Error::NotAnInstruction));
    ///
    /// m.set_insn_length(1);
    /// assert_eq!(m.is_insn(), true);
    /// assert_eq!(m.get_insn_length().unwrap(), 0x1);
    ///
    /// m.set_insn_length(2);
    /// assert_eq!(m.get_insn_length().unwrap(), 0x2);
    ///
    /// m.set_insn_length(0xE);
    /// assert_eq!(m.get_insn_length().unwrap(), 0xE);
    ///
    /// m.set_insn_length(0xF);
    /// assert_eq!(m.is_insn(), true);
    /// assert!(matches!(m.get_insn_length().err().unwrap(), Error::LongInstruction));
    /// ```
    pub fn set_insn_length(&mut self, length: u8) {
        let len = if length >= 0xF {
            // instrunction length too long
            0x0F
        } else if length == 0x0 {
            // not an instruction
            0x00
        } else {
            // good flow
            length & 0x0F
        };

        self.0 = (self.0 & 0b1111_0000) | len;
    }

    pub fn is_insn(&self) -> bool {
        self.0 & 0b0000_1111 != 0
    }

    /// Does the instruction fallthrough?
    pub fn does_fallthrough(&self) -> bool {
        self.0 & 0b0001_0000 > 0
    }

    /// ```
    /// use matches::matches;
    /// use lancelot::flowmeta::*;
    ///
    /// let mut m = FlowMeta::zero();
    /// assert_eq!(m.does_fallthrough(), false);
    ///
    /// m.set_fallthrough();
    /// assert_eq!(m.does_fallthrough(), true);
    /// ```
    pub fn set_fallthrough(&mut self) {
        self.0 = self.0 | 0b0001_0000;
    }

    /// Does the instruction have flow xrefs from it?
    /// This does not include the fallthrough flow.
    pub fn has_xrefs_from(&self) -> bool {
        self.0 & 0b0010_0000 > 0
    }

    /// ```
    /// use matches::matches;
    /// use lancelot::flowmeta::*;
    ///
    /// let mut m = FlowMeta::zero();
    /// assert_eq!(m.has_xrefs_from(), false);
    ///
    /// m.set_xrefs_from();
    /// assert_eq!(m.has_xrefs_from(), true);
    /// ```
    pub fn set_xrefs_from(&mut self) {
        self.0 = self.0 | 0b0010_0000;
    }

    /// Does the instruction have flow xrefs to it?
    pub fn has_xrefs_to(&self) -> bool {
        self.0 & 0b0100_0000 > 0
    }

    /// Set the bit indicating that there are flow xrefs to this instruction.
    ///
    /// ```
    /// use lancelot::flowmeta::*;
    /// let mut m = FlowMeta::zero();
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
    /// let mut m = FlowMeta::zero();
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
                   Err(Error::LongInstruction) => ">=0xF".to_string(),
                   Err(Error::NotAnInstruction) => "not an instruction".to_string(),
               },
               self.does_fallthrough(),
               self.has_xrefs_to(),
               self.has_xrefs_from())
    }
}
