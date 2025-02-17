use std::{cmp::min, fmt::Write};

use anyhow::Result;

use crate::{arch::Arch, aspace::AddressSpace, VA};

use super::Workspace;

#[derive(Default, Clone)]
struct OriginalHooks {
    print_address_abs: Option<zydis::Hook>,
    print_mnemonic:    Option<zydis::Hook>,
    pre_instruction:   Option<zydis::Hook>,
}

#[derive(Clone, Copy)]
pub struct FormatterOptions {
    colors:          bool,
    /// show up to the given number of bytes for each instruction,
    /// or ... (ellipsis) when truncated.
    /// use zero to disable this column.
    ///
    /// unit: bytes
    /// default: 8
    /// max: 16
    hex_column_size: usize,

    /// pad mnemonics to at least the given width.
    /// won't truncate longer instructions, just wont be nicely aligned.
    /// you probably don't need to touch this unless you want to.
    ///
    /// unit: characters
    /// default: 7
    mnemonic_width: usize,
}

struct UserData<'a> {
    ws:      &'a dyn Workspace,
    orig:    OriginalHooks,
    options: FormatterOptions,
}

pub struct FormatterBuilder {
    options: FormatterOptions,
}

impl FormatterBuilder {
    #[must_use]
    pub fn build(self) -> Formatter {
        Formatter::from_options(self.options)
    }

    #[must_use]
    pub fn with_colors(mut self, colors: bool) -> FormatterBuilder {
        self.options.colors = colors;
        self
    }

    #[must_use]
    pub fn with_hex_column_size(mut self, hex_column_size: usize) -> FormatterBuilder {
        // 0x10: max instruction length
        self.options.hex_column_size = min(hex_column_size, 0x10);
        self
    }
}

pub struct Formatter {
    options: FormatterOptions,
    inner:   zydis::Formatter,
    orig:    OriginalHooks,
}

pub const TOKEN_USER_SYMBOLNAME: zydis::Token = zydis::Token(zydis::TOKEN_USER.0 + 1);
pub const TOKEN_USER_HEX: zydis::Token = zydis::Token(zydis::TOKEN_USER.0 + 2);

impl Formatter {
    // default theme
    // TODO: move this to a struct that can be configured
    const COLOR_ADDRESS_ABS: ansi_term::Color = ansi_term::Color::Blue;
    const COLOR_ADDRESS_REL: ansi_term::Color = ansi_term::Color::Blue;
    const COLOR_DECORATOR: ansi_term::Color = Formatter::GREY;
    const COLOR_DELIMITER: ansi_term::Color = Formatter::GREY;
    const COLOR_DISPLACEMENT: ansi_term::Color = ansi_term::Color::Blue;
    const COLOR_HEX: ansi_term::Color = ansi_term::Color::Cyan;
    const COLOR_IMMEDIATE: ansi_term::Color = ansi_term::Color::Blue;
    const COLOR_INVALID: ansi_term::Color = ansi_term::Color::Red;
    const COLOR_MNEMONIC: ansi_term::Color = ansi_term::Color::Green;
    const COLOR_PARENTHESIS_CLOSE: ansi_term::Color = Formatter::GREY;
    const COLOR_PARENTHESIS_OPEN: ansi_term::Color = Formatter::GREY;
    const COLOR_PREFIX: ansi_term::Color = Formatter::GREY;
    const COLOR_REGISTER: ansi_term::Color = ansi_term::Color::Yellow;
    const COLOR_SYMBOL: ansi_term::Color = Formatter::GREY;
    const COLOR_SYMBOLNAME: ansi_term::Color = ansi_term::Color::Purple;
    const COLOR_TYPECAST: ansi_term::Color = Formatter::GREY;
    const COLOR_USER: ansi_term::Color = Formatter::GREY;
    const COLOR_WHITESPACE: ansi_term::Color = ansi_term::Color::Black;
    const GREY: ansi_term::Color = ansi_term::Color::Fixed(242);

    #[must_use]
    pub fn new() -> Formatter {
        FormatterBuilder {
            options: FormatterOptions {
                colors:          true,
                hex_column_size: 7,
                mnemonic_width:  7,
            },
        }
        .build()
    }

    #[must_use]
    pub fn with_options() -> FormatterBuilder {
        FormatterBuilder {
            options: FormatterOptions {
                colors:          true,
                hex_column_size: 7,
                mnemonic_width:  7,
            },
        }
    }

    pub fn from_options(options: FormatterOptions) -> Formatter {
        let mut inner = zydis::Formatter::new(zydis::FormatterStyle::INTEL).unwrap();

        let mut orig: OriginalHooks = Default::default();

        let f = inner
            .set_pre_instruction(Box::new(
                |_formatter: &zydis::Formatter,
                 buf: &mut zydis::FormatterBuffer,
                 ctx: &mut zydis::FormatterContext,
                 userdata: Option<&mut dyn core::any::Any>|
                 -> zydis::Result<()> {
                    // programming error: userdata must be provided. this is guaranteed within
                    // Formatter.
                    let userdata = userdata.expect("no userdata");

                    // programming error: userdata must be a Box<UserData>. this is guaranteed
                    // within Formatter.
                    let userdata = userdata.downcast_ref::<UserData>().expect("incorrect userdata");

                    let va = ctx.runtime_address;

                    if let Some(sec) = userdata
                        .ws
                        .module()
                        .sections
                        .iter()
                        .find(|&sec| sec.virtual_range.contains(&va))
                    {
                        buf.append(TOKEN_USER_SYMBOLNAME)?;
                        buf.get_string()?.append(&sec.name)?;
                    } else {
                        buf.append(zydis::TOKEN_INVALID)?;
                        buf.get_string()?.append("???")?;
                    }
                    buf.append(zydis::TOKEN_DELIMITER)?;
                    buf.get_string()?.append(":")?;

                    buf.append(zydis::TOKEN_ADDRESS_ABS)?;
                    match userdata.ws.module().arch {
                        Arch::X32 => {
                            buf.get_string()?.append(&format!("{va:08x}"))?;
                        }
                        Arch::X64 => {
                            buf.get_string()?.append(&format!("{va:016x}"))?;
                        }
                    }

                    buf.append(zydis::TOKEN_WHITESPACE)?;
                    buf.get_string()?.append("  ")?;

                    if userdata.options.hex_column_size > 0 {
                        let mut insn_buf = [0u8; 0x10];
                        let insn_len = (unsafe { &*ctx.instruction }).length as usize;
                        let col_count = userdata.options.hex_column_size;
                        userdata
                            .ws
                            .module()
                            .address_space
                            .read_into(va, &mut insn_buf[..insn_len])
                            .expect("failed to read instruction");

                        let mut hex = String::new();
                        for (i, b) in insn_buf.iter().enumerate().take(col_count) {
                            if insn_len > col_count && i == col_count - 1 {
                                // instruction is larger than reserved space,
                                // and this is the final spot for hex,
                                // which is 3 characters wide,
                                // so show "..." instead of the last byte.
                                hex.write_str("...").unwrap();
                            } else if i < insn_len {
                                // most common case: bytes of the instruction

                                if i != 0 {
                                    hex.write_str(" ").unwrap();
                                }

                                hex.write_str(&format!("{b:02X}")).unwrap();
                            } else {
                                // common case, insn is smaller than reserved space,
                                // so fill with spaces.
                                hex.write_str("   ").unwrap();
                            }
                        }

                        buf.append(TOKEN_USER_HEX)?;
                        buf.get_string()?.append(&hex)?;

                        buf.append(zydis::TOKEN_WHITESPACE)?;
                        buf.get_string()?.append("  ")?;
                    }

                    Ok(())
                },
            ))
            .unwrap();
        orig.pre_instruction = Some(f);

        let f = inner
            .set_print_address_abs(Box::new(
                |formatter: &zydis::Formatter,
                 buf: &mut zydis::FormatterBuffer,
                 ctx: &mut zydis::FormatterContext,
                 userdata: Option<&mut dyn core::any::Any>|
                 -> zydis::Result<()> {
                    // programming error: userdata must be provided. this is guaranteed within
                    // Formatter.
                    let userdata = userdata.expect("no userdata");

                    // programming error: userdata must be a Box<UserData>. this is guaranteed
                    // within Formatter.
                    let userdata = userdata.downcast_ref::<UserData>().expect("incorrect userdata");

                    let absolute_address = unsafe {
                        // safety: the insn and operands come from zydis, so we assume they contain
                        // valid data.
                        let insn: &zydis::DecodedInstruction = &*ctx.instruction;
                        let op: &zydis::DecodedOperand = &*ctx.operand;
                        insn.calc_absolute_address(ctx.runtime_address, op)
                            .expect("failed to calculate absolute address")
                    };

                    if let Some(name) = userdata.ws.analysis().names.names_by_address.get(&absolute_address) {
                        // name is found in map, use that.
                        buf.append(TOKEN_USER_SYMBOLNAME)?;

                        buf.get_string()?.append(name)
                    } else {
                        // name is not found, use original formatter.

                        // programming error: the original hook must be recorded. this is guaranteed
                        // within Formatter.
                        let orig = userdata.orig.print_address_abs.as_ref().expect("no original hook");

                        if let zydis::Hook::PrintAddressAbs(Some(f)) = orig {
                            // safety: zydis::Formatter <-> zydis::ffi::ZydisFormatter is safe according to
                            // here: https://docs.rs/zydis/3.1.2/src/zydis/formatter.rs.html#306
                            let status =
                                unsafe { f(formatter as *const _ as *const zydis::ffi::ZydisFormatter, buf, ctx) };
                            if status.is_error() {
                                Err(status)
                            } else {
                                Ok(())
                            }
                        } else {
                            // I'm not sure how this could ever be the case, as zydis initializes the hook
                            // with a default. I suppose if you explicitly set
                            // the callback to NULL/None? Which we don't do here.
                            panic!("unexpected original hook");
                        }
                    }
                },
            ))
            .unwrap();
        orig.print_address_abs = Some(f);

        let f = inner
            .set_print_mnemonic(Box::new(
                |formatter: &zydis::Formatter,
                 buf: &mut zydis::FormatterBuffer,
                 ctx: &mut zydis::FormatterContext,
                 userdata: Option<&mut dyn core::any::Any>|
                 -> zydis::Result<()> {
                    // programming error: userdata must be provided. this is guaranteed within
                    // Formatter.
                    let userdata = userdata.expect("no userdata");

                    // programming error: userdata must be a Box<UserData>. this is guaranteed
                    // within Formatter.
                    let userdata = userdata.downcast_ref::<UserData>().expect("incorrect userdata");

                    let orig = userdata.orig.print_mnemonic.as_ref().expect("no original hook");

                    if let zydis::Hook::PrintMnemonic(Some(f)) = orig {
                        // safety: zydis::Formatter <-> zydis::ffi::ZydisFormatter is safe according to
                        // here: https://docs.rs/zydis/3.1.2/src/zydis/formatter.rs.html#306
                        let status = unsafe { f(formatter as *const _ as *const zydis::ffi::ZydisFormatter, buf, ctx) };
                        if status.is_error() {
                            return Err(status);
                        }

                        let (_, mnemonic) = buf.get_token()?.get_value()?;

                        if mnemonic.len() < userdata.options.mnemonic_width {
                            let mut padding = String::new();

                            for _ in 0..userdata.options.mnemonic_width - mnemonic.len() {
                                padding.write_str(" ").unwrap();
                            }

                            buf.append(zydis::TOKEN_WHITESPACE)?;
                            buf.get_string()?.append(&padding)?;
                        }

                        Ok(())
                    } else {
                        // I'm not sure how this could ever be the case, as zydis initializes the hook
                        // with a default. I suppose if you explicitly set
                        // the callback to NULL/None? Which we don't do here.
                        panic!("unexpected original hook");
                    }
                },
            ))
            .unwrap();
        orig.print_mnemonic = Some(f);

        Formatter { options, inner, orig }
    }

    fn get_token_color(token: zydis::Token) -> ansi_term::Color {
        match token {
            zydis::TOKEN_INVALID => Formatter::COLOR_INVALID,
            zydis::TOKEN_WHITESPACE => Formatter::COLOR_WHITESPACE,
            zydis::TOKEN_DELIMITER => Formatter::COLOR_DELIMITER,
            zydis::TOKEN_PARENTHESIS_OPEN => Formatter::COLOR_PARENTHESIS_OPEN,
            zydis::TOKEN_PARENTHESIS_CLOSE => Formatter::COLOR_PARENTHESIS_CLOSE,
            zydis::TOKEN_PREFIX => Formatter::COLOR_PREFIX,
            zydis::TOKEN_MNEMONIC => Formatter::COLOR_MNEMONIC,
            zydis::TOKEN_REGISTER => Formatter::COLOR_REGISTER,
            zydis::TOKEN_ADDRESS_ABS => Formatter::COLOR_ADDRESS_ABS,
            zydis::TOKEN_ADDRESS_REL => Formatter::COLOR_ADDRESS_REL,
            zydis::TOKEN_DISPLACEMENT => Formatter::COLOR_DISPLACEMENT,
            zydis::TOKEN_IMMEDIATE => Formatter::COLOR_IMMEDIATE,
            zydis::TOKEN_TYPECAST => Formatter::COLOR_TYPECAST,
            zydis::TOKEN_DECORATOR => Formatter::COLOR_DECORATOR,
            zydis::TOKEN_SYMBOL => Formatter::COLOR_SYMBOL,
            zydis::TOKEN_USER => Formatter::COLOR_USER,
            TOKEN_USER_SYMBOLNAME => Formatter::COLOR_SYMBOLNAME,
            TOKEN_USER_HEX => Formatter::COLOR_HEX,
            _ => unimplemented!("token: {}", token),
        }
    }

    fn render_token<T: Write>(&self, o: &mut T, token: zydis::Token, s: &str) -> Result<()> {
        if self.options.colors {
            // force this into a string, or else the formatting control codes will not be written.
            //
            // from the documentation:
            // > If you do want to get at the escape codes, then you can convert the ANSIString
            // > to a string as you would any other Display value.
            let s = Formatter::get_token_color(token).paint(s).to_string();
            o.write_str(&s)?;
        } else {
            o.write_str(s)?;
        }

        Ok(())
    }

    pub fn format_instruction(&self, ws: &dyn Workspace, insn: &zydis::DecodedInstruction, va: VA) -> Result<String> {
        let mut buffer = [0u8; 400];

        // we pass our userdata to ZydisFormatterFormatInstruction.
        // but to make it work, we have to play games with the lifetimes:
        // we need to convince the compiler that the userdata pointer lives long enough
        // to by used by the callbacks.
        //
        // we do this by extending the workspace lifetime from '_ to 'static.
        //
        // userdata is passed into ZydisFormatterFormatInstruction,
        // which passes userdata to each of the formatter callbacks.
        // those read strictly from insn/ctx/userdata and write strictly to output
        // buffer. there is no state maintained within these routines.
        // the callbacks won't be invoked beyond the call into FormatInstruction.
        //
        // therefore, i believe its safe to extend the lifetime here to work with zydis.
        //let x = unsafe { std::mem::transmute::<&'_ PEWorkspace, &'static
        // PEWorkspace>(ws) };
        let x = unsafe { std::mem::transmute::<&'_ dyn Workspace, &'static dyn Workspace>(ws) };

        let mut ud = UserData {
            orig:    self.orig.clone(),
            ws:      x,
            options: self.options,
        };

        let mut out = String::new();
        for (token, s) in self
            .inner
            .tokenize_instruction(insn, &mut buffer, Some(va), Some(&mut ud))?
        {
            self.render_token(&mut out, token, s)?;
        }

        Ok(out)
    }
}

impl Default for Formatter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{super::*, *};
    use crate::rsrc::*;

    #[test]
    fn with_colors() -> Result<()> {
        let buf = get_buf(Rsrc::NOP);
        let pe = crate::loader::pe::PE::from_bytes(&buf)?;
        let config = config::empty();

        let ws = PEWorkspace::from_pe(config, pe)?;

        let fmt = Formatter::with_options().with_colors(true).build();

        // ```
        //     .text:00401C4E 000 68 F4 61 40 00          push    offset ModuleName ; "mscoree.dll"
        //     .text:00401C53 004 FF 15 00 60 40 00       call    ds:GetModuleHandleA
        //     .text:00401C59 000 85 C0                   test    eax, eax
        // ```
        let insn = crate::test::read_insn(&ws.pe.module, 0x401C53);
        let s = fmt.format_instruction(&ws, &insn, 0x401C53)?;
        assert!(s.contains("\u{1b}"));
        assert!(s.contains("call"));
        assert!(s.contains("GetModuleHandleA"));

        Ok(())
    }

    #[test]
    fn no_colors() -> Result<()> {
        let buf = get_buf(Rsrc::NOP);
        let pe = crate::loader::pe::PE::from_bytes(&buf)?;
        let config = config::empty();

        let ws = PEWorkspace::from_pe(config, pe)?;

        let fmt = Formatter::with_options()
            .with_colors(false)
            .with_hex_column_size(0)
            .build();

        // ```
        //     .text:00401C4E 000 68 F4 61 40 00          push    offset ModuleName ; "mscoree.dll"
        //     .text:00401C53 004 FF 15 00 60 40 00       call    ds:GetModuleHandleA
        //     .text:00401C59 000 85 C0                   test    eax, eax
        // ```
        let insn = crate::test::read_insn(&ws.pe.module, 0x401C53);
        assert_eq!(
            fmt.format_instruction(&ws, &insn, 0x401C53)?,
            ".text:00401c53  call    [kernel32.dll!GetModuleHandleA]"
        );

        Ok(())
    }

    #[test]
    fn hex() -> Result<()> {
        let buf = get_buf(Rsrc::NOP);
        let pe = crate::loader::pe::PE::from_bytes(&buf)?;
        let config = config::empty();

        let ws = PEWorkspace::from_pe(config, pe)?;

        // ```
        //     .text:00401C4E 000 68 F4 61 40 00          push    offset ModuleName ; "mscoree.dll"
        //     .text:00401C53 004 FF 15 00 60 40 00       call    ds:GetModuleHandleA
        //     .text:00401C59 000 85 C0                   test    eax, eax
        // ```
        let insn = crate::test::read_insn(&ws.pe.module, 0x401C53);

        let fmt = Formatter::with_options()
            .with_colors(false)
            .with_hex_column_size(0)
            .build();
        assert_eq!(
            fmt.format_instruction(&ws, &insn, 0x401C53)?,
            ".text:00401c53  call    [kernel32.dll!GetModuleHandleA]"
        );

        let fmt = Formatter::with_options()
            .with_colors(false)
            .with_hex_column_size(7)
            .build();
        assert_eq!(
            fmt.format_instruction(&ws, &insn, 0x401C53)?,
            ".text:00401c53  FF 15 00 60 40 00     call    [kernel32.dll!GetModuleHandleA]"
        );

        Ok(())
    }
}
