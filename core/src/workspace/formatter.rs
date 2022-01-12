use std::fmt::Write;

use anyhow::Result;

use crate::{analysis::dis::zydis, arch::Arch, workspace::PEWorkspace, VA};

#[derive(Default, Clone)]
struct OriginalHooks {
    print_address_abs: Option<zydis::Hook>,
    pre_instruction:   Option<zydis::Hook>,
}

struct UserData<'a> {
    ws:   &'a PEWorkspace,
    orig: OriginalHooks,
}

pub struct FormatterOptions {
    colors: bool,
}

pub struct FormatterBuilder {
    options: FormatterOptions,
}

impl FormatterBuilder {
    pub fn build(self) -> Formatter {
        Formatter::from_options(self.options)
    }

    pub fn with_colors(mut self, colors: bool) -> FormatterBuilder {
        self.options.colors = colors;
        self
    }
}

pub struct Formatter {
    options: FormatterOptions,
    inner:   zydis::Formatter,
    orig:    OriginalHooks,
}

pub const TOKEN_USER_SYMBOLNAME: zydis::Token = zydis::Token(zydis::TOKEN_USER.0 + 1);

impl Formatter {
    const COLOR_ADDRESS_ABS: ansi_term::Color = ansi_term::Color::Blue;
    const COLOR_ADDRESS_REL: ansi_term::Color = ansi_term::Color::Blue;
    // grey
    const COLOR_DECORATOR: ansi_term::Color = ansi_term::Color::Fixed(242);
    // grey
    const COLOR_DELIMITER: ansi_term::Color = ansi_term::Color::Fixed(242);
    const COLOR_DISPLACEMENT: ansi_term::Color = ansi_term::Color::Blue;
    const COLOR_IMMEDIATE: ansi_term::Color = ansi_term::Color::Blue;
    // default theme
    // TODO: move this to a struct that can be configured
    const COLOR_INVALID: ansi_term::Color = ansi_term::Color::Red;
    const COLOR_MNEMONIC: ansi_term::Color = ansi_term::Color::Green;
    // grey
    const COLOR_PARENTHESIS_CLOSE: ansi_term::Color = ansi_term::Color::Fixed(242);
    // grey
    const COLOR_PARENTHESIS_OPEN: ansi_term::Color = ansi_term::Color::Fixed(242);
    // grey
    const COLOR_PREFIX: ansi_term::Color = ansi_term::Color::Fixed(242);
    const COLOR_REGISTER: ansi_term::Color = ansi_term::Color::Yellow;
    // grey
    const COLOR_SYMBOL: ansi_term::Color = ansi_term::Color::Fixed(242);
    const COLOR_SYMBOLNAME: ansi_term::Color = ansi_term::Color::Purple;
    // grey
    const COLOR_TYPECAST: ansi_term::Color = ansi_term::Color::Fixed(242);
    const COLOR_USER: ansi_term::Color = ansi_term::Color::Fixed(242);
    const COLOR_WHITESPACE: ansi_term::Color = ansi_term::Color::Black;

    pub fn new() -> FormatterBuilder {
        FormatterBuilder {
            options: FormatterOptions { colors: true },
        }
    }

    pub fn from_options(options: FormatterOptions) -> Formatter {
        let mut inner = zydis::Formatter::new(zydis::FormatterStyle::INTEL).unwrap();

        let mut orig: OriginalHooks = Default::default();

        // TODO: align mnemonic

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
                        .pe
                        .module
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

                    // TODO: insn bytes

                    buf.append(zydis::TOKEN_ADDRESS_ABS)?;
                    match userdata.ws.pe.module.arch {
                        Arch::X32 => {
                            buf.get_string()?.append(&format!("{:08x}", va))?;
                        }
                        Arch::X64 => {
                            buf.get_string()?.append(&format!("{:016x}", va))?;
                        }
                    }

                    buf.append(zydis::TOKEN_WHITESPACE)?;
                    buf.get_string()?.append("  ")?;

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

                    if let Some(name) = userdata.ws.analysis.names.names_by_address.get(&absolute_address) {
                        // name is found in map, use that.
                        buf.append(TOKEN_USER_SYMBOLNAME)?;
                        return buf.get_string()?.append(name);
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
                                return Err(status);
                            } else {
                                return Ok(());
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

        Formatter { options, inner, orig }
    }

    // grey

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
            _ => unimplemented!("token: {}", token),
        }
    }

    fn render_token<T: Write>(&self, o: &mut T, token: zydis::Token, s: &str) -> Result<()> {
        if self.options.colors {
            o.write_str(&Formatter::get_token_color(token).paint(s).to_string())?;
        } else {
            o.write_str(s)?;
        }

        Ok(())
    }

    pub fn format_instruction(&self, ws: &PEWorkspace, insn: &zydis::DecodedInstruction, va: VA) -> Result<String> {
        let mut buffer = [0u8; 200];

        // we pass our userdata to ZydisFormatterFormatInstruction.
        // but to make it work, we have to play games with the lifetimes:
        // we need to convince the compiler that the userdata pointer lives long enough
        // to by used by the callbacks.
        //
        // we do this by extending the CFG lifetime from '_ to 'static.
        //
        // userdata is passed into ZydisFormatterFormatInstruction,
        // which passes userdata to each of the formatter callbacks.
        // those read strictly from insn/ctx/userdata and write strictly to output
        // buffer. there is no state maintained within these routines.
        // the callbacks won't be invoked beyond the call into FormatInstruction.
        //
        // therefore, i believe its safe to extend the lifetime here to work with zydis.
        let x = unsafe { std::mem::transmute::<&'_ PEWorkspace, &'static PEWorkspace>(ws) };

        let mut ud = UserData {
            orig: self.orig.clone(),
            ws:   x,
        };

        let mut out = String::new();
        for (token, s) in self
            .inner
            .tokenize_instruction(&insn, &mut buffer, Some(va), Some(&mut ud))?
        {
            self.render_token(&mut out, token, s)?;
        }

        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::{super::*, *};
    use crate::rsrc::*;
    use anyhow::Result;

    #[test]
    fn with_colors() -> Result<()> {
        let buf = get_buf(Rsrc::NOP);
        let pe = crate::loader::pe::PE::from_bytes(&buf)?;

        let ws = PEWorkspace::from_pe(pe)?;

        let fmt = Formatter::new().with_colors(true).build();

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

        let ws = PEWorkspace::from_pe(pe)?;

        let fmt = Formatter::new().with_colors(false).build();

        // ```
        //     .text:00401C4E 000 68 F4 61 40 00          push    offset ModuleName ; "mscoree.dll"
        //     .text:00401C53 004 FF 15 00 60 40 00       call    ds:GetModuleHandleA
        //     .text:00401C59 000 85 C0                   test    eax, eax
        // ```
        let insn = crate::test::read_insn(&ws.pe.module, 0x401C53);
        assert_eq!(
            fmt.format_instruction(&ws, &insn, 0x401C53)?,
            "call [kernel32.dll!GetModuleHandleA]"
        );

        Ok(())
    }
}
