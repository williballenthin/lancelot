use std::collections::BTreeMap;

use anyhow::Result;

use crate::{analysis::dis::zydis, VA};

struct UserData<'a> {
    names:                  &'a BTreeMap<VA, String>,
    orig_print_address_abs: Option<zydis::Hook>,
}

pub struct Formatter<'a> {
    inner: zydis::Formatter,
    ud:    Box<UserData<'a>>,
}

impl<'a> Formatter<'a> {
    pub fn new(names: &'a BTreeMap<VA, String>) -> Formatter {
        let mut ud = Box::new(UserData {
            names,
            orig_print_address_abs: None,
        });

        let mut inner = zydis::Formatter::new(zydis::FormatterStyle::INTEL).unwrap();

        let orig = inner
            .set_print_address_abs(Box::new(
                |formatter: &zydis::Formatter,
                 buf: &mut zydis::FormatterBuffer,
                 ctx: &mut zydis::FormatterContext,
                 userdata: Option<&mut dyn core::any::Any>|
                 -> zydis::Result<()> {
                    // programming error: userdata must be provided.
                    // TODO: enforce via types.
                    let userdata = userdata.expect("no userdata");

                    // programming error: userdata must be a Box<UserData>.
                    // TODO: enforce via types.
                    let userdata = userdata.downcast_ref::<Box<UserData>>().expect("incorrect userdata");

                    let absolute_address = unsafe {
                        // safety: the insn and operands come from zydis, so we assume they contain
                        // valid data.
                        let insn: &zydis::DecodedInstruction = &*ctx.instruction;
                        let op: &zydis::DecodedOperand = &*ctx.operand;
                        insn.calc_absolute_address(ctx.runtime_address, op)
                            .expect("failed to calculate absolute address")
                    };

                    if let Some(name) = userdata.names.get(&absolute_address) {
                        // name is found in map, use that.
                        return buf.get_string()?.append(name);
                    } else {
                        // name is not found, use original formatter.

                        // programming error: the original hook must be recorded.
                        // TODO: enforce via types.
                        let orig = userdata.orig_print_address_abs.as_ref().expect("no original hook");

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
        ud.orig_print_address_abs = Some(orig);

        Formatter { inner, ud }
    }

    pub fn format_instruction(&'a mut self, insn: &zydis::DecodedInstruction, va: VA) -> Result<String> {
        let mut buffer = [0u8; 200];
        let mut buffer = zydis::OutputBuffer::new(&mut buffer[..]);

        match self {
            Formatter { inner, ud } => {
                // we pass our userdata to ZydisFormatterFormatInstruction.
                // but to make it work, we have to play games with the lifetimes:
                // we need to convince the compiler that the userdata pointer lives long enough
                // to by used by the callbacks.
                //
                // we do this by extending the lifetime from 'a (from names: &'a BTreeMap<VA,
                // String>) to 'static.
                //
                // userdata is passed into ZydisFormatterFormatInstruction,
                // which passes userdata to each of the formatter callbacks.
                // those read strictly from insn/ctx/userdata and write strictly to output
                // buffer. there is no state maintained within these routines.
                //
                // therefore, i believe its safe to extend the lifetime here to work with zydis.
                let x = unsafe { std::mem::transmute::<&mut Box<UserData<'a>>, &mut Box<UserData<'static>>>(ud) };

                inner.format_instruction(&insn, &mut buffer, Some(va), Some(x))?;
            }
        };

        Ok(buffer.as_str()?.to_string())
    }

    pub fn from_workspace(ws: &crate::workspace::PEWorkspace) -> Formatter {
        Formatter::new(&ws.analysis.names.names_by_address)
    }
}

#[cfg(test)]
mod tests {
    use super::{super::*, *};
    use crate::rsrc::*;
    use anyhow::Result;

    #[test]
    fn k32() -> Result<()> {
        let buf = get_buf(Rsrc::K32);
        let pe = crate::loader::pe::PE::from_bytes(&buf)?;

        let ws = PEWorkspace::from_pe(pe)?;

        {
            let mut fmt = Formatter::from_workspace(&ws);
            let insn = crate::test::read_insn(&ws.pe.module, 0x1800134D4);
            assert_eq!(
                fmt.format_instruction(&insn, 0x1800134D4)?,
                "call [kernelbase.dll!KernelBaseGetGlobalData]"
            );
        }

        {
            let mut fmt = Formatter::from_workspace(&ws);
            let insn = crate::test::read_insn(&ws.pe.module, 0x180019961);
            assert_eq!(
                fmt.format_instruction(&insn, 0x180019961)?,
                "call [kernelbase.dll!BaseFormatObjectAttributes]"
            );
        }

        Ok(())
    }
}
