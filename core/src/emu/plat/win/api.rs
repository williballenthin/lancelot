use std::collections::BTreeMap;

use anyhow::Result;
use lazy_static::lazy_static;

use super::WindowsEmulator;

pub enum CallingConvention {
    Stdcall,
    Cdecl,
}

pub struct ArgumentDescriptor {
    pub ty:   String,
    pub name: String,
}

pub struct FunctionDescriptor {
    pub calling_convention: CallingConvention,
    pub return_type:        String,
    pub arguments:          Vec<ArgumentDescriptor>,
}

type Hook = Box<dyn Fn(&mut dyn WindowsEmulator, &FunctionDescriptor) -> Result<()> + Send + Sync>;

lazy_static! {
    pub static ref API: BTreeMap<String, FunctionDescriptor> = {
        let mut m = BTreeMap::new();

        // populate from: https://github.com/microsoft/windows-rs/blob/master/.windows/winmd/Windows.Win32.winmd
        // alternative source: https://github.com/vivisect/vivisect/blob/master/vivisect/impapi/windows/i386.py
        // alternative source: https://github.com/fireeye/speakeasy/blob/88502c6eb99dd21ca6ebdcba3edff42c9c2c1bf8/speakeasy/winenv/api/usermode/kernel32.py#L1192

        m.insert(
            String::from("kernel32.dll!GetVersionExA"),
            FunctionDescriptor {
                calling_convention: CallingConvention::Stdcall,
                return_type: String::from("bool"),
                arguments: vec![
                    ArgumentDescriptor {
                        ty: String::from("LPOSVERSIONINFOA"),
                        name: String::from("lpVersionInformation"),
                    }
                ]
            }
        );

        m
    };

    pub static ref HOOKS: BTreeMap<String, Hook> = {
        let mut m = BTreeMap::new();

        m.insert(
            String::from("kernel32.dll!GetVersionExA"),
            Box::new(
                move |emu: &mut dyn WindowsEmulator, desc: &FunctionDescriptor| -> Result<()> {
                    let ra = emu.pop()?;
                    emu.set_pc(ra);

                    // this is 32-bit land
                    if let CallingConvention::Stdcall = desc.calling_convention {
                        for _ in 0..desc.arguments.len() {
                            let _ = emu.pop()?;
                        }
                    }

                    // TODO:

                    // this is 64-bit
                    // emu.inner.set_rax(0);

                    //emu.handle_return(0, desc)?;

                    Ok(())
                }
            ) as Hook
        );

        m
    };
}
