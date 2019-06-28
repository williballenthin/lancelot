//< Helpers that are useful for tests and doctests.

use super::rsrc::*;
use super::loader;
use super::arch::Arch;
use super::loaders::sc::ShellcodeLoader;
use super::workspace::Workspace;

/// Helper to construct a 32-bit Windows shellcode workspace from raw bytes.
///
/// It may panic when the workspace cannot be created/loaded.
/// Therefore, this is best used for tests.
///
/// ```
/// use lancelot::test;
/// use lancelot::arch::*;
///
/// let ws = test::get_shellcode32_workspace(b"\xEB\xFE");
/// assert_eq!(ws.read_u8(RVA(0x0)).unwrap(), 0xEB);
/// ```
pub fn get_shellcode32_workspace(buf: &[u8]) -> Workspace {
    Workspace::from_bytes("foo.bin", buf)
        .with_loader(Box::new(ShellcodeLoader::new(
            loader::Platform::Windows,
            Arch::X32
        )))
        .load()
        .unwrap()
}

pub fn get_shellcode64_workspace(buf: &[u8]) -> Workspace {
    Workspace::from_bytes("foo.bin", buf)
        .with_loader(Box::new(ShellcodeLoader::new(
            loader::Platform::Windows,
            Arch::X64
        )))
        .load()
        .unwrap()
}

pub fn get_rsrc_workspace(rsrc: Rsrc) -> Workspace {
    Workspace::from_bytes("foo.bin", &get_buf(rsrc))
        .load()
        .unwrap()
}
