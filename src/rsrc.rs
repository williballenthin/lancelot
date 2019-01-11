//! A module to assist with fetching test data from the crate's resources.
use std::path::PathBuf;

#[derive(Copy, Clone)]
pub enum Rsrc {
    /// A defanged 64-bit version of kernel32.dll.
    K32,
    /// from: https://www.bigmessowires.com/2015/10/08/a-handmade-executable-file/
    /// since it doesn't have any sections or optional header, good for testing corner cases.
    TINY,
    /// from: https://joenord.com/apps/nop/
    NOP,
}

/// Fetch the file system path of the given resource.
///
/// ```
/// use lancelot::rsrc::*;
/// assert!(get_path(Rsrc::K32).ends_with("k32.bin"));
/// ```
pub fn get_path(rsrc: Rsrc) -> String {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("resources");
    d.push("test");

    match rsrc {
        Rsrc::K32 => {
            d.push("k32.bin");
        }
        Rsrc::TINY => {
            d.push("tiny.exe");
        }
        Rsrc::NOP => {
            d.push("nop.exe");
        }
    }

    String::from(d.to_str().unwrap())
}

/// Fetch the contents of the given resource.
///
/// ```
/// use lancelot::rsrc::*;
/// assert_eq!(get_buf(Rsrc::K32)[0], b'M');
/// assert_eq!(get_buf(Rsrc::K32)[1], b'Z');
/// ```
pub fn get_buf(rsrc: Rsrc) -> Vec<u8> {
    let path = get_path(rsrc);
    let mut buf = super::read_file(&path).unwrap();
    match rsrc {
        Rsrc::K32 => {
            buf[0] = b'M';
            buf[1] = b'Z';
        }
        Rsrc::TINY => {
            // pass
        }
        Rsrc::NOP => {
            // pass
        }
    }
    buf
}

/// Fetch a parsed and loaded workspace from the given resource.
///
/// ```
/// use lancelot::rsrc::*;
/// let ws = get_workspace(Rsrc::TINY);
/// ```
pub fn get_workspace(rsrc: Rsrc) -> super::Workspace {
    let path = get_path(rsrc);
    let buf = get_buf(rsrc);
    super::Workspace::from_buf(&path, buf).unwrap()
}
