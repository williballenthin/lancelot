//! A module to assist with fetching test data from the crate's resources.
use std::path::PathBuf;

#[derive(Copy, Clone)]
pub enum Rsrc {
    /// A defanged 64-bit version of kernel32.dll.
    K32,
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
    }
    buf
}

/// Fetch a parsed and loaded workspace from the given resource.
///
/// ```
/// use lancelot::rsrc::*;
/// let ws = get_workspace(Rsrc::K32);
/// ```
pub fn get_workspace(rsrc: Rsrc) -> super::Workspace {
    let path = get_path(rsrc);
    let buf = get_buf(rsrc);
    super::Workspace::from_buf(&path, buf).unwrap()
}
