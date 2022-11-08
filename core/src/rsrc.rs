//! A module to assist with fetching test data from the crate's resources.
use std::path::PathBuf;

use super::util;

#[derive(Copy, Clone)]
pub enum Rsrc {
    /// A defanged 64-bit version of kernel32.dll.
    K32,
    /// from: https://www.bigmessowires.com/2015/10/08/a-handmade-executable-file/
    /// since it doesn't have any sections or optional header, good for testing
    /// corner cases.
    TINY,
    /// from: https://joenord.com/apps/nop/
    NOP,
    /// from: https://github.com/gentilkiwi/mimikatz/releases/tag/2.2.0-20190512
    MIMI,
    /// COFF file from libcurl
    ALTSVC,
}

/// Fetch the file system name of the given resource.
pub fn get_name(rsrc: Rsrc) -> String {
    match rsrc {
        Rsrc::K32 => String::from("k32.bin"),
        Rsrc::TINY => String::from("tiny.exe"),
        Rsrc::NOP => String::from("nop.exe"),
        Rsrc::MIMI => String::from("mimikatz.exe_"),
        Rsrc::ALTSVC => String::from("altsvc.c.obj"),
    }
}

/// Fetch the file system path of the given resource.
pub fn get_path(rsrc: Rsrc) -> String {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("resources");
    d.push("test");
    d.push(get_name(rsrc));
    String::from(d.to_str().unwrap())
}

/// Fetch the contents of the given resource.
pub fn get_buf(rsrc: Rsrc) -> Vec<u8> {
    let path = get_path(rsrc);
    let mut buf = util::read_file(&path).unwrap();
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
        Rsrc::MIMI => {
            // pass
        }
        Rsrc::ALTSVC => {
            // pass
        }
    }
    buf
}

pub fn get_config() -> Box<dyn crate::workspace::cfg::Configuration> {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("resources");
    path.push("test");
    path.push("cfg");

    Box::new(crate::workspace::cfg::FileSystemConfiguration::from_path(&path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_buf() {
        assert_eq!(get_buf(Rsrc::K32)[0], b'M');
        assert_eq!(get_buf(Rsrc::K32)[1], b'Z');
    }

    #[test]
    fn test_get_path() {
        assert!(get_path(Rsrc::K32).ends_with("k32.bin"));
    }

    #[test]
    fn test_get_name() {
        assert_eq!(get_name(Rsrc::K32), "k32.bin");
    }
}
