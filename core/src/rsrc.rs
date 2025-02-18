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
    /// AR archive from msvc
    LIBCMT,
    /// AR archive from msvc
    LIBCPMT,
    /// COFF file from libcmtd.lib
    TLSDYN,
    MFCM140,
    /// COFF file from MFCM140
    _1MFCM140,
    /// COFF file from MFCM140
    POSTDLLMAIN,
    /// EXE malware sample from VT
    DED0,
    /// EXE from Assemblage dataset with relocations
    CPP1,
}

/// Fetch the file system name of the given resource.
pub fn get_name(rsrc: Rsrc) -> String {
    match rsrc {
        Rsrc::K32 => String::from("k32.bin"),
        Rsrc::TINY => String::from("tiny.exe"),
        Rsrc::NOP => String::from("nop.exe"),
        Rsrc::MIMI => String::from("mimikatz.exe_"),
        Rsrc::ALTSVC => String::from("altsvc.c.obj"),
        Rsrc::LIBCMT => String::from("libcmt.lib"),
        Rsrc::LIBCPMT => String::from("libcpmt.lib"),
        Rsrc::TLSDYN => String::from("tlsdyn.obj"),
        Rsrc::MFCM140 => String::from("MFCM140.lib"),
        Rsrc::_1MFCM140 => String::from("1.MFCM140.dll"),
        Rsrc::POSTDLLMAIN => String::from("postdllmain.obj"),
        Rsrc::DED0 => String::from("ded0ee29af97496f27d810f6c16d78a3031d8c2193d5d2a87355f3e3ca58f9b3"),
        Rsrc::CPP1 => String::from("cpp1.exe_"),
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
        Rsrc::K32 | Rsrc::DED0 => {
            // deobfuscate the MZ header
            buf[0] = b'M';
            buf[1] = b'Z';
        }
        _ => {
            // pass
        }
    }
    buf
}

pub fn get_config() -> Box<dyn crate::workspace::config::Configuration> {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("resources");
    path.push("test");
    path.push("cfg");

    Box::new(crate::workspace::config::FileSystemConfiguration::from_path(&path))
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
