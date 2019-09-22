// from: https://github.com/Maktm/FLIRTDB/blob/1f5763535e02d7cccf2f90a96a8ebaa36e9b2495/cmt/windows/libcmt_15_msvc_x86.pat#L354
//
//     6AFF5064A100000000508B44240C64892500000000896C240C8D6C240C50F2C3 00 0000 0020 :0000 __EH_prolog
//
// take that first column and treat it as a byte signature:
//
//     rule __EH_prolog : flirt
//     {
//         strings:
//             $bytes = {6AFF5064A100000000508B44240C64892500000000896C240C8D6C240C50F2C3}
//         condition:
//             $bytes
//     }
//
// and search for it:
//
//     $ yara src/analysis/pe/flirt/__EH_prolog.yara /mnt/c/Windows/SysWOW64/
//     __EH_prolog /mnt/c/Windows/SysWOW64//ucrtbase.dll
//     __EH_prolog /mnt/c/Windows/SysWOW64//ucrtbased.dll
//     __EH_prolog /mnt/c/Windows/SysWOW64//vcruntime140.dll
//     __EH_prolog /mnt/c/Windows/SysWOW64//vcruntime140_clr0400.dll
//     __EH_prolog /mnt/c/Windows/SysWOW64//vcruntime140d.dll
// ```
#[macro_use] extern crate nom;

use regex::bytes::Regex;


pub mod pat;


pub struct ByteSignature(Regex);

pub struct Name {
    offset: u16,
    name: String,
}

pub struct FlirtSignature {
    byte_sig: ByteSignature,

    /// number of bytes passed to the CRC16 checksum
    size_of_bytes_crc16: u8,  // max: 0xFF
    crc16: u16,
    size_of_function: u16,  // max: 0x8000

    public_names: Vec<Name>,
    local_names: Vec<Name>,
    referenced_names: Vec<Name>,
}
