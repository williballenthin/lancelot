use std::collections::BTreeMap;

use anyhow::Result;
use log::debug;

use crate::{
    analysis::{
        dis,
        pe::{Import, ImportedSymbol},
    },
    aspace::AddressSpace,
    module::{Module, Permissions},
    VA,
};
use lancelot_flirt::*;

const EMPTY_CONTEXT: zydis::ffi::RegisterContext = zydis::ffi::RegisterContext {
    values: [0u64; zydis::REGISTER_MAX_VALUE + 1],
};

/// make a best guess for the reference target, found at `ref_offset` from `va`.
///
/// flirt uses references `(offset, name)` to describe that a function contains
/// a pointer to some known name (usually also matched by flirt).
/// the offset is relative to the start of the function, and may point in the
/// middle of an instruction!
/// (this is probably an artifact of extracting via relocations in lib files.)
///
/// its a problem because we don't know where the instruction,
/// so its hard to inspect operands for pointers.
/// we could either disassemble the entire function and find instruction ranges,
/// or scan backwards looking for potential instructions.
/// we do the latter here, as it works well in practice.
///
/// from the given address `ref_offset`, we disassemble backwards, up to -4
/// bytes. at each location, we inspect the operands. if it could be a pointer,
/// then we use metadata provided by zydis for the offset of the operand data.
/// (this is a great feature of zydis!)
/// the offset of the operand pointer data should match the number of bytes
/// we've disassembled backwards, that is, the pointer is found at the
/// reference address.
///
/// in practice, many references look like `call FOO` which is `E8 ?? ?? ?? ??`
/// and we recover the reference on the first try.
fn guess_reference_target(
    module: &Module,
    decoder: &zydis::Decoder,
    va: VA,
    ref_offset: u64,
    perms: Permissions,
) -> Option<VA> {
    // scan from -1 to -4 bytes backwards from the reference
    for i in (1..=4u64).rev() {
        let candidate_insn_va = va + ref_offset - i;
        let mut insn_buf = [0u8; 16];

        if module.address_space.read_into(candidate_insn_va, &mut insn_buf).is_ok() {
            if let Ok(Some(insn)) = dis::decode(decoder, &insn_buf) {
                // we assume the pointer will be found in the first two explicit operands,
                // which works well for x86.
                for (j, op) in dis::get_operands(&insn).take(2).enumerate() {
                    match &op.kind {
                        dis::DecodedOperandKind::Mem(mem) => {
                            if (mem.base == zydis::Register::NONE || mem.base == zydis::Register::RIP)
                                && mem.disp.has_displacement
                                && insn.raw.disp.offset == i as u8
                            {
                                if let Ok(target) = insn.calc_absolute_address_ex(candidate_insn_va, op, &EMPTY_CONTEXT)
                                {
                                    if module.probe_va(target, perms) {
                                        return Some(target);
                                    }
                                }
                            }
                            continue;
                        }
                        dis::DecodedOperandKind::Imm(_) => {
                            if insn.raw.imm[j].offset == i as u8 {
                                if let Ok(target) = insn.calc_absolute_address(candidate_insn_va, op) {
                                    if module.probe_va(target, perms) {
                                        return Some(target);
                                    }
                                }
                            }
                            continue;
                        }
                        dis::DecodedOperandKind::Ptr(_) => continue,
                        dis::DecodedOperandKind::Reg(_) => continue,
                        dis::DecodedOperandKind::Unused => continue,
                    }
                }
            }
        }
    }

    None
}

/// the maximum number of bytes read from the function start for signature
/// matching.
///
/// a FLIRT signature only ever examines a bounded prefix of a function:
/// the 32-byte pattern, up to 255 CRC16 bytes, and tail bytes/footer after
/// that (tail bytes reach about 7k bytes into the function, in the FLARE
/// MSVC runtime signatures). this cap is beyond those.
///
/// without a cap, each candidate function reads from its start to the end
/// of its section, which is O(functions × section size) bytes of copying
/// per FLIRT pass (and again for each recursive reference match).
const MATCH_WINDOW_SIZE: u64 = 0x8000;

/// does the signature name the function it recognizes `wanted`?
fn has_name_at_start(sig: &FlirtSignature, wanted: &str) -> bool {
    sig.names.iter().any(|name| match name {
        Symbol::Reference(_) => false,
        Symbol::Local(Name { name, offset }) | Symbol::Public(Name { name, offset }) => {
            *offset == 0 && name == wanted && name != UNRESOLVED_COLLISION
        }
    })
}

/// could a signature refer to this import by the name `wanted`?
///
/// signatures name the import's address table entry, like `__imp_CloseHandle`,
/// or the function, like `CloseHandle`; and 32-bit names may be decorated,
/// like `_malloc` (cdecl), `_CloseHandle@4` (stdcall), or `@Foo@4` (fastcall).
fn is_import_named(import: &Import, wanted: &str) -> bool {
    let ImportedSymbol::Name(name) = &import.symbol else {
        return false;
    };

    let wanted = wanted.strip_prefix("__imp_").unwrap_or(wanted);
    if wanted == name {
        return true;
    }

    let undecorated = match wanted.rsplit_once('@') {
        Some((head, n)) if !head.is_empty() && !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()) => head,
        _ => wanted,
    };
    let undecorated = undecorated.strip_prefix(['_', '@']).unwrap_or(undecorated);
    undecorated == name
}

/// match the given flirt signatures at the given address.
/// returns a list of the signatures that match.
///
/// a signature's references must name what they point to:
/// either code that a signature recognizes, recursively,
/// or an entry of the import address table, using `imports`.
pub fn match_flirt(
    module: &Module,
    sigs: &FlirtSignatureSet,
    imports: &BTreeMap<VA, Import>,
    va: VA,
) -> Result<Vec<FlirtSignature>> {
    fn match_flirt_inner(
        module: &Module,
        sigs: &FlirtSignatureSet,
        imports: &BTreeMap<VA, Import>,
        decoder: &zydis::Decoder,
        va: VA,
        cache: &mut BTreeMap<VA, Vec<FlirtSignature>>,
    ) -> Result<Vec<FlirtSignature>> {
        let sec = match module
            .sections
            .iter()
            .find(|sec| sec.virtual_range.start <= va && va < sec.virtual_range.end)
        {
            Some(sec) => sec,
            None => {
                // the address isn't found within any section,
                // such as a malformed PE whose entrypoint points outside of mapped memory.
                // there's no code here, so there's nothing to match.
                // see: https://github.com/mandiant/flare-floss/issues/1345
                debug!("flirt: {:#x}: address not within any section", va);
                return Ok(Default::default());
            }
        };

        let size = u64::min(sec.virtual_range.end - va, MATCH_WINDOW_SIZE);
        let buf = module.address_space.read_bytes(va, size as usize)?;

        debug!("flirt: matching: {:#x}", va);

        // candidates often have references at the same offsets, like the
        // ~1.5k signatures that share the 2-byte pattern of a `jmp [import]` thunk,
        // so recover each reference target once.
        let mut targets: BTreeMap<(u64, u8), Option<VA>> = Default::default();
        let mut guess_reference_target = |offset: u64, perms: Permissions| {
            *targets
                .entry((offset, perms.bits()))
                .or_insert_with(|| guess_reference_target(module, decoder, va, offset, perms))
        };

        Ok(sigs
            .r#match(&buf)
            .into_iter()
            .filter(|sig| {
                debug!("flirt: {:#x}: candidate: {:?}", va, sig);

                sig.names.iter().all(|name| {
                    let Symbol::Reference(Name { offset, name: wanted }) = name else {
                        return true;
                    };

                    // offsets are from the function start. we don't know what a negative one means.
                    let Ok(offset) = u64::try_from(*offset) else {
                        return false;
                    };

                    if wanted == "." {
                        // special case: name "." matches any data?
                        // not exactly sure if this should only match special data `ctype`?
                        // see: https://github.com/williballenthin/lancelot/issues/112#issuecomment-802379966
                        return guess_reference_target(offset, Permissions::R).is_some();
                    }

                    // code: match flirt signatures there, and look for the wanted name.
                    //
                    // we use the cache to record whether a negative match was encountered.
                    // this drastically when we have many nested references (like CALL wrappers).
                    // see: https://github.com/fireeye/capa/issues/448
                    if let Some(target) = guess_reference_target(offset, Permissions::X) {
                        // a reference to this function itself, like a recursive call,
                        // is named by this signature.
                        if target == va && has_name_at_start(sig, wanted) {
                            return true;
                        }

                        if !cache.contains_key(&target) {
                            // while matching there, a reference back to here (or to there)
                            // finds no names, rather than recursing without end.
                            cache.insert(target, Default::default());
                            let target_sigs =
                                match_flirt_inner(module, sigs, imports, decoder, target, cache).unwrap_or_default();
                            cache.insert(target, target_sigs);
                        }

                        if cache[&target]
                            .iter()
                            .any(|target_sig| has_name_at_start(target_sig, wanted))
                        {
                            debug!("flirt: {:#x}: found reference: {} @ {:#x}", va, wanted, offset);
                            return true;
                        }
                    }

                    // an import: its address table entry has no code to match, but it has a name.
                    if let Some(import) =
                        guess_reference_target(offset, Permissions::R).and_then(|target| imports.get(&target))
                    {
                        if is_import_named(import, wanted) {
                            debug!("flirt: {:#x}: found import reference: {} @ {:#x}", va, wanted, offset);
                            return true;
                        }
                    }

                    false
                })
            })
            .cloned()
            .collect::<Vec<_>>())
    }

    let decoder = dis::get_disassembler(module)?;
    let mut cache = Default::default();
    match_flirt_inner(module, sigs, imports, &decoder, va, &mut cache)
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use crate::rsrc::*;

    /// a PE with a `.text` section with `VirtualSize == 0` used to panic
    /// during FLIRT matching, because no mapped section contained the
    /// entrypoint.
    /// see: https://github.com/mandiant/flare-floss/issues/1345
    #[test]
    fn zero_length_section() -> Result<()> {
        let buf = get_buf(Rsrc::ZEROSEC);
        let pe = crate::loader::pe::PE::from_bytes(&buf)?;

        let sigs = lancelot_flirt::FlirtSignatureSet::with_signatures(vec![]);

        // must not panic, even if a function start (like the entrypoint)
        // falls outside of all mapped sections.
        for va in crate::analysis::pe::find_function_starts(&pe)? {
            super::match_flirt(&pe.module, &sigs, &Default::default(), va)?;
        }

        // must not panic for addresses outside of all mapped sections,
        // such as when a malformed PE has an entrypoint in unmapped memory.
        assert!(super::match_flirt(&pe.module, &sigs, &Default::default(), 0x999_9000)?.is_empty());

        Ok(())
    }

    #[test]
    fn import_names() {
        use crate::analysis::pe::{Import, ImportedSymbol};
        let import = |name: &str| Import {
            address: 0x1000,
            dll:     "kernel32.dll".into(),
            symbol:  ImportedSymbol::Name(name.into()),
        };

        assert!(super::is_import_named(&import("CloseHandle"), "CloseHandle"));
        assert!(super::is_import_named(&import("CloseHandle"), "__imp_CloseHandle"));
        assert!(super::is_import_named(&import("CloseHandle"), "__imp__CloseHandle@4"));
        assert!(super::is_import_named(&import("CloseHandle"), "_CloseHandle@4"));
        assert!(super::is_import_named(
            &import("ExReleaseResourceLite"),
            "__imp_@ExReleaseResourceLite@4"
        ));
        assert!(super::is_import_named(&import("malloc"), "__imp__malloc"));
        assert!(super::is_import_named(
            &import("_aligned_malloc"),
            "__imp__aligned_malloc"
        ));
        assert!(super::is_import_named(
            &import("?terminate@@YAXXZ"),
            "__imp_?terminate@@YAXXZ"
        ));

        assert!(!super::is_import_named(&import("CloseHandle"), "OpenHandle"));
        assert!(!super::is_import_named(&import("CloseHandle"), "CloseHandleEx"));
        let ordinal = Import {
            address: 0x1000,
            dll:     "kernel32.dll".into(),
            symbol:  ImportedSymbol::Ordinal(1),
        };
        assert!(!super::is_import_named(&ordinal, "CloseHandle"));
    }

    /// signatures whose references name an import can match.
    #[test]
    fn match_flirt_import_reference() -> Result<()> {
        // `jmp [SysAllocStringLen]`, recognized by the signature
        // `ff25 00 0000 0006 :0000 _SysAllocStringLen@8 ^0002 SysAllocStringLen`.
        let buf = get_buf(Rsrc::I236B);
        let pe = crate::loader::pe::PE::from_bytes(&buf)?;
        let sigs = get_config().get_sigs()?;
        let imports = crate::analysis::pe::get_imports(&pe)?;

        let matches = super::match_flirt(&pe.module, &sigs, &imports, 0x4037C8)?;
        let names: Vec<_> = matches.iter().filter_map(|m| m.get_name()).collect();
        assert_eq!(names, vec!["_SysAllocStringLen@8"]);

        // without the imports, the reference can't be resolved.
        assert!(super::match_flirt(&pe.module, &sigs, &Default::default(), 0x4037C8)?.is_empty());

        Ok(())
    }

    /// a reference back to the function itself must not recurse without end.
    #[test]
    fn match_flirt_self_reference() -> Result<()> {
        // nop.exe 0x40130c + 0x45 is the operand of a call back to 0x40130c.
        let buf = get_buf(Rsrc::NOP);
        let pe = crate::loader::pe::PE::from_bytes(&buf)?;
        const PAT: &str = "\
f6410c407406837908007424ff4904780b8b118802ff010fb6c0eb0c0fbec051 00 0000 0050 :0000 recurse ^0045 recurse
f6410c407406837908007424ff4904780b8b118802ff010fb6c0eb0c0fbec051 00 0000 0050 :0000 other ^0045 missing
---
";
        let sigs = lancelot_flirt::FlirtSignatureSet::with_signatures(lancelot_flirt::pat::parse(PAT)?);

        let matches = super::match_flirt(&pe.module, &sigs, &Default::default(), 0x40130C)?;
        let names: Vec<_> = matches.iter().filter_map(|m| m.get_name()).collect();
        // the first signature names the function itself, as its reference requires.
        // nothing names it `missing`.
        assert_eq!(names, vec!["recurse"]);

        Ok(())
    }

    #[test]
    fn match_flirt_nop() -> Result<()> {
        // recognize _exit in nop.exe via the msvc runtime signatures,
        // end to end against a real PE, within the bounded match window.
        let buf = get_buf(Rsrc::NOP);
        let pe = crate::loader::pe::PE::from_bytes(&buf)?;
        let sigs = get_config().get_sigs()?;

        let imports = crate::analysis::pe::get_imports(&pe)?;
        let matches = super::match_flirt(&pe.module, &sigs, &imports, 0x401DA9)?;
        assert!(
            matches.iter().any(|m| m.get_name() == Some("_exit")),
            "expected _exit at 0x401DA9, got: {matches:?}"
        );

        Ok(())
    }
}
