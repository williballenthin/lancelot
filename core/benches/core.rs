use criterion::{criterion_group, criterion_main, Criterion};

fn emu_fetch_benchmark(c: &mut Criterion) {
    // 0:  48 c7 c0 01 00 00 00    mov    rax,0x1
    let mut emu = lancelot::test::emu_from_shellcode64(&b"\x48\xC7\xC0\x01\x00\x00\x00"[..]);
    emu.reg.rip = 0x0;

    c.bench_function("fetch", |b| {
        b.iter(|| {
            emu.mem.read_u128(criterion::black_box(0x0)).unwrap();
        })
    });

    c.bench_function("fetch and decode", |b| {
        b.iter(|| {
            emu.fetch().unwrap();
        })
    });
}

fn emu_insn_benchmark(c: &mut Criterion) {
    c.bench_function("mov rax, 0x1", |b| {
        // 0:  48 c7 c0 01 00 00 00    mov    rax,0x1
        let mut emu = lancelot::test::emu_from_shellcode64(&b"\x48\xC7\xC0\x01\x00\x00\x00"[..]);
        b.iter(|| {
            emu.reg.rip = 0x0;
            emu.step().unwrap();
        })
    });

    c.bench_function("push 0x1", |b| {
        // 0:  6a 01                   push   0x1
        let mut emu = lancelot::test::emu_from_shellcode64(&b"\x6A\x01"[..]);
        b.iter(|| {
            emu.reg.rip = 0x0;
            emu.reg.rsp = 0x6000;
            emu.step().unwrap();
        })
    });

    c.bench_function("sub rax, rbx", |b| {
        // 0:  48 29 d8                sub    rax,rbx
        let mut emu = lancelot::test::emu_from_shellcode64(&b"\x48\x29\xD8"[..]);
        b.iter(|| {
            emu.reg.rip = 0x0;
            emu.reg.rax = 0x1;
            emu.reg.rbx = 0x1;
            emu.step().unwrap();
        })
    });

    c.bench_function("add rax, rbx", |b| {
        // 0:  48 01 d8                add    rax,rbx
        let mut emu = lancelot::test::emu_from_shellcode64(&b"\x48\x01\xD8"[..]);
        b.iter(|| {
            emu.reg.rip = 0x0;
            emu.reg.rax = 0x1;
            emu.reg.rbx = 0x1;
            emu.step().unwrap();
        })
    });
}

fn cfg_benchmark(c: &mut Criterion) {
    use lancelot::analysis::cfg::instruction_index::*;

    c.bench_function("cfg::InstructionIndex::build_index", |b| {
        let buf = lancelot::rsrc::get_buf(lancelot::rsrc::Rsrc::K32);
        let pe = lancelot::loader::pe::PE::from_bytes(&buf).unwrap();

        let mut functions: Vec<_> = Default::default();
        functions.extend(lancelot::analysis::pe::entrypoints::find_pe_entrypoint(&pe).unwrap());
        functions.extend(lancelot::analysis::pe::exports::find_pe_exports(&pe).unwrap());

        b.iter(|| {
            let mut insns: InstructionIndex = Default::default();

            for &function in functions.iter() {
                insns.build_index(&pe.module, function).unwrap();
            }
        })
    });

    c.bench_function("cfg::CFG::from_instructions", |b| {
        let buf = lancelot::rsrc::get_buf(lancelot::rsrc::Rsrc::K32);
        let pe = lancelot::loader::pe::PE::from_bytes(&buf).unwrap();

        let mut functions: Vec<_> = Default::default();
        functions.extend(lancelot::analysis::pe::entrypoints::find_pe_entrypoint(&pe).unwrap());
        functions.extend(lancelot::analysis::pe::exports::find_pe_exports(&pe).unwrap());

        let mut insns: InstructionIndex = Default::default();
        for &function in functions.iter() {
            insns.build_index(&pe.module, function).unwrap();
        }

        b.iter(|| CFG::from_instructions(insns.clone()))
    });
}

criterion_group!(cfg, cfg_benchmark);
criterion_group!(emu_fetch, emu_fetch_benchmark);
criterion_group!(emu_insn, emu_insn_benchmark);
criterion_main!(emu_fetch, emu_insn, cfg);
