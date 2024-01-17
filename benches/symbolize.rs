#![allow(clippy::fn_to_numeric_cast)]

use std::hint::black_box;
use std::path::Path;

use blazesym::symbolize::Breakpad;
use blazesym::symbolize::Elf;
use blazesym::symbolize::GsymFile;
use blazesym::symbolize::Input;
use blazesym::symbolize::Process;
use blazesym::symbolize::Source;
use blazesym::symbolize::Symbolizer;
use blazesym::Addr;
use blazesym::Pid;

use criterion::measurement::Measurement;
use criterion::Bencher;
use criterion::BenchmarkGroup;


/// Symbolize addresses in the current process.
fn symbolize_process() {
    let src = Source::Process(Process::new(Pid::Slf));
    let addrs = [
        libc::__errno_location as Addr,
        libc::dlopen as Addr,
        libc::fopen as Addr,
        symbolize_process as Addr,
        Symbolizer::symbolize_single as Addr,
    ];

    let symbolizer = Symbolizer::new();
    let results = symbolizer
        .symbolize(black_box(&src), black_box(Input::AbsAddr(&addrs)))
        .unwrap();
    assert_eq!(results.len(), addrs.len());
}

/// Symbolize an address in a Breakpad (*.sym) file, end-to-end, i.e.,
/// including all necessary setup.
fn symbolize_breakpad() {
    let sym_vmlinux = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("vmlinux-5.17.12-100.fc34.x86_64.sym");
    let src = Source::from(Breakpad::new(sym_vmlinux));
    let symbolizer = Symbolizer::new();

    let result = symbolizer
        .symbolize_single(black_box(&src), black_box(Input::FileOffset(0x10ecb0)))
        .unwrap()
        .into_sym()
        .unwrap();

    assert_eq!(result.name, "abort_creds");
    assert_eq!(result.code_info.as_ref().unwrap().line, Some(534));
}

/// Symbolize an address in an ELF file, end-to-end, i.e., including all
/// necessary setup.
fn symbolize_elf() {
    let elf_vmlinux = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("vmlinux-5.17.12-100.fc34.x86_64.elf");
    let mut elf = Elf::new(elf_vmlinux);
    elf.debug_syms = false;
    let src = Source::Elf(elf);

    let symbolizer = Symbolizer::builder().enable_code_info(false).build();
    let result = symbolizer
        .symbolize_single(
            black_box(&src),
            black_box(Input::VirtOffset(0xffffffff8110ecb0)),
        )
        .unwrap()
        .into_sym()
        .unwrap();

    assert_eq!(result.name, "abort_creds");
}

/// Symbolize an address in a DWARF file, excluding line information,
/// end-to-end, i.e., including all necessary setup.
fn symbolize_dwarf_no_lines() {
    let dwarf_vmlinux = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("vmlinux-5.17.12-100.fc34.x86_64.dwarf");
    let src = Source::Elf(Elf::new(dwarf_vmlinux));
    let symbolizer = Symbolizer::builder().enable_code_info(false).build();

    let result = symbolizer
        .symbolize_single(
            black_box(&src),
            black_box(Input::VirtOffset(0xffffffff8110ecb0)),
        )
        .unwrap()
        .into_sym()
        .unwrap();

    assert_eq!(result.name, "abort_creds");
    assert_eq!(result.code_info.as_ref(), None);
}

/// Symbolize an address in a DWARF file, end-to-end, i.e., including all
/// necessary setup.
fn symbolize_dwarf() {
    let dwarf_vmlinux = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("vmlinux-5.17.12-100.fc34.x86_64.dwarf");
    let src = Source::Elf(Elf::new(dwarf_vmlinux));
    let symbolizer = Symbolizer::new();

    let result = symbolizer
        .symbolize_single(
            black_box(&src),
            black_box(Input::VirtOffset(0xffffffff8110ecb0)),
        )
        .unwrap()
        .into_sym()
        .unwrap();

    assert_eq!(result.name, "abort_creds");
    assert_eq!(result.code_info.as_ref().unwrap().line, Some(534));
}

/// Symbolize an address in a Gsym file, end-to-end, i.e., including all
/// necessary setup.
fn symbolize_gsym() {
    let gsym_vmlinux = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("vmlinux-5.17.12-100.fc34.x86_64.gsym");
    let src = Source::from(GsymFile::new(gsym_vmlinux));
    let symbolizer = Symbolizer::new();

    let result = symbolizer
        .symbolize_single(
            black_box(&src),
            black_box(Input::VirtOffset(0xffffffff8110ecb0)),
        )
        .unwrap()
        .into_sym()
        .unwrap();

    assert_eq!(result.name, "abort_creds");
}

/// Symbolize multiple addresses in a Gsym file.
///
/// Addresses with high inlined function count were chosen, to
/// illustrate impact of reporting large numbers of them.
fn symbolize_gsym_multi_no_setup<M>(b: &mut Bencher<'_, M>)
where
    M: Measurement,
{
    let gsym_vmlinux = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("vmlinux-5.17.12-100.fc34.x86_64.gsym");
    let src = Source::from(GsymFile::new(gsym_vmlinux));
    let symbolizer = Symbolizer::new();

    // Addresses of instructions with an inlined function count >= 12.
    let addrs = &[
        0xffffffff812d527c,
        0xffffffff812d5285,
        0xffffffff812d9677,
        0xffffffff812dc48a,
        0xffffffff812dc4a2,
        0xffffffff812dc52d,
    ];

    let () = b.iter(|| {
        let result = symbolizer
            .symbolize(black_box(&src), black_box(Input::VirtOffset(addrs)))
            .unwrap();
        let _result = black_box(result);
    });
}


pub fn benchmark<M>(group: &mut BenchmarkGroup<'_, M>)
where
    M: Measurement,
{
    bench_fn!(group, symbolize_process);
    bench_fn!(group, symbolize_breakpad);
    bench_fn!(group, symbolize_elf);
    bench_fn!(group, symbolize_dwarf_no_lines);
    bench_fn!(group, symbolize_dwarf);
    bench_fn!(group, symbolize_gsym);
    bench_sub_fn!(group, symbolize_gsym_multi_no_setup);
}
