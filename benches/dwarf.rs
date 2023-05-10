use std::path::Path;

use blazesym::inspect;
use blazesym::inspect::Inspector;

use criterion::measurement::Measurement;
use criterion::BenchmarkGroup;


/// Lookup an address, end-to-end, i.e., including all necessary setup.
fn lookup_end_to_end() {
    let dwarf_vmlinux = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("vmlinux-5.17.12-100.fc34.x86_64");
    let src = inspect::Source::Elf(inspect::Elf::new(dwarf_vmlinux));

    let inspector = Inspector::new();
    let results = inspector
        .lookup(&["abort_creds"], &src)
        .unwrap()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    assert_eq!(results.len(), 1);

    let result = results.first().unwrap();
    assert_eq!(result.address, 0xffffffff8110ecb0);
}

pub fn benchmark<M>(group: &mut BenchmarkGroup<'_, M>)
where
    M: Measurement,
{
    if cfg!(feature = "generate-bench-files") {
        group.bench_function(stringify!(dwarf::lookup_end_to_end), |b| {
            b.iter(lookup_end_to_end)
        });
    }
}
