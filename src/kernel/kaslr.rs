use std::fs::File;
use std::mem::size_of;
use std::path::Path;
use std::str;

use crate::elf;
use crate::elf::types::ElfN_Nhdr;
use crate::elf::BackendImpl;
use crate::elf::ElfParser;
use crate::inspect::FindAddrOpts;
use crate::inspect::Inspect;
use crate::log;
use crate::util::align_up_u32;
use crate::util::from_radix_16;
use crate::util::split_bytes;
use crate::ErrorExt as _;
use crate::ErrorKind;
use crate::IntoError as _;
use crate::Result;


/// The absolute path to the `kcore` `proc` node.
const PROC_KCORE: &str = "/proc/kcore";
/// The name of the `VMCOREINFO` ELF note.
///
/// See <https://www.kernel.org/doc/html/latest/admin-guide/kdump/vmcoreinfo.html>
const VMCOREINFO_NAME: &[u8] = b"VMCOREINFO\0";


/// "Parse" the VMCOREINFO descriptor.
///
/// This underspecified blob roughly has the following format:
/// ```text
/// OSRELEASE=6.2.15-100.fc36.x86_64
/// BUILD-ID=d3d01c80278f8927486b7f01d0ab6be77784dceb
/// PAGESIZE=4096
/// SYMBOL(init_uts_ns)=ffffffffb72b8160
/// OFFSET(uts_namespace.name)=0
/// [...]
/// ```
fn parse_vmcoreinfo_desc(desc: &[u8]) -> impl Iterator<Item = (&[u8], &[u8])> {
    desc.split(|&b| b == b'\n')
        .filter_map(|line| split_bytes(line, |b| b == b'='))
}

/// Find and read the `KERNELOFFSET` note in a "kcore" file represented by
/// `parser` (i.e., already opened as an ELF).
fn read_kcore_kaslr_offset(parser: &ElfParser<File>) -> Result<Option<u64>> {
    let phdrs = parser.program_headers()?;
    for phdr in phdrs.iter(0) {
        if phdr.type_() != elf::types::PT_NOTE {
            continue
        }

        let file = parser.backend();
        let mut offset = phdr.offset();

        // Iterate through all available notes. See `elf(5)` for
        // details.
        while offset + (size_of::<ElfN_Nhdr>() as u64) <= phdr.file_size() {
            let nhdr = file
                .read_pod_obj::<ElfN_Nhdr>(offset)
                .context("failed to read kcore note header")?;
            offset += size_of::<ElfN_Nhdr>() as u64;

            let name = if nhdr.n_namesz > 0 {
                let name = file.read_pod_slice::<u8>(offset, nhdr.n_namesz as _)?;
                offset += u64::from(align_up_u32(nhdr.n_namesz, 4));
                Some(name)
            } else {
                None
            };

            // We are looking for the note named `VMCOREINFO`.
            if name.as_deref() == Some(VMCOREINFO_NAME) {
                if nhdr.n_descsz > 0 {
                    let desc = file.read_pod_slice::<u8>(offset, nhdr.n_descsz as _)?;
                    let offset = parse_vmcoreinfo_desc(&desc)
                        .find(|(key, _value)| key == b"KERNELOFFSET")
                        // The value is in hexadecimal format. Go figure.
                        .map(|(_key, value)| {
                            from_radix_16(value).ok_or_invalid_data(|| {
                                format!("failed to parse KERNELOFFSET value `{value:x?}`")
                            })
                        })
                        .transpose();
                    return offset
                }

                // There shouldn't be multiple notes with that name,
                // but I suppose it can't hurt to keep checking...?
            }

            offset += u64::from(align_up_u32(nhdr.n_descsz, 4));
        }
    }
    Ok(None)
}

fn find_kcore_kaslr_offset() -> Result<Option<u64>> {
    // Note that we cannot use the regular mmap based ELF parser
    // backend for this file, as it cannot be mmap'ed. We have to
    // fall back to using regular I/O instead.
    let parser = match ElfParser::open_file_io(Path::new(PROC_KCORE)) {
        Ok(parser) => parser,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };
    let offset = read_kcore_kaslr_offset(&parser)?.inspect(|offset| {
        log::debug!("determined KASLR offset to be {offset:#x} based on {PROC_KCORE} contents");
    });
    Ok(offset)
}

/// Look up the address of an exact-named symbol through an [`Inspect`]
/// resolver, returning the first match.
fn inspect_sym_addr(resolver: &dyn Inspect, name: &str) -> Result<Option<u64>> {
    let syms = resolver.find_addr(name, &FindAddrOpts::default())?;
    // `KsymResolver::find_addr` reports symbols from a lower bound onward
    // rather than exact matches, so filter to the exact name.
    let sym = syms
        .into_iter()
        .find(|sym| sym.name.as_ref() == name)
        .map(|sym| sym.addr);
    Ok(sym)
}

/// Derive the KASLR offset by comparing the address of `_stext` as reported
/// by `kallsyms` (already KASLR-relocated) against its address in the
/// `vmlinux` image (link-time addresses).
///
/// `_stext` is documented by the kernel as indicating its start
/// address:
/// <https://www.kernel.org/doc/html/latest/admin-guide/kdump/vmcoreinfo.html#stext>
fn find_stext_kaslr_offset(
    ksym_resolver: &dyn Inspect,
    vmlinux_resolver: &dyn Inspect,
) -> Result<Option<u64>> {
    let stext_kallsyms = inspect_sym_addr(ksym_resolver, "_stext")?;
    let stext_vmlinux = inspect_sym_addr(vmlinux_resolver, "_stext")?;

    let offset = match (stext_kallsyms, stext_vmlinux) {
        (Some(stext_kallsyms), Some(stext_vmlinux)) => {
            stext_kallsyms.checked_sub(stext_vmlinux).inspect(|offset| {
                log::debug!("derived KASLR offset {offset:#x} from _stext symbol subtraction")
            })
        }
        _ => None,
    };
    Ok(offset)
}

pub(crate) fn find_kaslr_offset(
    ksym_resolver: Option<&dyn Inspect>,
    vmlinux_resolver: Option<&dyn Inspect>,
) -> Result<Option<u64>> {
    // TODO: Try other methods of determining KASLR offset, including
    //       comparisons between `/proc/kallsyms` values to
    //       `System.map-*` contents or parsing `dmesg` (no, really...)

    let result = find_kcore_kaslr_offset();
    let () = match result {
        Err(ref err)
            if matches!(
                err.kind(),
                ErrorKind::PermissionDenied | ErrorKind::NotFound
            ) =>
        {
            // For "expected" errors (e.g., `kcore` may not be available for
            // various reasons), keep trying other methods.
        }
        result => return result,
    };

    if let (Some(ksym), Some(vmlinux)) = (ksym_resolver, vmlinux_resolver) {
        return find_stext_kaslr_offset(ksym, vmlinux)
    }
    result
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::ops::Deref as _;
    use std::path::PathBuf;
    use std::rc::Rc;

    use test_log::test;

    use crate::kernel::cache::KernelCache;
    use crate::kernel::ksym::KsymResolver;


    /// Path to a small ELF fixture that does *not* contain `_stext`.
    fn stextless_path() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-stable-addrs.bin")
    }

    fn ksym_from_bytes(content: &[u8]) -> KsymResolver {
        KsymResolver::load_from_reader(&mut &*content, Path::new("<dummy>")).unwrap()
    }

    /// Stand-in for a vmlinux inspector able to resolve the `_stext`
    /// symbol.
    fn vmlinux_inspector() -> Box<dyn Inspect> {
        let inspector = ksym_from_bytes(
            b"ffffffff81000000 T _stext
ffffffff81000f60 T do_one_initcall
",
        );
        Box::new(inspector)
    }


    /// Check that we can parse a dummy VMCOREINFO descriptor.
    #[test]
    fn vmcoreinfo_desc_parsing() {
        let desc = b"OSRELEASE=6.2.15-100.fc36.x86_64
BUILD-ID=d3d01c80278f8927486b7f01d0ab6be77784dceb
SYMBOL(init_uts_ns)=ffffffffb72b8160
OFFSET(uts_namespace.name)=0
PAGESIZE=4096
";

        let page_size = parse_vmcoreinfo_desc(desc)
            .find(|(key, _value)| key == b"PAGESIZE")
            .map(|(_key, value)| value)
            .unwrap();
        assert_eq!(page_size, b"4096");
    }

    /// Check that we can determine the system's KASLR state.
    #[test]
    fn kaslr_offset_reading() {
        // Always attempt reading the KASLR offset to exercise the
        // VMCOREINFO parsing path.
        // Also, we care about the parsing logic, but can't make any
        // claims about the expected offset at this point.
        let _offset = find_kcore_kaslr_offset().unwrap();
    }

    /// Check that we correctly derive the KASLR offset via `_stext` method.
    #[test]
    fn stext_kaslr_offset_derived() {
        let ksym = ksym_from_bytes(
            b"ffffffff81abc000 T _stext
ffffffff81abf000 T do_one_initcall
",
        );
        let vmlinux = vmlinux_inspector();
        let offset = find_stext_kaslr_offset(&ksym, vmlinux.deref()).unwrap();
        assert_eq!(offset, Some(0xabc000));
    }

    /// Check that a kallsyms `_stext` exactly equal to vmlinux's `_stext`
    /// yields a zero KASLR offset.
    #[test]
    fn stext_kaslr_offset_zero() {
        let ksym = ksym_from_bytes(b"ffffffff81000000 T _stext\n");
        let vmlinux = vmlinux_inspector();

        let offset = find_stext_kaslr_offset(&ksym, vmlinux.deref()).unwrap();
        assert_eq!(offset, Some(0));
    }

    /// Check that a missing `_stext` in kallsyms surfaces as no KASLR
    /// offset.
    #[test]
    fn stext_kaslr_offset_no_kallsyms_stext() {
        let ksym = ksym_from_bytes(b"ffffffff81abf000 T do_one_initcall\n");
        let vmlinux = vmlinux_inspector();

        let offset = find_stext_kaslr_offset(&ksym, vmlinux.deref()).unwrap();
        assert_eq!(offset, None);
    }

    /// Check that a missing `_stext` in vmlinux surfaces as `None`.
    #[test]
    fn stext_kaslr_offset_no_vmlinux_stext() {
        let ksym = ksym_from_bytes(b"ffffffff81abc000 T _stext\n");
        let cache = KernelCache::new(Rc::new([]));
        let vmlinux = cache.elf_resolver(&stextless_path(), false).unwrap();

        let offset = find_stext_kaslr_offset(&ksym, &**vmlinux).unwrap();
        assert_eq!(offset, None);
    }

    /// Check that a kallsyms `_stext` below vmlinux's `_stext` yields
    /// no KASLR offset.
    #[test]
    fn stext_kaslr_offset_underflow() {
        let ksym = ksym_from_bytes(b"ffffffff80000000 T _stext\n");
        let vmlinux = vmlinux_inspector();

        let offset = find_stext_kaslr_offset(&ksym, vmlinux.deref()).unwrap();
        assert_eq!(offset, None);
    }
}
