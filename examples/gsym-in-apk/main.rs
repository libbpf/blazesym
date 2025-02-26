//! An example illustrating how to use **blazesym** for hooking into the APK
//! symbolization path and using a custom "resolver" that uses Gsym information
//! to symbolize addresses, as opposed to the default one that only looks
//! directly at members and their ELF/DWARF symbols.

#![allow(clippy::collapsible_if)]

use std::fs::File;
use std::path::Path;
use std::path::PathBuf;

use blazesym::helper::GsymResolver;
use blazesym::inspect;
use blazesym::symbolize;
use blazesym::symbolize::ApkMemberInfo;
use blazesym::symbolize::FindSymOpts;
use blazesym::symbolize::Input;
use blazesym::symbolize::Reason;
use blazesym::symbolize::Resolve;
use blazesym::symbolize::ResolvedSym;
use blazesym::symbolize::Symbolize;
use blazesym::symbolize::Symbolizer;
use blazesym::symbolize::TranslateFileOffset;
use blazesym::Addr;
use blazesym::ErrorExt as _;
use blazesym::Mmap;
use blazesym::Result;

use goblin::elf64;
use zip::ZipArchive;


/// A resolver type that symbolizes APK addresses based on a Gsym file.
#[derive(Debug)]
struct CustomApkResolver {
    mmap: Mmap,
    gsym: GsymResolver,
}

impl Symbolize for CustomApkResolver {
    // The "core" resolver functionality is just forwarding the request to the
    // blazesym provided `GsymResolver`.
    #[inline]
    fn find_sym(&self, addr: Addr, opts: &FindSymOpts) -> Result<Result<ResolvedSym<'_>, Reason>> {
        self.gsym.find_sym(addr, opts)
    }
}

// Our resolver also needs to be able to translate file offsets into virtual
// offsets, as these are the "kind" of addresses that non-container
// symbolization sources use. Gsym does not provide such translation
// capabilities, which is why we use ELF data.
impl TranslateFileOffset for CustomApkResolver {
    fn file_offset_to_virt_offset(&self, file_offset: u64) -> Result<Option<Addr>> {
        let bytes = <[u8; 64]>::try_from(&self.mmap[0..64]).unwrap();
        let ehdr = elf64::header::Header::from_bytes(&bytes);
        let phdrs = elf64::program_header::ProgramHeader::from_bytes(
            &self.mmap[ehdr.e_phoff as usize..],
            ehdr.e_phnum.into(),
        );
        let addr = phdrs.iter().find_map(|phdr| {
            if phdr.p_type == elf64::program_header::PT_LOAD {
                if (phdr.p_offset..phdr.p_offset + phdr.p_filesz).contains(&file_offset) {
                    return Some((file_offset - phdr.p_offset + phdr.p_vaddr) as Addr)
                }
            }
            None
        });

        Ok(addr)
    }
}

fn dispatch_apk(info: ApkMemberInfo<'_>) -> Result<Option<Box<dyn Resolve>>> {
    let ApkMemberInfo {
        apk_path: _,
        member_path,
        member_mmap,
        ..
    } = info;

    assert_eq!(member_path, Path::new("libtest-so.so"));

    // We know that the offset we attempt to symbolize maps to binary that is
    // represented by this Gsym file, so we hard code its path. In a more
    // realistic setting one way want to look up a file in the file system based
    // on the member name, its build ID, or whatever else.
    let gsym = GsymResolver::open(
        Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("data")
            .join("libtest-so.gsym"),
    )?;
    let resolver = CustomApkResolver {
        mmap: member_mmap,
        gsym,
    };
    Ok(Some(Box::new(resolver)))
}

/// Retrieve the path to our test APK file.
fn apk_path() -> PathBuf {
    Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("data")
        .join("test.zip")
}

/// Find the file offset of the `the_answer` function inside the `libtest-so.so`
/// test binary inside the `test.zip` zip archive.
fn find_the_answer_fn_file_offset() -> Addr {
    let so = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("data")
        .join("libtest-so.so");
    let inspector = inspect::Inspector::new();
    let src = inspect::source::Source::from(inspect::source::Elf::new(so));
    let syms = inspector
        .lookup(&src, &["the_answer"])
        .unwrap()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    assert_eq!(syms.len(), 1);
    let fn_offset = syms[0].file_offset.unwrap();

    let apk = apk_path();
    let apk_file = File::open(apk).unwrap();
    let mut zip = ZipArchive::new(apk_file).unwrap();
    let so = zip.by_name("libtest-so.so").unwrap();

    let apk_offset = so.data_start();
    apk_offset + fn_offset
}

fn main() -> Result<()> {
    let fn_file_offset = find_the_answer_fn_file_offset();
    let apk = apk_path();
    let src = symbolize::source::Source::Apk(symbolize::source::Apk::new(apk));
    let symbolizer = Symbolizer::builder()
        // Set a custom "dispatcher" function for symbolizing APKs. This will
        // cause the library to invoke our `dispatch_apk` function with some
        // information about the member of an APK that an address to symbolize
        // falls into.
        .set_apk_dispatcher(dispatch_apk)
        .build();
    let sym = symbolizer
        // NB: File offset was retrieved above. In a more realistic setting it
        //     would likely be produced by our normalization APIs.
        .symbolize_single(&src, Input::FileOffset(fn_file_offset))
        .with_context(|| format!("failed to symbolize file offset {fn_file_offset:#x}"))?;
    println!("{sym:?}");
    Ok(())
}
