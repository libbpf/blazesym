//! An example illustrating usage of the library to produce virtual offsets as
//! opposed to file offsets from the normalization step by applying some
//! post-processing.

#![allow(clippy::fn_to_numeric_cast)]

use blazesym::helper::ElfResolver;
use blazesym::normalize::Normalizer;
use blazesym::symbolize::Elf;
use blazesym::symbolize::Input;
use blazesym::symbolize::Source;
use blazesym::symbolize::Symbolizer;
use blazesym::symbolize::TranslateFileOffset as _;
use blazesym::Addr;
use blazesym::Pid;


fn main() {
    let normalizer = Normalizer::new();
    let normalized = normalizer
        .normalize_user_addrs(Pid::Slf, [main as Addr].as_slice())
        .unwrap();
    assert_eq!(normalized.outputs.len(), 1);

    // Normalization reports file offsets, but there are cases where virtual
    // addresses may be the more desirable output (e.g., when only split DWARF
    // information is available for later symbolization, which may not directly
    // be able to handle file offsets, but it does support virtual offsets).
    // Hence, we post-process the output to convert from one to the other.
    let (file_offset, meta_idx) = normalized.outputs[0];
    // Find the meta data entry so that we can look at the binary to which
    // the file offset belongs directly.
    let meta = &normalized.meta[meta_idx];
    let elf = meta.as_elf().unwrap();
    let resolver = ElfResolver::open(&elf.path).unwrap();
    // Translate the reported file offset into a virtual address.
    let virt_offset = resolver
        .file_offset_to_virt_offset(file_offset)
        .unwrap()
        .unwrap();

    // Just for illustration purposes, symbolize the virtual offset now.
    let symbolizer = Symbolizer::new();
    let src = Source::Elf(Elf::new(&elf.path));
    let sym = symbolizer
        .symbolize_single(&src, Input::VirtOffset(virt_offset))
        .unwrap()
        .into_sym()
        .unwrap();
    assert_eq!(sym.name, "normalize_virt_offset::main");
}
