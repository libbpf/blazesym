use std::borrow::Cow;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::fmt::Debug;
use std::mem::swap;
use std::path::Path;
use std::path::PathBuf;
use std::rc::Rc;

use crate::elf::ElfBackend;
use crate::elf::ElfCache;
use crate::elf::ElfResolver;
use crate::gsym::GsymResolver;
use crate::kernel::KernelResolver;
use crate::ksym::KSymCache;
use crate::ksym::KALLSYMS;
use crate::log;
use crate::maps;
use crate::maps::PathMapsEntry;
use crate::normalize;
use crate::normalize::create_apk_elf_path;
use crate::normalize::normalize_apk_addr;
use crate::normalize::normalize_elf_addr;
use crate::normalize::normalize_sorted_user_addrs_with_entries;
use crate::util;
use crate::util::uname_release;
use crate::Addr;
use crate::ErrorExt as _;
use crate::IntSym;
use crate::Pid;
use crate::Result;
use crate::SrcLang;
use crate::SymResolver;

use super::source::Elf;
use super::source::Gsym;
use super::source::GsymData;
use super::source::GsymFile;
use super::source::Kernel;
use super::source::Process;
use super::source::Source;


/// Demangle a symbol name using the demangling scheme for the given language.
#[cfg(feature = "demangle")]
fn maybe_demangle(name: &str, language: SrcLang) -> String {
    match language {
        SrcLang::Rust => rustc_demangle::try_demangle(name)
            .ok()
            .as_ref()
            .map(|x| format!("{x:#}")),
        SrcLang::Cpp => cpp_demangle::Symbol::new(name)
            .ok()
            .and_then(|x| x.demangle(&Default::default()).ok()),
        SrcLang::Unknown => rustc_demangle::try_demangle(name)
            .map(|x| format!("{x:#}"))
            .ok()
            .or_else(|| {
                cpp_demangle::Symbol::new(name)
                    .ok()
                    .and_then(|sym| sym.demangle(&Default::default()).ok())
            }),
    }
    .unwrap_or_else(|| name.to_string())
}

#[cfg(not(feature = "demangle"))]
fn maybe_demangle(name: &str, _language: SrcLang) -> String {
    // Demangling is disabled.
    name.to_string()
}


/// Source code location information for a symbol or inlined function.
#[derive(Clone, Debug, PartialEq)]
pub struct CodeInfo {
    /// The directory in which the source file resides.
    pub dir: Option<PathBuf>,
    /// The file that defines the symbol.
    pub file: OsString,
    /// The line number of the symbolized instruction in the source
    /// code.
    ///
    /// This is the line number of the instruction of the address being
    /// symbolized, not the line number that defines the symbol
    /// (function).
    pub line: Option<u32>,
    /// The column number of the symbolized instruction in the source
    /// code.
    pub column: Option<u16>,
    /// The struct is non-exhaustive and open to extension.
    pub(crate) _non_exhaustive: (),
}

impl CodeInfo {
    /// Helper method to retrieve the path to the represented source file,
    /// on a best-effort basis. It depends on the symbolization source data
    /// whether this path is absolute or relative and, if its the latter, what
    /// directory it is relative to. In general this path is mostly intended for
    /// displaying purposes.
    #[inline]
    pub fn to_path(&self) -> Cow<'_, Path> {
        self.dir.as_ref().map_or_else(
            || Cow::Borrowed(Path::new(&self.file)),
            |dir| Cow::Owned(dir.join(&self.file)),
        )
    }
}


/// A type representing an inlined function.
#[derive(Clone, Debug, PartialEq)]
pub struct InlinedFn {
    /// The symbol name of the function.
    pub name: String,
    /// Source code location information for the call to the function.
    pub code_info: Option<CodeInfo>,
    /// The struct is non-exhaustive and open to extension.
    pub(crate) _non_exhaustive: (),
}


/// The result of address symbolization by [`Symbolizer`].
#[derive(Clone, Debug, PartialEq)]
pub struct Sym {
    /// The symbol name that an address belongs to.
    pub name: String,
    /// The address at which the symbol is located (i.e., its "start").
    ///
    /// This is the "normalized" address of the symbol, as present in
    /// the file (and reported by tools such as `readelf(1)`,
    /// `llvm-gsymutil`, or similar).
    pub addr: Addr,
    /// The byte offset of the address that got symbolized from the
    /// start of the symbol (i.e., from `addr`).
    ///
    /// E.g., when normalizing address 0x1337 of a function that starts at
    /// 0x1330, the offset will be set to 0x07 (and `addr` will be 0x1330). This
    /// member is especially useful in contexts when input addresses are not
    /// already normalized, such as when normalizing an address in a process
    /// context (which may have been relocated and/or have layout randomizations
    /// applied).
    pub offset: usize,
    /// The symbol's size, if available.
    pub size: Option<usize>,
    /// Source code location information for the symbol.
    pub code_info: Option<CodeInfo>,
    /// Inlined function information, if requested and available.
    ///
    /// Availability depends on both the underlying symbolization source (e.g.,
    /// ELF does not contain inline information, but DWARF does) as well as
    /// whether a function was actually inlined at the address in question.
    ///
    /// Inlined functions are reported in the order in which their calls are
    /// nested. For example, if the instruction at the address to symbolize
    /// falls into a function `f` at an inlined call to `g`, which in turn
    /// contains an inlined call to `h`, the symbols will be reported in the
    /// order `f`, `g`, `h`.
    pub inlined: Box<[InlinedFn]>,
    /// The struct is non-exhaustive and open to extension.
    pub(crate) _non_exhaustive: (),
}


/// A builder for configurable construction of [`Symbolizer`] objects.
///
/// By default all features are enabled.
#[derive(Clone, Debug)]
pub struct Builder {
    /// Whether to enable usage of debug symbols.
    debug_syms: bool,
    /// Whether to attempt to gather source code location information.
    ///
    /// This setting implies usage of debug symbols and forces the corresponding
    /// flag to `true`.
    src_location: bool,
    /// Whether to report inlined functions as part of symbolization.
    inlined_fns: bool,
    /// Whether or not to transparently demangle symbols.
    ///
    /// Demangling happens on a best-effort basis. Currently supported
    /// languages are Rust and C++ and the flag will have no effect if
    /// the underlying language does not mangle symbols (such as C).
    demangle: bool,
}

impl Builder {
    /// Enable/disable usage of debug symbols.
    ///
    /// That can be useful in cases where ELF symbol information is stripped.
    pub fn enable_debug_syms(mut self, enable: bool) -> Builder {
        self.debug_syms = enable;
        self
    }

    /// Enable/disable source code location information (line numbers,
    /// file names etc.).
    pub fn enable_src_location(mut self, enable: bool) -> Builder {
        self.src_location = enable;
        self
    }

    /// Enable/disable inlined function reporting.
    pub fn enable_inlined_fns(mut self, enable: bool) -> Builder {
        self.inlined_fns = enable;
        self
    }

    /// Enable/disable usage of debug symbols.
    ///
    /// That can be useful in cases where ELF symbol information is stripped.
    pub fn enable_demangling(mut self, enable: bool) -> Builder {
        self.demangle = enable;
        self
    }

    /// Create the [`Symbolizer`] object.
    pub fn build(self) -> Symbolizer {
        let Builder {
            debug_syms,
            src_location,
            inlined_fns,
            demangle,
        } = self;
        let ksym_cache = KSymCache::new();
        let elf_cache = ElfCache::new(src_location, debug_syms);

        Symbolizer {
            ksym_cache,
            elf_cache,
            src_location,
            inlined_fns,
            demangle,
        }
    }
}

impl Default for Builder {
    fn default() -> Self {
        Self {
            debug_syms: true,
            src_location: true,
            inlined_fns: true,
            demangle: true,
        }
    }
}


/// Symbolizer provides an interface to symbolize addresses.
#[derive(Debug)]
pub struct Symbolizer {
    ksym_cache: KSymCache,
    elf_cache: ElfCache,
    src_location: bool,
    inlined_fns: bool,
    demangle: bool,
}

impl Symbolizer {
    /// Create a new [`Symbolizer`].
    pub fn new() -> Self {
        Builder::default().build()
    }

    /// Retrieve a [`Builder`] object for configurable construction of a
    /// [`Symbolizer`].
    pub fn builder() -> Builder {
        Builder::default()
    }

    /// Demangle the provided symbol if asked for and possible.
    fn maybe_demangle(&self, symbol: &str, language: SrcLang) -> String {
        if self.demangle {
            maybe_demangle(symbol, language)
        } else {
            symbol.to_string()
        }
    }

    /// Symbolize an address using the provided [`SymResolver`].
    #[cfg_attr(feature = "tracing", crate::log::instrument(skip_all, fields(addr = format_args!("{addr:#x}"), resolver = ?resolver)))]
    fn symbolize_with_resolver(
        &self,
        addr: Addr,
        resolver: &dyn SymResolver,
    ) -> Result<Option<Sym>> {
        let sym = if let Some(sym) = resolver.find_sym(addr)? {
            sym
        } else {
            return Ok(None)
        };

        let src_loc = if self.src_location {
            resolver.find_code_info(addr, self.inlined_fns)?
        } else {
            None
        };

        let (name, code_info) = if let Some(src_loc) = &src_loc {
            let name = src_loc.direct.0;
            let frame_code_info = &src_loc.direct.1;
            (name, Some(CodeInfo::from(frame_code_info)))
        } else {
            (None, None)
        };

        let inlined = if let Some(src_loc) = &src_loc {
            src_loc
                .inlined
                .iter()
                .map(|(name, info)| {
                    let name = name.to_string();
                    let info = info.as_ref().map(CodeInfo::from);
                    InlinedFn {
                        name,
                        code_info: info,
                        _non_exhaustive: (),
                    }
                })
                .collect()
        } else {
            Vec::new()
        };

        let IntSym {
            name: sym_name,
            addr: sym_addr,
            size: sym_size,
            lang,
        } = sym;

        let sym = Sym {
            name: self.maybe_demangle(name.unwrap_or(sym_name), lang),
            addr: sym_addr,
            offset: addr - sym_addr,
            size: sym_size,
            code_info,
            inlined: inlined.into_boxed_slice(),
            _non_exhaustive: (),
        };
        Ok(Some(sym))
    }

    /// Symbolize a list of addresses using the provided [`SymResolver`].
    fn symbolize_addrs(
        &self,
        addrs: &[Addr],
        resolver: &dyn SymResolver,
    ) -> Result<Vec<(Sym, usize)>> {
        let mut syms = Vec::with_capacity(addrs.len());
        for (i, addr) in addrs.iter().enumerate() {
            let resolved = self.symbolize_with_resolver(*addr, resolver)?;
            let () = syms.extend(resolved.into_iter().map(|sym| (sym, i)));
        }
        Ok(syms)
    }

    fn resolve_addr_in_elf(&self, addr: Addr, path: &Path) -> Result<Option<Sym>> {
        let backend = self.elf_cache.find(path)?;
        let resolver = ElfResolver::with_backend(path, backend)?;
        let symbol = self.symbolize_with_resolver(addr, &resolver)?;
        Ok(symbol)
    }

    /// Symbolize the given list of user space addresses in the provided
    /// process.
    fn symbolize_user_addrs(&self, addrs: &[Addr], pid: Pid) -> Result<Vec<(Sym, usize)>> {
        struct SymbolizeHandler<'sym> {
            /// The "outer" `Symbolizer` instance.
            symbolizer: &'sym Symbolizer,
            /// Running index of the address being symbolized.
            addr_idx: usize,
            /// Symbols representing the symbolized addresses.
            all_symbols: Vec<(Sym, usize)>,
        }

        impl SymbolizeHandler<'_> {
            fn handle_apk_addr(&mut self, addr: Addr, entry: &PathMapsEntry) -> Result<()> {
                let (norm_addr, elf_path, elf_parser) = normalize_apk_addr(addr, entry)?;
                let apk_path = &entry.path.symbolic_path;
                // Create an Android-style binary-in-APK path for
                // reporting purposes.
                let apk_elf_path = create_apk_elf_path(apk_path, &elf_path)?;
                let backend = ElfBackend::Elf(Rc::new(elf_parser));

                let resolver = ElfResolver::with_backend(&apk_elf_path, backend)?;
                let symbol = self
                    .symbolizer
                    .symbolize_with_resolver(norm_addr, &resolver)?;
                let () = self
                    .all_symbols
                    .extend(symbol.into_iter().map(|sym| (sym, self.addr_idx)));
                Ok(())
            }

            fn handle_elf_addr(&mut self, addr: Addr, entry: &PathMapsEntry) -> Result<()> {
                let path = &entry.path.maps_file;
                let norm_addr = normalize_elf_addr(addr, entry)?;
                let symbol = self
                    .symbolizer
                    .resolve_addr_in_elf(norm_addr, path)
                    .with_context(|| {
                        format!(
                            "failed to symbolize normalized address {norm_addr:#x} in ELF file {}",
                            path.display()
                        )
                    })?;
                let () = self
                    .all_symbols
                    .extend(symbol.into_iter().map(|sym| (sym, self.addr_idx)));
                Ok(())
            }
        }

        impl normalize::Handler for SymbolizeHandler<'_> {
            #[cfg_attr(feature = "tracing", crate::log::instrument(skip_all, fields(addr = format_args!("{_addr:#x}"))))]
            fn handle_unknown_addr(&mut self, _addr: Addr) -> Result<()> {
                self.addr_idx += 1;
                Ok(())
            }

            fn handle_entry_addr(&mut self, addr: Addr, entry: &PathMapsEntry) -> Result<()> {
                let ext = entry
                    .path
                    .symbolic_path
                    .extension()
                    .unwrap_or_else(|| OsStr::new(""));
                let result = match ext.to_str() {
                    Some("apk") | Some("zip") => self.handle_apk_addr(addr, entry),
                    _ => self.handle_elf_addr(addr, entry),
                };
                self.addr_idx += 1;
                result
            }
        }

        let entries = maps::parse(pid)?;
        let handler = SymbolizeHandler {
            symbolizer: self,
            addr_idx: 0,
            all_symbols: Vec::with_capacity(addrs.len()),
        };

        let handler = util::with_ordered_elems_with_swap(
            addrs,
            |handler: &mut SymbolizeHandler<'_>| handler.all_symbols.as_mut_slice(),
            |sorted_addrs| normalize_sorted_user_addrs_with_entries(sorted_addrs, entries, handler),
            |symbols: &mut [(Sym, usize)], i, j| {
                if i != j {
                    debug_assert!(i <= symbols.len());
                    debug_assert!(j <= symbols.len());

                    let syms = symbols.as_mut_ptr();
                    // TODO: Use `slice::get_many_mut` once it is stable.
                    // SAFETY: `i` and `j` are different so we are creating
                    //         exclusive references to disjunct region of
                    //         memory. It is an invariant that both are within
                    //         bounds of the `symbols` slice.
                    let symi = unsafe { &mut *syms.add(i) };
                    let symj = unsafe { &mut *syms.add(j) };
                    swap(&mut symi.0, &mut symj.0)
                }
            },
        )?;
        Ok(handler.all_symbols)
    }

    fn symbolize_kernel_addrs(&self, addrs: &[Addr], src: &Kernel) -> Result<Vec<(Sym, usize)>> {
        let Kernel {
            kallsyms,
            kernel_image,
            _non_exhaustive: (),
        } = src;

        let ksym_resolver = if let Some(kallsyms) = kallsyms {
            let ksym_resolver = self.ksym_cache.get_resolver(kallsyms)?;
            Some(ksym_resolver)
        } else {
            let kallsyms = Path::new(KALLSYMS);
            let result = self.ksym_cache.get_resolver(kallsyms);
            match result {
                Ok(resolver) => Some(resolver),
                Err(err) => {
                    log::warn!(
                        "failed to load kallsyms from {}: {err}; ignoring...",
                        kallsyms.display()
                    );
                    None
                }
            }
        };

        let elf_resolver = if let Some(image) = kernel_image {
            let backend = self.elf_cache.find(image)?;
            let elf_resolver = ElfResolver::with_backend(image, backend)?;
            Some(elf_resolver)
        } else {
            let release = uname_release()?.to_str().unwrap().to_string();
            let basename = "vmlinux-";
            let dirs = [Path::new("/boot/"), Path::new("/usr/lib/debug/boot/")];
            let kernel_image = dirs.iter().find_map(|dir| {
                let path = dir.join(format!("{basename}{release}"));
                path.exists().then_some(path)
            });

            if let Some(image) = kernel_image {
                let result = self.elf_cache.find(&image);
                match result {
                    Ok(backend) => {
                        let result = ElfResolver::with_backend(&image, backend);
                        match result {
                            Ok(resolver) => Some(resolver),
                            Err(err) => {
                                log::warn!(
                                    "failed to create ELF resolver for kernel image {}: {err}; ignoring...",
                                    image.display()
                                );
                                None
                            }
                        }
                    }
                    Err(err) => {
                        log::warn!(
                            "failed to load kernel image {}: {err}; ignoring...",
                            image.display()
                        );
                        None
                    }
                }
            } else {
                None
            }
        };

        let resolver = KernelResolver::new(ksym_resolver, elf_resolver)?;
        let symbols = self.symbolize_addrs(addrs, &resolver)?;
        Ok(symbols)
    }

    /// Symbolize a list of addresses.
    ///
    /// Symbolize a list of addresses using the provided symbolization
    /// [`Source`][Source].
    ///
    /// This function returns zero or one objects per input address:
    /// - zero symbols are returned in case the address could not be symbolized
    /// - otherwise a single symbol is returned
    ///
    /// Each symbol is accompanied by the index of the input address (the second
    /// member in each tuple). These indices are guaranteed to be ascending.
    /// When an input address could not be symbolized, there won't be a symbol
    /// with the corresponding index reported.
    ///
    /// The following table lists which features the various formats
    /// (represented by the [`Source`][Source] argument) support. If a feature
    /// is not supported, the corresponding data in the [`Sym`] result will not
    /// be populated.
    ///
    /// | Format        | Feature                          | Supported by format?     | Supported by blazesym?   |
    /// |---------------|----------------------------------|:------------------------:|:------------------------:|
    /// | ELF           | symbol size                      | yes                      | yes                      |
    /// |               | source code location information | no                       | N/A                      |
    /// |               | inlined function information     | no                       | N/A                      |
    /// | DWARF         | symbol size                      | yes                      | yes                      |
    /// |               | source code location information | yes                      | yes                      |
    /// |               | inlined function information     | yes                      | no                       |
    /// | Gsym          | symbol size                      | yes                      | yes                      |
    /// |               | source code location information | yes                      | yes                      |
    /// |               | inlined function information     | yes                      | yes                      |
    /// | Ksym          | symbol size                      | no                       | N/A                      |
    /// |               | source code location information | no                       | N/A                      |
    /// |               | inlined function information     | no                       | N/A                      |
    #[cfg_attr(feature = "tracing", crate::log::instrument(skip_all, fields(src = ?src, addrs = format_args!("{addrs:#x?}"))))]
    pub fn symbolize(&self, src: &Source, addrs: &[Addr]) -> Result<Vec<(Sym, usize)>> {
        match src {
            Source::Elf(Elf {
                path,
                _non_exhaustive: (),
            }) => {
                let backend = self.elf_cache.find(path)?;
                let resolver = ElfResolver::with_backend(path, backend)?;
                let symbols = self.symbolize_addrs(addrs, &resolver)?;
                Ok(symbols)
            }
            Source::Kernel(kernel) => self.symbolize_kernel_addrs(addrs, kernel),
            Source::Process(Process {
                pid,
                _non_exhaustive: (),
            }) => self.symbolize_user_addrs(addrs, *pid),
            Source::Gsym(Gsym::Data(GsymData {
                data,
                _non_exhaustive: (),
            })) => {
                let resolver = GsymResolver::with_data(data)?;
                let symbols = self.symbolize_addrs(addrs, &resolver)?;
                Ok(symbols)
            }
            Source::Gsym(Gsym::File(GsymFile {
                path,
                _non_exhaustive: (),
            })) => {
                let resolver = GsymResolver::new(path.clone())?;
                let symbols = self.symbolize_addrs(addrs, &resolver)?;
                Ok(symbols)
            }
        }
    }
}

impl Default for Symbolizer {
    fn default() -> Self {
        Self::new()
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::mem::transmute;

    use crate::elf::ElfParser;
    use crate::inspect::FindAddrOpts;
    use crate::inspect::SymType;
    use crate::mmap::Mmap;
    use crate::symbolize;
    use crate::symbolize::Symbolizer;
    use crate::zip;

    use test_log::test;


    /// Check that we can correctly construct the source code path to a symbol.
    #[test]
    fn symbol_source_code_path() {
        let mut info = CodeInfo {
            dir: None,
            file: OsString::from("source.c"),
            line: Some(1),
            column: Some(2),
            _non_exhaustive: (),
        };
        assert_eq!(info.to_path(), Path::new("source.c"));

        info.dir = Some(PathBuf::from("/foobar"));
        assert_eq!(info.to_path(), Path::new("/foobar/source.c"));
    }

    /// Check that we can symbolize an address residing in a zip archive.
    #[test]
    fn symbolize_zip() {
        let test_zip = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test.zip");

        let mmap = Mmap::builder().exec().open(test_zip).unwrap();
        let archive = zip::Archive::with_mmap(mmap.clone()).unwrap();
        let so = archive
            .entries()
            .find_map(|entry| {
                let entry = entry.unwrap();
                (entry.path == Path::new("libtest-so.so")).then_some(entry)
            })
            .unwrap();

        let elf_mmap = mmap
            .constrain(so.data_offset..so.data_offset + so.data.len())
            .unwrap();

        // Look up the address of the `the_answer` function inside of the shared
        // object.
        let elf_parser = ElfParser::from_mmap(elf_mmap.clone());
        let opts = FindAddrOpts {
            sym_type: SymType::Function,
            ..Default::default()
        };
        let syms = elf_parser.find_addr("the_answer", &opts).unwrap();
        // There is only one symbol with this address in there.
        assert_eq!(syms.len(), 1);
        let sym = syms.first().unwrap();

        let the_answer_addr = unsafe { elf_mmap.as_ptr().add(sym.addr) };
        // Now just double check that everything worked out and the function
        // is actually where it was meant to be.
        let the_answer_fn =
            unsafe { transmute::<_, extern "C" fn() -> libc::c_int>(the_answer_addr) };
        let answer = the_answer_fn();
        assert_eq!(answer, 42);

        // Now symbolize the address we just looked up. It should be
        // correctly mapped to the `the_answer` function within our
        // process.
        let src = symbolize::Source::Process(symbolize::Process::new(Pid::Slf));
        let symbolizer = Symbolizer::new();
        let results = symbolizer
            .symbolize(&src, &[the_answer_addr as Addr])
            .unwrap()
            .into_iter()
            .collect::<Vec<_>>();
        assert_eq!(results.len(), 1);

        let (result, addr_idx) = &results[0];
        assert_eq!(*addr_idx, 0);
        assert_eq!(result.name, "the_answer");
        assert_eq!(result.addr, sym.addr);
    }
}
