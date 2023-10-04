use std::ffi::OsStr;
use std::fmt::Debug;
use std::path::Path;
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
use crate::normalize::normalize_elf_offset_with_parser;
use crate::normalize::normalize_sorted_user_addrs_with_entries;
use crate::util;
use crate::util::uname_release;
use crate::Addr;
use crate::Error;
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
use super::CodeInfo;
use super::InlinedFn;
use super::Input;
use super::Sym;
use super::Symbolized;


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
    code_info: bool,
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
    pub fn enable_code_info(mut self, enable: bool) -> Builder {
        self.code_info = enable;
        self
    }

    /// Enable/disable inlined function reporting.
    pub fn enable_inlined_fns(mut self, enable: bool) -> Builder {
        self.inlined_fns = enable;
        self
    }

    /// Enable/disable transparent demangling of symbol names.
    ///
    /// Demangling happens on a best-effort basis. Currently supported languages
    /// are Rust and C++ and the flag will have no effect if the underlying
    /// language does not mangle symbols (such as C).
    pub fn enable_demangling(mut self, enable: bool) -> Builder {
        self.demangle = enable;
        self
    }

    /// Create the [`Symbolizer`] object.
    pub fn build(self) -> Symbolizer {
        let Builder {
            debug_syms,
            code_info,
            inlined_fns,
            demangle,
        } = self;
        let ksym_cache = KSymCache::new();
        let elf_cache = ElfCache::new(code_info, debug_syms);

        Symbolizer {
            ksym_cache,
            elf_cache,
            code_info,
            inlined_fns,
            demangle,
        }
    }
}

impl Default for Builder {
    fn default() -> Self {
        Self {
            debug_syms: true,
            code_info: true,
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
    code_info: bool,
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
    ) -> Result<Symbolized> {
        let sym = if let Some(sym) = resolver.find_sym(addr)? {
            sym
        } else {
            return Ok(Symbolized::Unknown)
        };

        let addr_code_info = if self.code_info {
            resolver.find_code_info(addr, self.inlined_fns)?
        } else {
            None
        };

        let (name, code_info) = if let Some(info) = &addr_code_info {
            let name = info.direct.0;
            let code_info = &info.direct.1;
            (name, Some(CodeInfo::from(code_info)))
        } else {
            (None, None)
        };

        let IntSym {
            name: sym_name,
            addr: sym_addr,
            size: sym_size,
            lang,
        } = sym;

        let inlined = if let Some(code_info) = &addr_code_info {
            code_info
                .inlined
                .iter()
                .map(|(name, info)| {
                    let name = self.maybe_demangle(name, lang);
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

        let sym = Sym {
            name: self.maybe_demangle(name.unwrap_or(sym_name), lang),
            addr: sym_addr,
            offset: (addr - sym_addr) as usize,
            size: sym_size,
            code_info,
            inlined: inlined.into_boxed_slice(),
            _non_exhaustive: (),
        };
        Ok(Symbolized::Sym(sym))
    }

    /// Symbolize a list of addresses using the provided [`SymResolver`].
    fn symbolize_addrs(
        &self,
        addrs: &[Addr],
        resolver: &dyn SymResolver,
    ) -> Result<Vec<Symbolized>> {
        addrs
            .iter()
            .map(|addr| self.symbolize_with_resolver(*addr, resolver))
            .collect()
    }

    fn resolve_addr_in_elf(&self, addr: Addr, path: &Path) -> Result<Symbolized> {
        let backend = self.elf_cache.find(path)?;
        let resolver = ElfResolver::with_backend(path, backend)?;
        let symbolized = self.symbolize_with_resolver(addr, &resolver)?;
        Ok(symbolized)
    }

    /// Symbolize the given list of user space addresses in the provided
    /// process.
    fn symbolize_user_addrs(&self, addrs: &[Addr], pid: Pid) -> Result<Vec<Symbolized>> {
        struct SymbolizeHandler<'sym> {
            /// The "outer" `Symbolizer` instance.
            symbolizer: &'sym Symbolizer,
            /// Symbols representing the symbolized addresses.
            all_symbols: Vec<Symbolized>,
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
                let () = self.all_symbols.push(symbol);
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
                let () = self.all_symbols.push(symbol);
                Ok(())
            }
        }

        impl normalize::Handler for SymbolizeHandler<'_> {
            #[cfg_attr(feature = "tracing", crate::log::instrument(skip_all, fields(addr = format_args!("{_addr:#x}"))))]
            fn handle_unknown_addr(&mut self, _addr: Addr) -> Result<()> {
                let () = self.all_symbols.push(Symbolized::Unknown);
                Ok(())
            }

            fn handle_entry_addr(&mut self, addr: Addr, entry: &PathMapsEntry) -> Result<()> {
                let ext = entry
                    .path
                    .symbolic_path
                    .extension()
                    .unwrap_or_else(|| OsStr::new(""));
                match ext.to_str() {
                    Some("apk") | Some("zip") => self.handle_apk_addr(addr, entry),
                    _ => self.handle_elf_addr(addr, entry),
                }
            }
        }

        let entries = maps::parse(pid)?;
        let handler = SymbolizeHandler {
            symbolizer: self,
            all_symbols: Vec::with_capacity(addrs.len()),
        };

        let handler = util::with_ordered_elems(
            addrs,
            |handler: &mut SymbolizeHandler<'_>| handler.all_symbols.as_mut_slice(),
            |sorted_addrs| normalize_sorted_user_addrs_with_entries(sorted_addrs, entries, handler),
        )?;
        Ok(handler.all_symbols)
    }

    fn create_kernel_resolver(&self, src: &Kernel) -> Result<KernelResolver> {
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

        KernelResolver::new(ksym_resolver, elf_resolver)
    }

    /// Symbolize a list of addresses.
    ///
    /// Symbolize a list of addresses using the provided symbolization
    /// [`Source`][Source].
    ///
    /// This function returns exactly one [`Symbolized`] object for each input
    /// address, in the order of input addresses.
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
    /// |               | inlined function information     | yes                      | yes                      |
    /// | Gsym          | symbol size                      | yes                      | yes                      |
    /// |               | source code location information | yes                      | yes                      |
    /// |               | inlined function information     | yes                      | yes                      |
    /// | Ksym          | symbol size                      | no                       | N/A                      |
    /// |               | source code location information | no                       | N/A                      |
    /// |               | inlined function information     | no                       | N/A                      |
    #[cfg_attr(feature = "tracing", crate::log::instrument(skip_all, fields(src = ?src, addrs = format_args!("{input:#x?}"))))]
    pub fn symbolize(&self, src: &Source, input: Input<&[u64]>) -> Result<Vec<Symbolized>> {
        match src {
            Source::Elf(Elf {
                path,
                _non_exhaustive: (),
            }) => {
                let backend = self.elf_cache.find(path)?;
                let resolver = ElfResolver::with_backend(path, backend)?;

                match input {
                    Input::VirtOffset(addrs) => addrs
                        .iter()
                        .map(|addr| self.symbolize_with_resolver(*addr, &resolver))
                        .collect(),
                    Input::AbsAddr(..) => {
                        return Err(Error::with_unsupported(
                            "ELF symbolization does not support absolute address inputs",
                        ))
                    }
                    Input::FileOffset(offsets) => offsets
                        .iter()
                        .map(|offset| {
                            match normalize_elf_offset_with_parser(*offset, resolver.parser())? {
                                Some(addr) => self.symbolize_with_resolver(addr, &resolver),
                                None => Ok(Symbolized::Unknown),
                            }
                        })
                        .collect(),
                }
            }
            Source::Kernel(kernel) => {
                let addrs = match input {
                    Input::AbsAddr(addrs) => addrs,
                    Input::VirtOffset(..) => {
                        return Err(Error::with_unsupported(
                            "kernel symbolization does not support virtual offset inputs",
                        ))
                    }
                    Input::FileOffset(..) => {
                        return Err(Error::with_unsupported(
                            "kernel symbolization does not support file offset inputs",
                        ))
                    }
                };

                let resolver = self.create_kernel_resolver(kernel)?;
                let symbols = self.symbolize_addrs(addrs, &resolver)?;
                Ok(symbols)
            }
            Source::Process(Process {
                pid,
                _non_exhaustive: (),
            }) => {
                let addrs = match input {
                    Input::AbsAddr(addrs) => addrs,
                    Input::VirtOffset(..) => {
                        return Err(Error::with_unsupported(
                            "process symbolization does not support virtual offset inputs",
                        ))
                    }
                    Input::FileOffset(..) => {
                        return Err(Error::with_unsupported(
                            "process symbolization does not support file offset inputs",
                        ))
                    }
                };

                self.symbolize_user_addrs(addrs, *pid)
            }
            Source::Gsym(Gsym::Data(GsymData {
                data,
                _non_exhaustive: (),
            })) => {
                let addrs = match input {
                    Input::VirtOffset(addrs) => addrs,
                    Input::AbsAddr(..) => {
                        return Err(Error::with_unsupported(
                            "Gsym symbolization does not support absolute address inputs",
                        ))
                    }
                    Input::FileOffset(..) => {
                        return Err(Error::with_unsupported(
                            "Gsym symbolization does not support file offset inputs",
                        ))
                    }
                };

                let resolver = GsymResolver::with_data(data)?;
                let symbols = self.symbolize_addrs(addrs, &resolver)?;
                Ok(symbols)
            }
            Source::Gsym(Gsym::File(GsymFile {
                path,
                _non_exhaustive: (),
            })) => {
                let addrs = match input {
                    Input::VirtOffset(addrs) => addrs,
                    Input::AbsAddr(..) => {
                        return Err(Error::with_unsupported(
                            "Gsym symbolization does not support absolute address inputs",
                        ))
                    }
                    Input::FileOffset(..) => {
                        return Err(Error::with_unsupported(
                            "Gsym symbolization does not support file offset inputs",
                        ))
                    }
                };

                let resolver = GsymResolver::new(path.clone())?;
                let symbols = self.symbolize_addrs(addrs, &resolver)?;
                Ok(symbols)
            }
        }
    }

    /// Symbolize a single input address/offset.
    ///
    /// In general, it is more performant to symbolize addresses in batches
    /// using [`symbolize`][Self::symbolize]. However, in cases where only a
    /// single address is available, this method provides a more convenient API.
    #[cfg_attr(feature = "tracing", crate::log::instrument(skip_all, fields(src = ?src, input = format_args!("{input:#x?}"))))]
    pub fn symbolize_single(&self, src: &Source, input: Input<u64>) -> Result<Symbolized> {
        match src {
            Source::Elf(Elf {
                path,
                _non_exhaustive: (),
            }) => {
                let backend = self.elf_cache.find(path)?;

                let addr = match input {
                    Input::VirtOffset(addr) => addr,
                    Input::AbsAddr(..) => {
                        return Err(Error::with_unsupported(
                            "ELF symbolization does not support absolute address inputs",
                        ))
                    }
                    Input::FileOffset(offset) => {
                        match normalize_elf_offset_with_parser(offset, backend.parser())? {
                            Some(addr) => addr,
                            None => return Ok(Symbolized::Unknown),
                        }
                    }
                };

                let resolver = ElfResolver::with_backend(path, backend)?;
                self.symbolize_with_resolver(addr, &resolver)
            }
            Source::Kernel(kernel) => {
                let addr = match input {
                    Input::AbsAddr(addr) => addr,
                    Input::VirtOffset(..) => {
                        return Err(Error::with_unsupported(
                            "kernel symbolization does not support virtual offset inputs",
                        ))
                    }
                    Input::FileOffset(..) => {
                        return Err(Error::with_unsupported(
                            "kernel symbolization does not support file offset inputs",
                        ))
                    }
                };

                let resolver = self.create_kernel_resolver(kernel)?;
                self.symbolize_with_resolver(addr, &resolver)
            }
            Source::Process(Process {
                pid,
                _non_exhaustive: (),
            }) => {
                let addr = match input {
                    Input::AbsAddr(addr) => addr,
                    Input::VirtOffset(..) => {
                        return Err(Error::with_unsupported(
                            "process symbolization does not support virtual offset inputs",
                        ))
                    }
                    Input::FileOffset(..) => {
                        return Err(Error::with_unsupported(
                            "process symbolization does not support file offset inputs",
                        ))
                    }
                };

                let mut symbols = self.symbolize_user_addrs(&[addr], *pid)?;
                debug_assert!(symbols.len() <= 1, "{symbols:#?}");
                Ok(symbols.pop().unwrap_or(Symbolized::Unknown))
            }
            Source::Gsym(Gsym::Data(GsymData {
                data,
                _non_exhaustive: (),
            })) => {
                let addr = match input {
                    Input::VirtOffset(addr) => addr,
                    Input::AbsAddr(..) => {
                        return Err(Error::with_unsupported(
                            "Gsym symbolization does not support absolute address inputs",
                        ))
                    }
                    Input::FileOffset(..) => {
                        return Err(Error::with_unsupported(
                            "Gsym symbolization does not support file offset inputs",
                        ))
                    }
                };

                let resolver = GsymResolver::with_data(data)?;
                self.symbolize_with_resolver(addr, &resolver)
            }
            Source::Gsym(Gsym::File(GsymFile {
                path,
                _non_exhaustive: (),
            })) => {
                let addr = match input {
                    Input::VirtOffset(addr) => addr,
                    Input::AbsAddr(..) => {
                        return Err(Error::with_unsupported(
                            "Gsym symbolization does not support absolute address inputs",
                        ))
                    }
                    Input::FileOffset(..) => {
                        return Err(Error::with_unsupported(
                            "Gsym symbolization does not support file offset inputs",
                        ))
                    }
                };

                let resolver = GsymResolver::new(path.clone())?;
                self.symbolize_with_resolver(addr, &resolver)
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

    use std::ffi::OsString;
    use std::mem::transmute;
    use std::path::PathBuf;

    use crate::elf::ElfParser;
    use crate::inspect::FindAddrOpts;
    use crate::inspect::SymType;
    use crate::mmap::Mmap;
    use crate::symbolize;
    use crate::symbolize::Symbolizer;
    use crate::zip;
    use crate::ErrorKind;

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

    /// Make sure that we error out as expected on certain input
    /// variants.
    #[test]
    fn unsupported_inputs() {
        let test_elf = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-stable-addresses.bin");
        let test_gsym = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-stable-addresses.gsym");

        let unsupported = [
            (
                symbolize::Source::Process(symbolize::Process::new(Pid::Slf)),
                &[
                    Input::VirtOffset([42].as_slice()),
                    Input::FileOffset([43].as_slice()),
                ][..],
            ),
            (
                symbolize::Source::Kernel(symbolize::Kernel::default()),
                &[
                    Input::VirtOffset([44].as_slice()),
                    Input::FileOffset([45].as_slice()),
                ][..],
            ),
            (
                symbolize::Source::Elf(symbolize::Elf::new(&test_elf)),
                &[Input::AbsAddr([46].as_slice())][..],
            ),
            (
                symbolize::Source::Gsym(symbolize::Gsym::File(symbolize::GsymFile::new(
                    &test_gsym,
                ))),
                &[
                    Input::AbsAddr([48].as_slice()),
                    Input::FileOffset([49].as_slice()),
                ][..],
            ),
        ];

        let symbolizer = Symbolizer::new();
        for (src, inputs) in unsupported {
            for input in inputs {
                let err = symbolizer.symbolize(&src, *input).unwrap_err();
                assert_eq!(err.kind(), ErrorKind::Unsupported);

                let input = input.try_to_single().unwrap();
                let err = symbolizer.symbolize_single(&src, input).unwrap_err();
                assert_eq!(err.kind(), ErrorKind::Unsupported);
            }
        }
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
            .constrain(so.data_offset..so.data_offset + so.data.len() as u64)
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

        let the_answer_addr = unsafe { elf_mmap.as_ptr().add(sym.addr as usize) };
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
        let result = symbolizer
            .symbolize_single(&src, Input::AbsAddr(the_answer_addr as Addr))
            .unwrap()
            .into_sym()
            .unwrap();

        assert_eq!(result.name, "the_answer");
        assert_eq!(result.addr, sym.addr);
    }
}
