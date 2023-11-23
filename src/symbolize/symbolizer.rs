use std::borrow::Cow;
use std::ffi::OsStr;
use std::fmt::Debug;
use std::fs::File;
use std::ops::Deref as _;
use std::ops::Range;
use std::path::Path;
use std::path::PathBuf;
use std::rc::Rc;

use crate::elf;
use crate::elf::ElfParser;
use crate::elf::ElfResolver;
use crate::elf::ElfResolverData;
use crate::file_cache::FileCache;
use crate::gsym::GsymResolver;
use crate::insert_map::InsertMap;
use crate::kernel::KernelResolver;
use crate::ksym::KSymResolver;
use crate::ksym::KALLSYMS;
use crate::log;
use crate::maps;
use crate::maps::PathMapsEntry;
use crate::mmap::Mmap;
use crate::normalize;
use crate::normalize::normalize_sorted_user_addrs_with_entries;
use crate::normalize::Handler as _;
use crate::util;
use crate::util::uname_release;
use crate::zip;
use crate::Addr;
use crate::Error;
use crate::ErrorExt as _;
use crate::IntoError as _;
use crate::Pid;
use crate::Result;
use crate::SymResolver;

use super::source::Apk;
use super::source::Elf;
use super::source::Gsym;
use super::source::GsymData;
use super::source::GsymFile;
use super::source::Kernel;
use super::source::Process;
use super::source::Source;
use super::AddrCodeInfo;
use super::InlinedFn;
use super::Input;
use super::IntSym;
use super::SrcLang;
use super::Sym;
use super::Symbolized;


fn create_apk_elf_path(apk: &Path, elf: &Path) -> Result<PathBuf> {
    let mut extension = apk
        .extension()
        .unwrap_or_else(|| OsStr::new("apk"))
        .to_os_string();
    // Append '!' to indicate separation from archive internal contents
    // that follow. This is an Android convention.
    let () = extension.push("!");

    let mut apk = apk.to_path_buf();
    if !apk.set_extension(extension) {
        return Err(Error::with_invalid_data(format!(
            "path {} is not valid",
            apk.display()
        )))
    }

    let path = apk.join(elf);
    Ok(path)
}


/// Demangle a symbol name using the demangling scheme for the given language.
#[cfg(feature = "demangle")]
fn maybe_demangle(name: Cow<'_, str>, language: SrcLang) -> Cow<'_, str> {
    match language {
        SrcLang::Rust => rustc_demangle::try_demangle(name.as_ref())
            .ok()
            .as_ref()
            .map(|x| Cow::Owned(format!("{x:#}"))),
        SrcLang::Cpp => cpp_demangle::Symbol::new(name.as_ref())
            .ok()
            .and_then(|x| x.demangle(&Default::default()).ok().map(Cow::Owned)),
        SrcLang::Unknown => rustc_demangle::try_demangle(name.as_ref())
            .map(|x| Cow::Owned(format!("{x:#}")))
            .ok()
            .or_else(|| {
                cpp_demangle::Symbol::new(name.as_ref())
                    .ok()
                    .and_then(|sym| sym.demangle(&Default::default()).ok().map(Cow::Owned))
            }),
    }
    .unwrap_or(name)
}

#[cfg(not(feature = "demangle"))]
fn maybe_demangle(name: Cow<'_, str>, _language: SrcLang) -> Cow<'_, str> {
    // Demangling is disabled.
    name
}


fn elf_offset_to_address(offset: u64, parser: &ElfParser) -> Result<Option<Addr>> {
    let phdrs = parser.program_headers()?;
    let addr = phdrs.iter().find_map(|phdr| {
        if phdr.p_type == elf::types::PT_LOAD {
            if (phdr.p_offset..phdr.p_offset + phdr.p_memsz).contains(&offset) {
                return Some((offset - phdr.p_offset + phdr.p_vaddr) as Addr)
            }
        }
        None
    });

    Ok(addr)
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

        Symbolizer {
            apk_cache: FileCache::new(),
            elf_cache: FileCache::new(),
            gsym_cache: FileCache::new(),
            ksym_cache: FileCache::new(),
            debug_syms,
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


/// An enumeration helping us to differentiate between cached and uncached
/// symbol resolvers.
///
/// An "uncached" resolver is one that is created on the spot. We do so for
/// cases when we keep the input data, for example (e.g., when we have no
/// control over its lifetime).
/// A "cached" resolver is one that ultimately lives in one of our internal
/// caches. These caches have the same lifetime as the `Symbolizer` object
/// itself (represented here as `'slf`).
///
/// Object of this type are at the core of our logic determining whether to
/// heap allocate certain data such as paths or symbol names or whether to just
/// hand out references to mmap'ed data.
#[derive(Debug)]
enum Resolver<'tmp, 'slf> {
    Uncached(&'tmp (dyn SymResolver + 'tmp)),
    Cached(&'slf dyn SymResolver),
}


/// Symbolizer provides an interface to symbolize addresses.
///
/// An instance of this type is the unit at which symbolization inputs are
/// cached. That is to say, source files (DWARF, ELF, ...) and the parsed data
/// structures may be kept around in memory for the lifetime of this object to
/// speed up future symbolization requests. If you are working with large input
/// sources and/or do not intend to perform multiple symbolization requests
/// (i.e., [`symbolize`][Symbolizer::symbolize] or
/// [`symbolize_single`][Symbolizer::symbolize_single] calls) for the same
/// symbolization source, you may want to consider creating a new `Symbolizer`
/// instance regularly.
#[derive(Debug)]
pub struct Symbolizer {
    #[allow(clippy::type_complexity)]
    apk_cache: FileCache<(zip::Archive, InsertMap<Range<u64>, Rc<ElfResolver>>)>,
    elf_cache: FileCache<ElfResolverData>,
    gsym_cache: FileCache<Rc<GsymResolver<'static>>>,
    ksym_cache: FileCache<Rc<KSymResolver>>,
    debug_syms: bool,
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
    fn maybe_demangle<'sym>(&self, symbol: Cow<'sym, str>, language: SrcLang) -> Cow<'sym, str> {
        if self.demangle {
            maybe_demangle(symbol, language)
        } else {
            symbol
        }
    }

    /// Symbolize an address using the provided [`SymResolver`].
    #[cfg_attr(feature = "tracing", crate::log::instrument(skip_all, fields(addr = format_args!("{addr:#x}"), resolver = ?resolver)))]
    fn symbolize_with_resolver<'slf>(
        &'slf self,
        addr: Addr,
        resolver: &Resolver<'_, 'slf>,
    ) -> Result<Symbolized<'slf>> {
        let (sym_name, sym_addr, sym_size, lang) = match resolver {
            Resolver::Uncached(resolver) => {
                if let Some(sym) = resolver.find_sym(addr)? {
                    let IntSym {
                        name: sym_name,
                        addr: sym_addr,
                        size: sym_size,
                        lang,
                    } = sym;

                    (Cow::Owned(sym_name.to_string()), sym_addr, sym_size, lang)
                } else {
                    return Ok(Symbolized::Unknown)
                }
            }
            Resolver::Cached(resolver) => {
                if let Some(sym) = resolver.find_sym(addr)? {
                    let IntSym {
                        name: sym_name,
                        addr: sym_addr,
                        size: sym_size,
                        lang,
                    } = sym;

                    (Cow::Borrowed(sym_name), sym_addr, sym_size, lang)
                } else {
                    return Ok(Symbolized::Unknown)
                }
            }
        };

        let (name, code_info, inlined) = if self.code_info {
            match resolver {
                Resolver::Uncached(resolver) => {
                    let addr_code_info = resolver.find_code_info(addr, self.inlined_fns)?;
                    if let Some(AddrCodeInfo {
                        direct: (direct_name, direct_code_info),
                        inlined,
                    }) = addr_code_info
                    {
                        let direct_name = direct_name.map(|name| Cow::Owned(name.to_string()));
                        let direct_code_info = direct_code_info.to_owned();
                        let inlined = inlined
                            .into_iter()
                            .map(|(name, info)| {
                                let name = self.maybe_demangle(Cow::Owned(name.to_string()), lang);
                                InlinedFn {
                                    name,
                                    code_info: info.map(|info| info.to_owned()),
                                    _non_exhaustive: (),
                                }
                            })
                            .collect();
                        (direct_name, Some(direct_code_info), inlined)
                    } else {
                        (None, None, Vec::new())
                    }
                }
                Resolver::Cached(resolver) => {
                    let addr_code_info = resolver.find_code_info(addr, self.inlined_fns)?;
                    if let Some(AddrCodeInfo {
                        direct: (direct_name, direct_code_info),
                        inlined,
                    }) = addr_code_info
                    {
                        let direct_name = direct_name.map(Cow::Borrowed);
                        let inlined = inlined
                            .into_iter()
                            .map(|(name, info)| {
                                let name = self.maybe_demangle(Cow::Borrowed(name), lang);
                                InlinedFn {
                                    name,
                                    code_info: info,
                                    _non_exhaustive: (),
                                }
                            })
                            .collect();
                        (direct_name, Some(direct_code_info), inlined)
                    } else {
                        (None, None, Vec::new())
                    }
                }
            }
        } else {
            (None, None, Vec::new())
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
    fn symbolize_addrs<'slf>(
        &'slf self,
        addrs: &[Addr],
        resolver: &Resolver<'_, 'slf>,
    ) -> Result<Vec<Symbolized>> {
        addrs
            .iter()
            .map(|addr| self.symbolize_with_resolver(*addr, resolver))
            .collect()
    }

    fn create_gsym_resolver(&self, path: &Path, file: &File) -> Result<Rc<GsymResolver<'static>>> {
        let resolver = GsymResolver::from_file(path.to_path_buf(), file)?;
        Ok(Rc::new(resolver))
    }

    fn gsym_resolver<'slf>(&'slf self, path: &Path) -> Result<&'slf Rc<GsymResolver<'static>>> {
        let (file, cell) = self.gsym_cache.entry(path)?;
        let resolver = cell.get_or_try_init(|| self.create_gsym_resolver(path, file))?;
        Ok(resolver)
    }

    fn create_apk_resolver<'slf>(
        &'slf self,
        apk: &zip::Archive,
        apk_path: &Path,
        file_off: u64,
        resolver_map: &'slf InsertMap<Range<u64>, Rc<ElfResolver>>,
    ) -> Result<Option<(&'slf Rc<ElfResolver>, Addr)>> {
        // Find the APK entry covering the calculated file offset.
        for apk_entry in apk.entries() {
            let apk_entry = apk_entry?;
            let bounds = apk_entry.data_offset..apk_entry.data_offset + apk_entry.data.len() as u64;

            if bounds.contains(&file_off) {
                let resolver = resolver_map.get_or_try_insert(bounds.clone(), || {
                    let mmap = apk
                        .mmap()
                        .constrain(bounds.clone())
                        .ok_or_invalid_input(|| {
                            format!(
                                "invalid APK entry data bounds ({bounds:?}) in {}",
                                apk_path.display()
                            )
                        })?;
                    // Create an Android-style binary-in-APK path for
                    // reporting purposes.
                    let apk_elf_path = create_apk_elf_path(apk_path, apk_entry.path)?;
                    let parser = Rc::new(ElfParser::from_mmap(mmap));
                    let resolver = ElfResolver::from_parser(
                        &apk_elf_path,
                        parser,
                        self.debug_syms,
                        self.code_info,
                    )?;
                    let resolver = Rc::new(resolver);
                    Ok(resolver)
                })?;

                let elf_off = file_off - apk_entry.data_offset;
                if let Some(addr) = elf_offset_to_address(elf_off, resolver.parser())? {
                    return Ok(Some((resolver, addr)))
                }
                break
            }
        }

        Ok(None)
    }

    fn apk_resolver<'slf>(
        &'slf self,
        path: &Path,
        file_off: u64,
    ) -> Result<Option<(&'slf Rc<ElfResolver>, Addr)>> {
        let (file, cell) = self.apk_cache.entry(path)?;
        let (apk, resolvers) = cell.get_or_try_init(|| {
            let apk = zip::Archive::with_mmap(Mmap::builder().map(file)?)?;
            let resolvers = InsertMap::new();
            Result::<_, Error>::Ok((apk, resolvers))
        })?;

        let result = self.create_apk_resolver(apk, path, file_off, resolvers);
        result
    }

    fn resolve_addr_in_elf(&self, addr: Addr, path: &Path) -> Result<Symbolized> {
        let resolver = self
            .elf_cache
            .elf_resolver(path, self.debug_syms, self.code_info)?;
        let symbolized = self.symbolize_with_resolver(addr, &Resolver::Cached(resolver.deref()))?;
        Ok(symbolized)
    }

    /// Symbolize the given list of user space addresses in the provided
    /// process.
    fn symbolize_user_addrs(&self, addrs: &[Addr], pid: Pid) -> Result<Vec<Symbolized>> {
        struct SymbolizeHandler<'sym> {
            /// The "outer" `Symbolizer` instance.
            symbolizer: &'sym Symbolizer,
            /// Symbols representing the symbolized addresses.
            all_symbols: Vec<Symbolized<'sym>>,
        }

        impl SymbolizeHandler<'_> {
            fn handle_apk_addr(&mut self, addr: Addr, entry: &PathMapsEntry) -> Result<()> {
                let file_off = addr - entry.range.start + entry.offset;
                let apk_path = &entry.path.symbolic_path;
                match self.symbolizer.apk_resolver(apk_path, file_off)? {
                    Some((elf_resolver, elf_addr)) => {
                        let symbol = self.symbolizer.symbolize_with_resolver(
                            elf_addr,
                            &Resolver::Cached(elf_resolver.deref()),
                        )?;
                        let () = self.all_symbols.push(symbol);
                        Ok(())
                    }
                    None => self.handle_unknown_addr(addr),
                }
            }

            fn handle_elf_addr(&mut self, addr: Addr, entry: &PathMapsEntry) -> Result<()> {
                let path = &entry.path.maps_file;
                let file_off = addr - entry.range.start + entry.offset;
                let parser = ElfParser::open(&entry.path.maps_file).with_context(|| {
                    format!("failed to open map file {}", entry.path.maps_file.display())
                })?;

                match elf_offset_to_address(file_off, &parser)? {
                    Some(norm_addr) => {
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
                    None => self.handle_unknown_addr(addr),
                }
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

    fn create_ksym_resolver(&self, path: &Path, _file: &File) -> Result<Rc<KSymResolver>> {
        // TODO: Should really use `file` and not `path` for the instantiation.
        let resolver = KSymResolver::load_file_name(path.to_path_buf())?;
        let resolver = Rc::new(resolver);
        Ok(resolver)
    }

    fn ksym_resolver<'slf>(&'slf self, path: &Path) -> Result<&'slf Rc<KSymResolver>> {
        let (file, cell) = self.ksym_cache.entry(path)?;
        let resolver = cell.get_or_try_init(|| self.create_ksym_resolver(path, file))?;
        Ok(resolver)
    }

    fn create_kernel_resolver(&self, src: &Kernel) -> Result<KernelResolver> {
        let Kernel {
            kallsyms,
            kernel_image,
            _non_exhaustive: (),
        } = src;

        let ksym_resolver = if let Some(kallsyms) = kallsyms {
            let ksym_resolver = self.ksym_resolver(kallsyms)?;
            Some(ksym_resolver)
        } else {
            let kallsyms = Path::new(KALLSYMS);
            let result = self.ksym_resolver(kallsyms);
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
            let resolver = self
                .elf_cache
                .elf_resolver(image, self.debug_syms, self.code_info)?;
            Some(resolver)
        } else {
            let release = uname_release()?.to_str().unwrap().to_string();
            let basename = "vmlinux-";
            let dirs = [Path::new("/boot/"), Path::new("/usr/lib/debug/boot/")];
            let kernel_image = dirs.iter().find_map(|dir| {
                let path = dir.join(format!("{basename}{release}"));
                path.exists().then_some(path)
            });

            if let Some(image) = kernel_image {
                let result = self
                    .elf_cache
                    .elf_resolver(&image, self.debug_syms, self.code_info);
                match result {
                    Ok(resolver) => Some(resolver),
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

        KernelResolver::new(ksym_resolver.cloned(), elf_resolver.cloned())
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
    /// | Format | Feature                          | Supported by format? | Supported by blazesym? |
    /// |--------|----------------------------------|:--------------------:|:----------------------:|
    /// | ELF    | symbol size                      | yes                  | yes                    |
    /// |        | source code location information | no                   | N/A                    |
    /// |        | inlined function information     | no                   | N/A                    |
    /// | DWARF  | symbol size                      | yes                  | yes                    |
    /// |        | source code location information | yes                  | yes                    |
    /// |        | inlined function information     | yes                  | yes                    |
    /// | Gsym   | symbol size                      | yes                  | yes                    |
    /// |        | source code location information | yes                  | yes                    |
    /// |        | inlined function information     | yes                  | yes                    |
    /// | Ksym   | symbol size                      | no                   | N/A                    |
    /// |        | source code location information | no                   | N/A                    |
    /// |        | inlined function information     | no                   | N/A                    |
    #[cfg_attr(feature = "tracing", crate::log::instrument(skip_all, fields(src = ?src, addrs = format_args!("{input:#x?}"))))]
    pub fn symbolize<'slf>(
        &'slf self,
        src: &Source,
        input: Input<&[u64]>,
    ) -> Result<Vec<Symbolized<'slf>>> {
        match src {
            Source::Apk(Apk {
                path,
                _non_exhaustive: (),
            }) => match input {
                Input::VirtOffset(..) => {
                    return Err(Error::with_unsupported(
                        "ELF symbolization does not support virtual offset inputs",
                    ))
                }
                Input::AbsAddr(..) => {
                    return Err(Error::with_unsupported(
                        "ELF symbolization does not support absolute address inputs",
                    ))
                }
                Input::FileOffset(offsets) => offsets
                    .iter()
                    .map(|offset| match self.apk_resolver(path, *offset)? {
                        Some((elf_resolver, elf_addr)) => self.symbolize_with_resolver(
                            elf_addr,
                            &Resolver::Cached(elf_resolver.deref()),
                        ),
                        None => Ok(Symbolized::Unknown),
                    })
                    .collect(),
            },
            Source::Elf(Elf {
                path,
                _non_exhaustive: (),
            }) => {
                let resolver =
                    self.elf_cache
                        .elf_resolver(path, self.debug_syms, self.code_info)?;
                match input {
                    Input::VirtOffset(addrs) => addrs
                        .iter()
                        .map(|addr| {
                            self.symbolize_with_resolver(*addr, &Resolver::Cached(resolver.deref()))
                        })
                        .collect(),
                    Input::AbsAddr(..) => {
                        return Err(Error::with_unsupported(
                            "ELF symbolization does not support absolute address inputs",
                        ))
                    }
                    Input::FileOffset(offsets) => offsets
                        .iter()
                        .map(
                            |offset| match elf_offset_to_address(*offset, resolver.parser())? {
                                Some(addr) => self.symbolize_with_resolver(
                                    addr,
                                    &Resolver::Cached(resolver.deref()),
                                ),
                                None => Ok(Symbolized::Unknown),
                            },
                        )
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

                let resolver = Rc::new(self.create_kernel_resolver(kernel)?);
                let symbols = self.symbolize_addrs(addrs, &Resolver::Uncached(resolver.deref()))?;
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

                let resolver = Rc::new(GsymResolver::with_data(data)?);
                let symbols = self.symbolize_addrs(addrs, &Resolver::Uncached(resolver.deref()))?;
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

                let resolver = self.gsym_resolver(path)?;
                let symbols = self.symbolize_addrs(addrs, &Resolver::Cached(resolver.deref()))?;
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
    pub fn symbolize_single<'slf>(
        &'slf self,
        src: &Source,
        input: Input<u64>,
    ) -> Result<Symbolized<'slf>> {
        match src {
            Source::Apk(Apk {
                path,
                _non_exhaustive: (),
            }) => match input {
                Input::VirtOffset(..) => {
                    return Err(Error::with_unsupported(
                        "APK symbolization does not support virtual offset inputs",
                    ))
                }
                Input::AbsAddr(..) => {
                    return Err(Error::with_unsupported(
                        "APK symbolization does not support absolute address inputs",
                    ))
                }
                Input::FileOffset(offset) => match self.apk_resolver(path, offset)? {
                    Some((elf_resolver, elf_addr)) => self
                        .symbolize_with_resolver(elf_addr, &Resolver::Cached(elf_resolver.deref())),
                    None => return Ok(Symbolized::Unknown),
                },
            },
            Source::Elf(Elf {
                path,
                _non_exhaustive: (),
            }) => {
                let resolver =
                    self.elf_cache
                        .elf_resolver(path, self.debug_syms, self.code_info)?;
                let addr = match input {
                    Input::VirtOffset(addr) => addr,
                    Input::AbsAddr(..) => {
                        return Err(Error::with_unsupported(
                            "ELF symbolization does not support absolute address inputs",
                        ))
                    }
                    Input::FileOffset(offset) => {
                        match elf_offset_to_address(offset, resolver.parser())? {
                            Some(addr) => addr,
                            None => return Ok(Symbolized::Unknown),
                        }
                    }
                };

                self.symbolize_with_resolver(addr, &Resolver::Cached(resolver.deref()))
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

                let resolver = Rc::new(self.create_kernel_resolver(kernel)?);
                self.symbolize_with_resolver(addr, &Resolver::Uncached(resolver.deref()))
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

                let resolver = Rc::new(GsymResolver::with_data(data)?);
                self.symbolize_with_resolver(addr, &Resolver::Uncached(resolver.deref()))
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

                let resolver = self.gsym_resolver(path)?;
                self.symbolize_with_resolver(addr, &Resolver::Cached(resolver.deref()))
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
    use crate::symbolize::CodeInfo;
    use crate::symbolize::Symbolizer;
    use crate::zip;
    use crate::ErrorKind;

    use test_log::test;


    /// Exercise the `Debug` representation of various types.
    #[test]
    fn debug_repr() {
        let builder = Symbolizer::builder();
        assert_ne!(format!("{builder:?}"), "");

        let symbolizer = builder.build();
        assert_ne!(format!("{symbolizer:?}"), "");
    }

    /// Check that we can create a path to an ELF inside an APK as expected.
    #[test]
    fn elf_apk_path_creation() {
        let apk = Path::new("/root/test.apk");
        let elf = Path::new("subdir/libc.so");
        let path = create_apk_elf_path(apk, elf).unwrap();
        assert_eq!(path, Path::new("/root/test.apk!/subdir/libc.so"));
    }

    /// Check that we can correctly construct the source code path to a symbol.
    #[test]
    fn symbol_source_code_path() {
        let mut info = CodeInfo {
            dir: None,
            file: Cow::Borrowed(OsStr::new("source.c")),
            line: Some(1),
            column: Some(2),
            _non_exhaustive: (),
        };
        assert_eq!(info.to_path(), Path::new("source.c"));

        info.dir = Some(Cow::Borrowed(Path::new("/foobar")));
        assert_eq!(info.to_path(), Path::new("/foobar/source.c"));
    }

    /// Make sure that we can demangle symbols.
    #[test]
    fn demangle() {
        if !cfg!(feature = "demangle") {
            return
        }

        let symbol = Cow::Borrowed("_ZN4core9panicking9panic_fmt17h5f1a6fd39197ad62E");
        let name = maybe_demangle(symbol, SrcLang::Rust);
        assert_eq!(name, "core::panicking::panic_fmt");

        let symbol = Cow::Borrowed("_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc");
        let name = maybe_demangle(symbol, SrcLang::Cpp);
        assert_eq!(
            name,
            "std::basic_ostream<char, std::char_traits<char> >& std::operator<< <std::char_traits<char> >(std::basic_ostream<char, std::char_traits<char> >&, char const*)"
        );
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
                symbolize::Source::Elf(symbolize::Elf::new(test_elf)),
                &[Input::AbsAddr([46].as_slice())][..],
            ),
            (
                symbolize::Source::Gsym(symbolize::Gsym::File(symbolize::GsymFile::new(test_gsym))),
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
