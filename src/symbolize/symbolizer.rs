use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::fs::File;
use std::mem::take;
use std::ops::Deref as _;
use std::ops::Range;
use std::path::Path;
use std::path::PathBuf;
use std::rc::Rc;

#[cfg(feature = "apk")]
use crate::apk::create_apk_elf_path;
#[cfg(feature = "breakpad")]
use crate::breakpad::BreakpadResolver;
use crate::elf::ElfParser;
use crate::elf::ElfResolver;
use crate::elf::ElfResolverData;
#[cfg(feature = "dwarf")]
use crate::elf::DEFAULT_DEBUG_DIRS;
use crate::file_cache::FileCache;
#[cfg(feature = "gsym")]
use crate::gsym::GsymResolver;
use crate::insert_map::InsertMap;
use crate::kernel::KernelResolver;
use crate::kernel::KsymResolver;
use crate::kernel::KALLSYMS;
use crate::log;
use crate::maps;
use crate::maps::EntryPath;
use crate::maps::MapsEntry;
use crate::maps::PathName;
use crate::mmap::Mmap;
use crate::normalize;
use crate::normalize::normalize_sorted_user_addrs_with_entries;
use crate::normalize::Handler as _;
use crate::perf_map::PerfMap;
use crate::symbolize::InlinedFn;
use crate::symbolize::Resolve;
use crate::symbolize::TranslateFileOffset;
use crate::util;
#[cfg(linux)]
use crate::util::uname_release;
use crate::util::Dbg;
#[cfg(feature = "tracing")]
use crate::util::Hexify;
#[cfg(feature = "apk")]
use crate::zip;
use crate::Addr;
use crate::Error;
use crate::ErrorExt as _;
use crate::ErrorKind;
use crate::IntoError as _;
use crate::Pid;
use crate::Result;

use super::cache;
use super::cache::Cache;
#[cfg(feature = "apk")]
use super::source::Apk;
#[cfg(feature = "breakpad")]
use super::source::Breakpad;
use super::source::Elf;
#[cfg(feature = "gsym")]
use super::source::Gsym;
#[cfg(feature = "gsym")]
use super::source::GsymData;
#[cfg(feature = "gsym")]
use super::source::GsymFile;
use super::source::Kernel;
use super::source::Process;
use super::source::Source;
use super::FindSymOpts;
use super::Input;
use super::Reason;
use super::ResolvedSym;
use super::SrcLang;
use super::Sym;
use super::Symbolize;
use super::Symbolized;


/// A type for displaying debug information for a [`MapsEntry`].
#[cfg(feature = "tracing")]
struct DebugMapsEntry<'entry>(&'entry MapsEntry);

#[cfg(feature = "tracing")]
impl Debug for DebugMapsEntry<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let MapsEntry {
            range,
            offset,
            path_name,
            ..
        } = self.0;

        let path = match path_name {
            // For debugging purposes we work with the symbolic path, as
            // it's the most easy to reason about. Note that it may not
            // be what ends up being used during symbolization.
            Some(PathName::Path(path)) => &path.symbolic_path,
            Some(PathName::Component(component)) => Path::new(component),
            None => Path::new("<no-path>"),
        };

        f.debug_struct(stringify!(MapsEntry))
            .field(stringify!(range), &format_args!("{range:#x?}"))
            .field(stringify!(offset), &format_args!("{offset:#x?}"))
            .field(stringify!(path), &path.display())
            .finish()
    }
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


/// Information about a member inside an APK.
///
/// This type is used in conjunction with the APK "dispatcher" infrastructure;
/// see [`Builder::set_apk_dispatcher`].
#[cfg(feature = "apk")]
#[derive(Clone, Debug)]
pub struct ApkMemberInfo<'dat> {
    /// The path to the APK itself.
    pub apk_path: &'dat Path,
    /// The path to the member inside the APK.
    pub member_path: &'dat Path,
    /// The memory mapped member data.
    pub member_mmap: Mmap,
    /// The struct is non-exhaustive and open to extension.
    #[doc(hidden)]
    pub _non_exhaustive: (),
}


/// The signature of a dispatcher function for APK symbolization.
///
/// This type is used in conjunction with the APK "dispatcher" infrastructure;
/// see [`Builder::set_apk_dispatcher`].
///
/// If this function returns `Some` resolver, this resolver will be used
/// for addresses belonging to the represented archive member. If `None`
/// is returned, the default dispatcher will be used instead.
// TODO: Use a trait alias once stable.
#[cfg(feature = "apk")]
pub trait ApkDispatch: Fn(ApkMemberInfo<'_>) -> Result<Option<Box<dyn Resolve>>> {}

#[cfg(feature = "apk")]
impl<F> ApkDispatch for F where F: Fn(ApkMemberInfo<'_>) -> Result<Option<Box<dyn Resolve>>> {}


/// The signature of a dispatcher function for process symbolization.
///
/// This type is used in conjunction with the process "dispatcher"
/// infrastructure; see [`Builder::set_process_dispatcher`].
///
/// If this function returns `Some` resolver, this resolver will be used
/// for addresses belonging to the represented process member. If `None`
/// is returned, the default dispatcher will be used instead.
pub trait ProcessDispatch: Fn(ProcessMemberInfo<'_>) -> Result<Option<Box<dyn Resolve>>> {}

impl<F> ProcessDispatch for F where F: Fn(ProcessMemberInfo<'_>) -> Result<Option<Box<dyn Resolve>>> {}


#[cfg(feature = "apk")]
fn default_apk_dispatcher(
    info: ApkMemberInfo<'_>,
    debug_dirs: Option<&[PathBuf]>,
) -> Result<Box<dyn Resolve>> {
    // Create an Android-style binary-in-APK path for
    // reporting purposes.
    let apk_elf_path = create_apk_elf_path(info.apk_path, info.member_path);
    let parser = Rc::new(ElfParser::from_mmap(
        info.member_mmap,
        Some(apk_elf_path.into_os_string()),
    ));
    let resolver = ElfResolver::from_parser(parser, debug_dirs)?;
    let resolver = Box::new(resolver);
    Ok(resolver)
}


/// Information about an address space member of a process.
#[derive(Clone, Debug)]
pub struct ProcessMemberInfo<'dat> {
    /// The virtual address range covered by this member.
    pub range: Range<Addr>,
    /// The "pathname" component in a `/proc/[pid]/maps` entry. See
    /// `proc(5)` section `/proc/[pid]/maps`.
    pub member_entry: &'dat PathName,
    /// The struct is non-exhaustive and open to extension.
    #[doc(hidden)]
    pub _non_exhaustive: (),
}


/// A builder for configurable construction of [`Symbolizer`] objects.
///
/// By default all features are enabled.
#[derive(Debug)]
pub struct Builder {
    /// Whether or not to automatically reload file system based
    /// symbolization sources that were updated since the last
    /// symbolization operation.
    auto_reload: bool,
    /// Whether to attempt to gather source code location information.
    code_info: bool,
    /// Whether to report inlined functions as part of symbolization.
    inlined_fns: bool,
    /// Whether or not to transparently demangle symbols.
    ///
    /// Demangling happens on a best-effort basis. Currently supported
    /// languages are Rust and C++ and the flag will have no effect if
    /// the underlying language does not mangle symbols (such as C).
    demangle: bool,
    /// List of additional directories in which split debug information
    /// is looked for.
    #[cfg(feature = "dwarf")]
    debug_dirs: Vec<PathBuf>,
    /// The "dispatch" function to use when symbolizing addresses
    /// mapping to members of an APK.
    #[cfg(feature = "apk")]
    apk_dispatch: Option<Dbg<Box<dyn ApkDispatch>>>,
    /// The "dispatch" function to use when symbolizing addresses
    /// mapping to members of a process.
    process_dispatch: Option<Dbg<Box<dyn ProcessDispatch>>>,
}

impl Builder {
    /// Enable/disable auto reloading of symbolization sources in the
    /// presence of updates.
    pub fn enable_auto_reload(mut self, enable: bool) -> Self {
        self.auto_reload = enable;
        self
    }

    /// Enable/disable source code location information (line numbers,
    /// file names etc.).
    pub fn enable_code_info(mut self, enable: bool) -> Self {
        self.code_info = enable;
        self
    }

    /// Enable/disable inlined function reporting.
    ///
    /// This option only has an effect if `code_info` is `true`.
    pub fn enable_inlined_fns(mut self, enable: bool) -> Self {
        self.inlined_fns = enable;
        self
    }

    /// Enable/disable transparent demangling of symbol names.
    ///
    /// Demangling happens on a best-effort basis. Currently supported languages
    /// are Rust and C++ and the flag will have no effect if the underlying
    /// language does not mangle symbols (such as C).
    pub fn enable_demangling(mut self, enable: bool) -> Self {
        self.demangle = enable;
        self
    }

    /// Set debug directories to search for split debug information.
    ///
    /// These directories will be consulted (in given order) when resolving
    /// debug links in binaries. By default `/usr/lib/debug` and `/lib/debug/`
    /// will be searched. Setting a list here will overwrite these defaults, so
    /// make sure to include these directories as desired.
    ///
    /// Note that the directory containing a symbolization source is always an
    /// implicit candidate target directory of the highest precedence.
    ///
    /// A value of `None` reverts to using the default set of directories.
    #[cfg(feature = "dwarf")]
    #[cfg_attr(docsrs, doc(cfg(feature = "dwarf")))]
    pub fn set_debug_dirs<D, P>(mut self, debug_dirs: Option<D>) -> Self
    where
        D: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        if let Some(debug_dirs) = debug_dirs {
            self.debug_dirs = debug_dirs
                .into_iter()
                .map(|p| p.as_ref().to_path_buf())
                .collect();
        } else {
            self.debug_dirs = DEFAULT_DEBUG_DIRS
                .iter()
                .map(PathBuf::from)
                .collect::<Vec<_>>();
        }
        self
    }

    /// Set the "dispatch" function to use when symbolizing addresses
    /// mapping to members of an APK.
    #[cfg(feature = "apk")]
    #[cfg_attr(docsrs, doc(cfg(feature = "apk")))]
    pub fn set_apk_dispatcher<D>(mut self, apk_dispatch: D) -> Self
    where
        D: ApkDispatch + 'static,
    {
        self.apk_dispatch = Some(Dbg(Box::new(apk_dispatch)));
        self
    }

    /// Set the "dispatch" function to use when symbolizing addresses
    /// mapping to members of a process.
    pub fn set_process_dispatcher<D>(mut self, process_dispatch: D) -> Self
    where
        D: ProcessDispatch + 'static,
    {
        self.process_dispatch = Some(Dbg(Box::new(process_dispatch)));
        self
    }

    /// Create the [`Symbolizer`] object.
    pub fn build(self) -> Symbolizer {
        let Self {
            auto_reload,
            code_info,
            inlined_fns,
            demangle,
            #[cfg(feature = "dwarf")]
            debug_dirs,
            #[cfg(feature = "apk")]
            apk_dispatch,
            process_dispatch,
        } = self;

        let find_sym_opts = match (code_info, inlined_fns) {
            (false, inlined_fns) => {
                if inlined_fns {
                    log::warn!(
                        "inlined function reporting asked for but more general code information inquiry is disabled; flag is being ignored"
                    );
                }
                FindSymOpts::Basic
            }
            (true, false) => FindSymOpts::CodeInfo,
            (true, true) => FindSymOpts::CodeInfoAndInlined,
        };

        Symbolizer {
            #[cfg(feature = "apk")]
            apk_cache: FileCache::builder().enable_auto_reload(auto_reload).build(),
            #[cfg(feature = "breakpad")]
            breakpad_cache: FileCache::builder().enable_auto_reload(auto_reload).build(),
            elf_cache: FileCache::builder().enable_auto_reload(auto_reload).build(),
            #[cfg(feature = "gsym")]
            gsym_cache: FileCache::builder().enable_auto_reload(auto_reload).build(),
            ksym_cache: FileCache::builder().enable_auto_reload(auto_reload).build(),
            perf_map_cache: FileCache::builder().enable_auto_reload(auto_reload).build(),
            process_vma_cache: RefCell::new(HashMap::new()),
            process_cache: InsertMap::new(),
            find_sym_opts,
            demangle,
            #[cfg(feature = "dwarf")]
            debug_dirs,
            #[cfg(feature = "apk")]
            apk_dispatch,
            process_dispatch,
        }
    }
}

impl Default for Builder {
    fn default() -> Self {
        Self {
            auto_reload: true,
            code_info: true,
            inlined_fns: true,
            demangle: true,
            #[cfg(feature = "dwarf")]
            debug_dirs: DEFAULT_DEBUG_DIRS
                .iter()
                .map(PathBuf::from)
                .collect::<Vec<_>>(),
            #[cfg(feature = "apk")]
            apk_dispatch: None,
            process_dispatch: None,
        }
    }
}


struct SymbolizeHandler<'sym> {
    /// The "outer" `Symbolizer` instance.
    symbolizer: &'sym Symbolizer,
    /// The PID of the process in which we symbolize.
    pid: Pid,
    /// Whether or not to consult debug symbols to satisfy the request
    /// (if present).
    debug_syms: bool,
    /// Whether or not to consult the process' perf map (if any) to
    /// satisfy the request.
    perf_map: bool,
    /// Whether to work with `/proc/<pid>/map_files/` entries or with
    /// symbolic paths mentioned in `/proc/<pid>/maps` instead.
    map_files: bool,
    /// Symbols representing the symbolized addresses.
    all_symbols: Vec<Symbolized<'sym>>,
}

impl SymbolizeHandler<'_> {
    #[cfg(feature = "apk")]
    fn handle_apk_addr(&mut self, addr: Addr, file_off: u64, entry_path: &EntryPath) -> Result<()> {
        let apk_path = if self.map_files {
            &entry_path.maps_file
        } else {
            &entry_path.symbolic_path
        };

        match self
            .symbolizer
            .apk_resolver(apk_path, file_off, self.debug_syms)?
        {
            Some((elf_resolver, elf_addr)) => {
                let symbol = self.symbolizer.symbolize_with_resolver(
                    elf_addr,
                    &Resolver::Cached(elf_resolver.as_symbolize()),
                )?;
                let () = self.all_symbols.push(symbol);
            }
            None => self.handle_unknown_addr(addr, Reason::InvalidFileOffset),
        }
        Ok(())
    }

    fn handle_elf_addr(&mut self, addr: Addr, file_off: u64, entry_path: &EntryPath) -> Result<()> {
        let resolver = if self.map_files {
            self.symbolizer.elf_cache.elf_resolver(
                entry_path,
                self.symbolizer.maybe_debug_dirs(self.debug_syms),
            )
        } else {
            let path = entry_path.symbolic_path.as_path();
            self.symbolizer
                .elf_cache
                .elf_resolver(path, self.symbolizer.maybe_debug_dirs(self.debug_syms))
        }?;


        match resolver.file_offset_to_virt_offset(file_off)? {
            Some(addr) => {
                let symbol = self
                    .symbolizer
                    .symbolize_with_resolver(addr, &Resolver::Cached(resolver.deref()))?;
                let () = self.all_symbols.push(symbol);
            }
            None => self.handle_unknown_addr(addr, Reason::InvalidFileOffset),
        }
        Ok(())
    }

    fn handle_perf_map_addr(&mut self, addr: Addr) -> Result<()> {
        if let Some(perf_map) = self.symbolizer.perf_map(self.pid)? {
            let symbolized = self
                .symbolizer
                .symbolize_with_resolver(addr, &Resolver::Cached(perf_map))?;
            let () = self.all_symbols.push(symbolized);
        } else {
            let () = self.handle_unknown_addr(addr, Reason::UnknownAddr);
        }
        Ok(())
    }
}

impl normalize::Handler<Reason> for SymbolizeHandler<'_> {
    #[cfg_attr(feature = "tracing", crate::log::instrument(skip_all, fields(addr = format_args!("{_addr:#x}"), ?reason)))]
    fn handle_unknown_addr(&mut self, _addr: Addr, reason: Reason) {
        let () = self.all_symbols.push(Symbolized::Unknown(reason));
    }

    #[cfg_attr(feature = "tracing", crate::log::instrument(skip_all, fields(addr = format_args!("{addr:#x}"), entry = ?DebugMapsEntry(entry))))]
    fn handle_entry_addr(&mut self, addr: Addr, entry: &MapsEntry) -> Result<()> {
        if let Some(path_name) = &entry.path_name {
            if let Some(resolver) = self
                .symbolizer
                .process_dispatch_resolver(entry.range.clone(), path_name)?
            {
                let file_off = addr - entry.range.start + entry.offset;
                let () = match resolver.file_offset_to_virt_offset(file_off)? {
                    Some(addr) => {
                        let symbol = self.symbolizer.symbolize_with_resolver(
                            addr,
                            &Resolver::Cached(resolver.as_symbolize()),
                        )?;
                        let () = self.all_symbols.push(symbol);
                    }
                    None => self.handle_unknown_addr(addr, Reason::InvalidFileOffset),
                };
                return Ok(())
            }

            // If there is no process dispatcher installed or it did
            // not return a resolver for the entry, we use our
            // default handling scheme.
        }

        match &entry.path_name {
            Some(PathName::Path(entry_path)) => {
                let file_off = addr - entry.range.start + entry.offset;
                let ext = entry_path
                    .symbolic_path
                    .extension()
                    .unwrap_or_else(|| OsStr::new(""));
                match ext.to_str() {
                    #[cfg(feature = "apk")]
                    Some("apk") | Some("zip") => self.handle_apk_addr(addr, file_off, entry_path),
                    _ => self.handle_elf_addr(addr, file_off, entry_path),
                }
            }
            Some(PathName::Component(..)) => {
                let () = self.handle_unknown_addr(addr, Reason::Unsupported);
                Ok(())
            }
            // If there is no path associated with this entry, we don't
            // really have any idea what the address may belong to. But
            // there is a chance that the address is part of the perf
            // map, so check that.
            // TODO: It's not entirely clear if a perf map could also
            //       cover addresses belonging to entries with a path.
            None if self.perf_map => self.handle_perf_map_addr(addr),
            None => {
                let () = self.handle_unknown_addr(addr, Reason::UnknownAddr);
                Ok(())
            }
        }
    }
}


/// An enumeration helping us to differentiate between cached and uncached
/// symbol resolvers.
///
/// An "uncached" resolver is one that is created on the spot. We do so for
/// cases when we cannot keep the input data, for example (e.g., when we
/// have no control over its lifetime).
/// A "cached" resolver is one that ultimately lives in one of our internal
/// caches. These caches have the same lifetime as the `Symbolizer` object
/// itself (represented here as `'slf`).
///
/// Objects of this type are at the core of our logic determining whether to
/// heap allocate certain data such as paths or symbol names or whether to just
/// hand out references to mmap'ed data.
#[derive(Debug)]
enum Resolver<'tmp, 'slf> {
    Uncached(&'tmp (dyn Symbolize + 'tmp)),
    Cached(&'slf dyn Symbolize),
}

#[cfg(feature = "tracing")]
impl<'tmp, 'slf: 'tmp> Resolver<'tmp, 'slf> {
    fn inner(&self) -> &(dyn Symbolize + '_) {
        match self {
            Self::Uncached(symbolize) | Self::Cached(symbolize) => *symbolize,
        }
    }
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
///
/// # Notes
/// Please note that demangling results are not cached.
#[derive(Debug)]
pub struct Symbolizer {
    #[cfg(feature = "apk")]
    apk_cache: FileCache<(zip::Archive, InsertMap<Range<u64>, Box<dyn Resolve>>)>,
    #[cfg(feature = "breakpad")]
    breakpad_cache: FileCache<BreakpadResolver>,
    elf_cache: FileCache<ElfResolverData>,
    #[cfg(feature = "gsym")]
    gsym_cache: FileCache<GsymResolver<'static>>,
    ksym_cache: FileCache<Rc<KsymResolver>>,
    perf_map_cache: FileCache<PerfMap>,
    /// Cache of VMA data on per-process basis.
    ///
    /// This member is only populated by explicit requests for caching
    /// data by the user.
    process_vma_cache: RefCell<HashMap<Pid, Box<[maps::MapsEntry]>>>,
    process_cache: InsertMap<PathName, Option<Box<dyn Resolve>>>,
    find_sym_opts: FindSymOpts,
    demangle: bool,
    #[cfg(feature = "dwarf")]
    debug_dirs: Vec<PathBuf>,
    #[cfg(feature = "apk")]
    apk_dispatch: Option<Dbg<Box<dyn ApkDispatch>>>,
    process_dispatch: Option<Dbg<Box<dyn ProcessDispatch>>>,
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
    #[cfg_attr(feature = "tracing", crate::log::instrument(skip_all, fields(addr = format_args!("{addr:#x}"), resolver = ?resolver.inner())))]
    fn symbolize_with_resolver<'slf>(
        &'slf self,
        addr: Addr,
        resolver: &Resolver<'_, 'slf>,
    ) -> Result<Symbolized<'slf>> {
        let (sym_name, sym_module, sym_addr, sym_size, code_info, inlined) = match resolver {
            Resolver::Uncached(resolver) => match resolver.find_sym(addr, &self.find_sym_opts)? {
                Ok(sym) => {
                    let ResolvedSym {
                        name,
                        module,
                        addr,
                        size,
                        lang,
                        code_info,
                        inlined,
                    } = sym;

                    let name =
                        Cow::Owned(self.maybe_demangle(Cow::Borrowed(name), lang).into_owned());
                    let module = module.map(|module| Cow::Owned(module.to_os_string()));
                    let code_info = code_info.map(|info| info.to_owned());
                    let inlined = Vec::from(inlined)
                        .into_iter()
                        .map(|inlined_fn| {
                            let InlinedFn {
                                name,
                                code_info,
                                _non_exhaustive: (),
                            } = inlined_fn;
                            InlinedFn {
                                name: Cow::Owned(self.maybe_demangle(name, lang).into_owned()),
                                code_info: code_info.map(|info| info.to_owned()),
                                _non_exhaustive: (),
                            }
                        })
                        .collect::<Vec<_>>()
                        .into_boxed_slice();

                    (name, module, addr, size, code_info, inlined)
                }
                Err(reason) => return Ok(Symbolized::Unknown(reason)),
            },
            Resolver::Cached(resolver) => match resolver.find_sym(addr, &self.find_sym_opts)? {
                Ok(sym) => {
                    let ResolvedSym {
                        name,
                        module,
                        addr,
                        size,
                        lang,
                        code_info,
                        mut inlined,
                    } = sym;

                    let name = self.maybe_demangle(Cow::Borrowed(name), lang);
                    let module = module.map(Cow::Borrowed);
                    let () = inlined.iter_mut().for_each(|inlined_fn| {
                        let name = take(&mut inlined_fn.name);
                        inlined_fn.name = self.maybe_demangle(name, lang);
                    });
                    (name, module, addr, size, code_info, inlined)
                }
                Err(reason) => return Ok(Symbolized::Unknown(reason)),
            },
        };

        let sym = Sym {
            name: sym_name,
            module: sym_module,
            addr: sym_addr,
            offset: (addr - sym_addr) as usize,
            size: sym_size,
            code_info,
            inlined,
            _non_exhaustive: (),
        };
        Ok(Symbolized::Sym(sym))
    }

    /// Symbolize a list of addresses using the provided [`SymResolver`].
    fn symbolize_addrs<'slf>(
        &'slf self,
        addrs: &[Addr],
        resolver: &Resolver<'_, 'slf>,
    ) -> Result<Vec<Symbolized<'slf>>> {
        addrs
            .iter()
            .map(|addr| self.symbolize_with_resolver(*addr, resolver))
            .collect()
    }

    #[cfg(feature = "gsym")]
    fn create_gsym_resolver(&self, path: &Path, file: &File) -> Result<GsymResolver<'static>> {
        let resolver = GsymResolver::from_file(path.to_path_buf(), file)?;
        Ok(resolver)
    }

    #[cfg(feature = "gsym")]
    fn gsym_resolver<'slf>(&'slf self, path: &Path) -> Result<&'slf GsymResolver<'static>> {
        let (file, cell) = self.gsym_cache.entry(path)?;
        let resolver = cell.get_or_try_init(|| self.create_gsym_resolver(path, file))?;
        Ok(resolver)
    }

    #[cfg(feature = "apk")]
    fn create_apk_resolver<'slf>(
        &'slf self,
        apk: &zip::Archive,
        apk_path: &Path,
        file_off: u64,
        debug_dirs: Option<&[PathBuf]>,
        resolver_map: &'slf InsertMap<Range<u64>, Box<dyn Resolve>>,
    ) -> Result<Option<(&'slf dyn Resolve, Addr)>> {
        // Find the APK entry covering the calculated file offset.
        for apk_entry in apk.entries() {
            let apk_entry = apk_entry
                .with_context(|| format!("failed to iterate `{}` members", apk_path.display()))?;
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
                    let info = ApkMemberInfo {
                        apk_path,
                        member_path: apk_entry.path,
                        member_mmap: mmap,
                        _non_exhaustive: (),
                    };

                    let resolver = if let Some(Dbg(apk_dispatch)) = &self.apk_dispatch {
                        if let Some(resolver) = (apk_dispatch)(info.clone())? {
                            resolver
                        } else {
                            default_apk_dispatcher(info, debug_dirs)?
                        }
                    } else {
                        default_apk_dispatcher(info, debug_dirs)?
                    };

                    Ok(resolver)
                })?;

                let elf_off = file_off - apk_entry.data_offset;
                if let Some(addr) = resolver.file_offset_to_virt_offset(elf_off)? {
                    return Ok(Some((resolver.deref(), addr)))
                }
                break
            }
        }

        Ok(None)
    }

    // TODO: Should likely require a `PathLike` as input, similar to
    //       `FileCache<ElfResolverData>::elf_resolver`.
    #[cfg(feature = "apk")]
    fn apk_resolver<'slf>(
        &'slf self,
        path: &Path,
        file_off: u64,
        debug_syms: bool,
    ) -> Result<Option<(&'slf dyn Resolve, Addr)>> {
        let (file, cell) = self.apk_cache.entry(path)?;
        let (apk, resolvers) = cell.get_or_try_init(|| {
            let mmap = Mmap::builder()
                .map(file)
                .with_context(|| format!("failed to memory map `{}`", path.display()))?;
            let apk = zip::Archive::with_mmap(mmap)
                .with_context(|| format!("failed to open zip file `{}`", path.display()))?;
            let resolvers = InsertMap::new();
            Result::<_, Error>::Ok((apk, resolvers))
        })?;

        let debug_dirs = self.maybe_debug_dirs(debug_syms);
        let result = self.create_apk_resolver(apk, path, file_off, debug_dirs, resolvers);
        result
    }

    #[cfg(feature = "breakpad")]
    fn create_breakpad_resolver(&self, path: &Path, file: &File) -> Result<BreakpadResolver> {
        let resolver = BreakpadResolver::from_file(path.to_path_buf(), file)?;
        Ok(resolver)
    }

    #[cfg(feature = "breakpad")]
    fn breakpad_resolver<'slf>(&'slf self, path: &Path) -> Result<&'slf BreakpadResolver> {
        let (file, cell) = self.breakpad_cache.entry(path)?;
        let resolver = cell.get_or_try_init(|| self.create_breakpad_resolver(path, file))?;
        Ok(resolver)
    }

    fn create_perf_map(&self, path: &Path, file: &File) -> Result<PerfMap> {
        let perf_map = PerfMap::from_file(path, file)?;
        Ok(perf_map)
    }

    fn perf_map(&self, pid: Pid) -> Result<Option<&PerfMap>> {
        let path = PerfMap::path(pid);

        match self.perf_map_cache.entry(&path) {
            Ok((file, cell)) => {
                let perf_map = cell.get_or_try_init(|| self.create_perf_map(&path, file))?;
                Ok(Some(perf_map))
            }
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err).with_context(|| format!("failed to open perf map `{path:?}`")),
        }
    }

    fn process_dispatch_resolver<'slf>(
        &'slf self,
        range: Range<Addr>,
        path_name: &PathName,
    ) -> Result<Option<&'slf dyn Resolve>> {
        if let Some(Dbg(process_dispatch)) = &self.process_dispatch {
            let resolver = self
                .process_cache
                .get_or_try_insert(path_name.clone(), || {
                    let info = ProcessMemberInfo {
                        range,
                        member_entry: path_name,
                        _non_exhaustive: (),
                    };
                    (process_dispatch)(info)
                })?;
            Ok(resolver.as_deref())
        } else {
            Ok(None)
        }
    }

    /// Symbolize the given list of user space addresses in the provided
    /// process.
    fn symbolize_user_addrs(
        &self,
        addrs: &[Addr],
        pid: Pid,
        debug_syms: bool,
        perf_map: bool,
        map_files: bool,
    ) -> Result<Vec<Symbolized>> {
        let mut handler = SymbolizeHandler {
            symbolizer: self,
            pid,
            debug_syms,
            perf_map,
            map_files,
            all_symbols: Vec::with_capacity(addrs.len()),
        };

        let handler = util::with_ordered_elems(
            addrs,
            |handler: &mut SymbolizeHandler<'_>| handler.all_symbols.as_mut_slice(),
            |sorted_addrs| -> Result<SymbolizeHandler<'_>> {
                if let Some(cached) = self.process_vma_cache.borrow().get(&pid) {
                    let mut entry_iter = cached.iter().map(Ok);
                    let entries = |_addr| entry_iter.next();

                    let () = normalize_sorted_user_addrs_with_entries(
                        sorted_addrs,
                        entries,
                        &mut handler,
                    )?;
                    Ok(handler)
                } else {
                    let mut entry_iter = maps::parse_filtered(pid)?;
                    let entries = |_addr| entry_iter.next();

                    let () = normalize_sorted_user_addrs_with_entries(
                        sorted_addrs,
                        entries,
                        &mut handler,
                    )?;
                    Ok(handler)
                }
            },
        )?;
        Ok(handler.all_symbols)
    }

    fn create_ksym_resolver(&self, path: &Path, file: &File) -> Result<Rc<KsymResolver>> {
        let resolver = KsymResolver::load_from_reader(file, path)?;
        let resolver = Rc::new(resolver);
        Ok(resolver)
    }

    fn ksym_resolver<'slf>(&'slf self, path: &Path) -> Result<&'slf Rc<KsymResolver>> {
        let (file, cell) = self.ksym_cache.entry(path)?;
        let resolver = cell.get_or_try_init(|| self.create_ksym_resolver(path, file))?;
        Ok(resolver)
    }

    #[cfg(linux)]
    fn create_kernel_resolver(&self, src: &Kernel) -> Result<KernelResolver> {
        use crate::util::bytes_to_os_str;
        use crate::MaybeDefault;

        let Kernel {
            kallsyms,
            vmlinux,
            kaslr_offset,
            debug_syms,
            _non_exhaustive: (),
        } = src;

        let ksym_resolver = match kallsyms {
            MaybeDefault::Some(kallsyms) => {
                let ksym_resolver = self.ksym_resolver(kallsyms)?;
                Some(ksym_resolver)
            }
            MaybeDefault::Default => {
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
            }
            MaybeDefault::None => None,
        };

        let elf_resolver = match vmlinux {
            MaybeDefault::Some(vmlinux) => {
                let resolver = self
                    .elf_cache
                    .elf_resolver(vmlinux.as_path(), self.maybe_debug_dirs(*debug_syms))?;
                Some(resolver)
            }
            MaybeDefault::Default => {
                let release = uname_release()?;
                let release = bytes_to_os_str(release.as_bytes())?;
                let basename = OsStr::new("vmlinux-");
                let dirs = [Path::new("/boot/"), Path::new("/usr/lib/debug/boot/")];
                let vmlinux = dirs.iter().find_map(|dir| {
                    let mut file = basename.to_os_string();
                    let () = file.push(release);
                    let path = dir.join(file);
                    path.exists().then_some(path)
                });

                if let Some(vmlinux) = vmlinux {
                    let result = self
                        .elf_cache
                        .elf_resolver(vmlinux.as_path(), self.maybe_debug_dirs(*debug_syms));
                    match result {
                        Ok(resolver) => {
                            log::debug!("found suitable vmlinux file `{}`", vmlinux.display());
                            Some(resolver)
                        }
                        Err(err) => {
                            log::warn!(
                                "failed to load vmlinux `{}`: {err}; ignoring...",
                                vmlinux.display()
                            );
                            None
                        }
                    }
                } else {
                    None
                }
            }
            MaybeDefault::None => None,
        };

        KernelResolver::new(ksym_resolver.cloned(), elf_resolver.cloned(), *kaslr_offset)
    }

    #[cfg(not(linux))]
    fn create_kernel_resolver(&self, _src: &Kernel) -> Result<KernelResolver> {
        Err(Error::with_unsupported(
            "kernel address symbolization is unsupported on operating systems other than Linux",
        ))
    }

    /// Cache some or all information associated with a symbolization
    /// source.
    ///
    /// Symbolization data is generally being cached when symbolization
    /// is performed. However, sometimes it is necessary to cache data
    /// early, for example to make subsequent symbolization requests as
    /// fast running as possible. In rare instances it can also be a
    /// matter of correctness. Process metadata such as VMAs and their
    /// offsets can be cached so that even after the processes exited
    /// symbolization requests can still be satisfied.
    ///
    /// If this method fails, any previously cached data is left
    /// untouched and will be used subsequently as if no failure
    /// occurred. Put differently, this method is only effectful on the
    /// happy path.
    #[cfg_attr(feature = "tracing", crate::log::instrument(skip_all, fields(cache = ?cache), err))]
    pub fn cache(&self, cache: &Cache) -> Result<()> {
        match cache {
            Cache::Elf(cache::Elf {
                path,
                _non_exhaustive: (),
            }) => {
                let _unpinned = self.elf_cache.unpin(path);
                let result = self
                    .elf_cache
                    .elf_resolver(path.as_path(), self.maybe_debug_dirs(false));
                // Make sure to always pin the entry, even if bailing
                // due to a retrieval error. Basically, the semantics we
                // want to have is that if caching new data fails the
                // previously cached data is still present.
                let _pinned = self.elf_cache.pin(path);
                let resolver = result?;

                let () = resolver.cache()?;
            }
            Cache::Process(cache::Process {
                pid,
                cache_vmas,
                _non_exhaustive: (),
            }) => {
                if *cache_vmas {
                    let parsed = maps::parse_filtered(*pid)?.collect::<Result<Box<_>>>()?;
                    let _prev = self.process_vma_cache.borrow_mut().insert(*pid, parsed);
                }
            }
        }
        Ok(())
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
    /// | Format      | Feature                          | Supported by format? | Supported by blazesym? |
    /// |-------------|----------------------------------|:--------------------:|:----------------------:|
    /// | Breakpad    | symbol size                      | yes                  | yes                    |
    /// |             | source code location information | yes                  | yes                    |
    /// |             | inlined function information     | yes                  | yes                    |
    /// | ELF         | symbol size                      | yes                  | yes                    |
    /// |             | source code location information | no                   | N/A                    |
    /// |             | inlined function information     | no                   | N/A                    |
    /// | DWARF       | symbol size                      | yes                  | yes                    |
    /// |             | source code location information | yes                  | yes                    |
    /// |             | inlined function information     | yes                  | yes                    |
    /// | Gsym        | symbol size                      | yes                  | yes                    |
    /// |             | source code location information | yes                  | yes                    |
    /// |             | inlined function information     | yes                  | yes                    |
    /// | Ksym        | symbol size                      | no                   | N/A                    |
    /// |             | source code location information | no                   | N/A                    |
    /// |             | inlined function information     | no                   | N/A                    |
    /// | BPF program | symbol size                      | no (?)               | no                     |
    /// |             | source code location information | yes                  | yes                    |
    /// |             | inlined function information     | no                   | no                     |
    #[cfg_attr(feature = "tracing", crate::log::instrument(skip_all, fields(src = ?src, addrs = ?input.map(Hexify)), err))]
    pub fn symbolize<'slf>(
        &'slf self,
        src: &Source,
        input: Input<&[u64]>,
    ) -> Result<Vec<Symbolized<'slf>>> {
        match src {
            #[cfg(feature = "apk")]
            Source::Apk(Apk {
                path,
                debug_syms,
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
                Input::FileOffset(offsets) => offsets
                    .iter()
                    .map(
                        |offset| match self.apk_resolver(path, *offset, *debug_syms)? {
                            Some((elf_resolver, elf_addr)) => self.symbolize_with_resolver(
                                elf_addr,
                                &Resolver::Cached(elf_resolver.as_symbolize()),
                            ),
                            None => Ok(Symbolized::Unknown(Reason::InvalidFileOffset)),
                        },
                    )
                    .collect(),
            },
            #[cfg(feature = "breakpad")]
            Source::Breakpad(Breakpad {
                path,
                _non_exhaustive: (),
            }) => {
                let addrs = match input {
                    Input::VirtOffset(..) => {
                        return Err(Error::with_unsupported(
                            "Breakpad symbolization does not support virtual offset inputs",
                        ))
                    }
                    Input::AbsAddr(..) => {
                        return Err(Error::with_unsupported(
                            "Breakpad symbolization does not support absolute address inputs",
                        ))
                    }
                    Input::FileOffset(addrs) => addrs,
                };

                let resolver = self.breakpad_resolver(path)?;
                let symbols = self.symbolize_addrs(addrs, &Resolver::Cached(resolver))?;
                Ok(symbols)
            }
            Source::Elf(Elf {
                path,
                debug_syms,
                _non_exhaustive: (),
            }) => {
                let resolver = self
                    .elf_cache
                    .elf_resolver(path.as_path(), self.maybe_debug_dirs(*debug_syms))?;
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
                            |offset| match resolver.file_offset_to_virt_offset(*offset)? {
                                Some(addr) => self.symbolize_with_resolver(
                                    addr,
                                    &Resolver::Cached(resolver.deref()),
                                ),
                                None => Ok(Symbolized::Unknown(Reason::InvalidFileOffset)),
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
                debug_syms,
                perf_map,
                map_files,
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

                self.symbolize_user_addrs(addrs, *pid, *debug_syms, *perf_map, *map_files)
            }
            #[cfg(feature = "gsym")]
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
            #[cfg(feature = "gsym")]
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
                let symbols = self.symbolize_addrs(addrs, &Resolver::Cached(resolver))?;
                Ok(symbols)
            }
            Source::Phantom(()) => unreachable!(),
        }
    }

    /// Symbolize a single input address/offset.
    ///
    /// In general, it is more performant to symbolize addresses in batches
    /// using [`symbolize`][Self::symbolize]. However, in cases where only a
    /// single address is available, this method provides a more convenient API.
    #[cfg_attr(feature = "tracing", crate::log::instrument(skip_all, fields(src = ?src, input = format_args!("{input:#x?}")), err))]
    pub fn symbolize_single<'slf>(
        &'slf self,
        src: &Source,
        input: Input<u64>,
    ) -> Result<Symbolized<'slf>> {
        match src {
            #[cfg(feature = "apk")]
            Source::Apk(Apk {
                path,
                debug_syms,
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
                Input::FileOffset(offset) => match self.apk_resolver(path, offset, *debug_syms)? {
                    Some((elf_resolver, elf_addr)) => self.symbolize_with_resolver(
                        elf_addr,
                        &Resolver::Cached(elf_resolver.as_symbolize()),
                    ),
                    None => return Ok(Symbolized::Unknown(Reason::InvalidFileOffset)),
                },
            },
            #[cfg(feature = "breakpad")]
            Source::Breakpad(Breakpad {
                path,
                _non_exhaustive: (),
            }) => {
                let addr = match input {
                    Input::VirtOffset(..) => {
                        return Err(Error::with_unsupported(
                            "Breakpad symbolization does not support virtual offset inputs",
                        ))
                    }
                    Input::AbsAddr(..) => {
                        return Err(Error::with_unsupported(
                            "Breakpad symbolization does not support absolute address inputs",
                        ))
                    }
                    Input::FileOffset(addr) => addr,
                };

                let resolver = self.breakpad_resolver(path)?;
                self.symbolize_with_resolver(addr, &Resolver::Cached(resolver))
            }
            Source::Elf(Elf {
                path,
                debug_syms,
                _non_exhaustive: (),
            }) => {
                let resolver = self
                    .elf_cache
                    .elf_resolver(path.as_path(), self.maybe_debug_dirs(*debug_syms))?;
                let addr = match input {
                    Input::VirtOffset(addr) => addr,
                    Input::AbsAddr(..) => {
                        return Err(Error::with_unsupported(
                            "ELF symbolization does not support absolute address inputs",
                        ))
                    }
                    Input::FileOffset(offset) => {
                        match resolver.file_offset_to_virt_offset(offset)? {
                            Some(addr) => addr,
                            None => return Ok(Symbolized::Unknown(Reason::InvalidFileOffset)),
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
                debug_syms,
                perf_map,
                map_files,
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

                let mut symbols =
                    self.symbolize_user_addrs(&[addr], *pid, *debug_syms, *perf_map, *map_files)?;
                debug_assert!(symbols.len() == 1, "{symbols:#?}");
                // SANITY: `symbolize_user_addrs` should *always* return
                //         one result for one input (except on error
                //         paths, of course).
                Ok(symbols.pop().unwrap())
            }
            #[cfg(feature = "gsym")]
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
            #[cfg(feature = "gsym")]
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
                self.symbolize_with_resolver(addr, &Resolver::Cached(resolver))
            }
            Source::Phantom(()) => unreachable!(),
        }
    }

    fn maybe_debug_dirs(&self, debug_syms: bool) -> Option<&[PathBuf]> {
        #[cfg(feature = "dwarf")]
        let debug_dirs = &self.debug_dirs;
        #[cfg(not(feature = "dwarf"))]
        let debug_dirs = &[];
        debug_syms.then_some(debug_dirs)
    }
}

impl Default for Symbolizer {
    fn default() -> Self {
        Self::new()
    }
}


#[cfg(test)]
#[allow(clippy::missing_transmute_annotations)]
mod tests {
    use super::*;

    use test_log::test;

    use crate::maps::Perm;
    use crate::symbolize::CodeInfo;


    /// Exercise the `Debug` representation of various types.
    #[test]
    fn debug_repr() {
        let builder = Symbolizer::builder();
        assert_ne!(format!("{builder:?}"), "");

        let symbolizer = builder.build();
        assert_ne!(format!("{symbolizer:?}"), "");

        let test_elf = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-stable-addrs.bin");
        let parser = Rc::new(ElfParser::open(test_elf.as_path()).unwrap());
        let resolver = ElfResolver::from_parser(parser, None).unwrap();
        let resolver = Resolver::Cached(&resolver);
        assert_ne!(format!("{resolver:?}"), "");
        assert_ne!(format!("{:?}", resolver.inner()), "");

        let entries = maps::parse(Pid::Slf).unwrap();
        let () = entries.for_each(|entry| {
            assert_ne!(format!("{:?}", DebugMapsEntry(&entry.unwrap())), "");
        });
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
            .join("test-stable-addrs.bin");
        let test_gsym = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-stable-addrs.gsym");
        let test_sym = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-stable-addrs.sym");
        let test_zip = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test.zip");

        let unsupported = [
            (
                Source::Apk(Apk::new(test_zip)),
                &[
                    Input::VirtOffset([40].as_slice()),
                    Input::AbsAddr([41].as_slice()),
                ][..],
            ),
            (
                Source::Breakpad(Breakpad::new(test_sym)),
                &[
                    Input::VirtOffset([50].as_slice()),
                    Input::AbsAddr([51].as_slice()),
                ][..],
            ),
            (
                Source::Process(Process::new(Pid::Slf)),
                &[
                    Input::VirtOffset([42].as_slice()),
                    Input::FileOffset([43].as_slice()),
                ][..],
            ),
            (
                Source::Kernel(Kernel::default()),
                &[
                    Input::VirtOffset([44].as_slice()),
                    Input::FileOffset([45].as_slice()),
                ][..],
            ),
            (
                Source::Elf(Elf::new(test_elf)),
                &[Input::AbsAddr([46].as_slice())][..],
            ),
            (
                Source::Gsym(Gsym::File(GsymFile::new(test_gsym))),
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

    /// Check that we do not normalize addresses belonging to a
    /// "component" (as opposed to a file).
    #[test]
    fn symbolize_entry_various() {
        let addrs = [0x10000, 0x30000];

        let mut entry_iter = [
            Ok(MapsEntry {
                range: 0x10000..0x20000,
                perm: Perm::default(),
                offset: 0,
                path_name: Some(PathName::Component("a-component".to_string())),
                build_id: None,
            }),
            Ok(MapsEntry {
                range: 0x30000..0x40000,
                perm: Perm::default(),
                offset: 0,
                path_name: None,
                build_id: None,
            }),
        ]
        .into_iter();
        let entries = |_addr| entry_iter.next();

        let symbolizer = Symbolizer::new();
        let mut handler = SymbolizeHandler {
            symbolizer: &symbolizer,
            pid: Pid::Slf,
            debug_syms: false,
            perf_map: false,
            map_files: false,
            all_symbols: Vec::new(),
        };
        let () = normalize_sorted_user_addrs_with_entries(
            addrs.as_slice().iter().copied(),
            entries,
            &mut handler,
        )
        .unwrap();

        let syms = handler.all_symbols;
        assert_eq!(syms.len(), 2);
        assert!(
            matches!(syms[0], Symbolized::Unknown(Reason::Unsupported)),
            "{:?}",
            syms[0]
        );
    }
}
