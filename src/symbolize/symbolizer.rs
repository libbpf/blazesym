use std::borrow::Cow;
use std::cell::OnceCell;
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
use crate::elf::StaticMem;
#[cfg(feature = "dwarf")]
use crate::elf::DEFAULT_DEBUG_DIRS;
use crate::file_cache::FileCache;
#[cfg(feature = "gsym")]
use crate::gsym::GsymResolver;
use crate::insert_map::InsertMap;
use crate::kernel::KernelCache;
use crate::kernel::KernelResolver;
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
#[cfg(feature = "apk")]
use crate::pathlike::PathLike;
use crate::perf_map::PerfMap;
use crate::symbolize::Resolve;
use crate::symbolize::TranslateFileOffset;
use crate::util;
#[cfg(linux)]
use crate::util::uname_release;
use crate::util::Dbg;
#[cfg(feature = "tracing")]
use crate::util::Hexify;
use crate::util::OnceCellExt as _;
use crate::vdso::create_vdso_parser;
use crate::vdso::VDSO_MAPS_COMPONENT;
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
fn maybe_demangle_impl(name: Cow<'_, str>, language: SrcLang) -> Cow<'_, str> {
    match language {
        SrcLang::Rust => rustc_demangle::try_demangle(name.as_ref())
            .ok()
            .as_ref()
            .map(|x| Cow::Owned(format!("{x:#}"))),
        SrcLang::Cpp => cpp_demangle::Symbol::new(name.as_ref())
            .ok()
            .and_then(|x| x.demangle().ok().map(Cow::Owned)),
        SrcLang::Unknown => rustc_demangle::try_demangle(name.as_ref())
            .map(|x| Cow::Owned(format!("{x:#}")))
            .ok()
            .or_else(|| {
                cpp_demangle::Symbol::new(name.as_ref())
                    .ok()
                    .and_then(|sym| sym.demangle().ok().map(Cow::Owned))
            }),
    }
    .unwrap_or(name)
}

#[cfg(not(feature = "demangle"))]
fn maybe_demangle_impl(name: Cow<'_, str>, _language: SrcLang) -> Cow<'_, str> {
    // Demangling is disabled.
    name
}

/// Demangle the provided symbol if asked for and possible.
fn maybe_demangle(symbol: Cow<'_, str>, language: SrcLang, demangle: bool) -> Cow<'_, str> {
    if demangle {
        maybe_demangle_impl(symbol, language)
    } else {
        symbol
    }
}


/// Symbolize an address using the provided [`Resolver`].
pub(crate) fn symbolize_with_resolver<'slf>(
    addr: Addr,
    resolver: &Resolver<'_, 'slf>,
    find_sym_opts: &FindSymOpts,
    demangle: bool,
) -> Result<Symbolized<'slf>> {
    /// Convert a `ResolvedSym` into a `Sym`, potentially performing
    /// symbol name demangling in the process.
    fn convert_sym<'sym>(addr: Addr, sym: ResolvedSym<'sym>, demangle: bool) -> Sym<'sym> {
        let ResolvedSym {
            name,
            module,
            addr: sym_addr,
            size,
            lang,
            code_info,
            mut inlined,
            _non_exhaustive: (),
        } = sym;

        let () = inlined.iter_mut().for_each(|inlined_fn| {
            let name = take(&mut inlined_fn.name);
            inlined_fn.name = maybe_demangle(name, lang, demangle);
        });

        let sym = Sym {
            name: maybe_demangle(Cow::Borrowed(name), lang, demangle),
            module: module.map(Cow::Borrowed),
            addr: sym_addr,
            offset: (addr - sym_addr) as usize,
            size,
            code_info,
            inlined,
            _non_exhaustive: (),
        };
        sym
    }

    let sym = match resolver {
        Resolver::Uncached(resolver) => match resolver.find_sym(addr, find_sym_opts)? {
            Ok(sym) => convert_sym(addr, sym, demangle).into_owned(),
            Err(reason) => return Ok(Symbolized::Unknown(reason)),
        },
        Resolver::Cached(resolver) => match resolver.find_sym(addr, find_sym_opts)? {
            Ok(sym) => convert_sym(addr, sym, demangle),
            Err(reason) => return Ok(Symbolized::Unknown(reason)),
        },
    };

    Ok(Symbolized::Sym(sym))
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
    apk_path: &dyn PathLike,
    info: ApkMemberInfo<'_>,
    debug_dirs: Option<&[PathBuf]>,
) -> Result<Box<dyn Resolve>> {
    // Create an Android-style binary-in-APK path for
    // reporting purposes.
    let apk_elf_path = create_apk_elf_path(apk_path.represented_path(), info.member_path);
    let parser = Rc::new(ElfParser::from_mmap(
        info.member_mmap,
        Some(apk_elf_path.into_os_string()),
    ));
    // TODO: Would be good to provide the `Symbolizer`'s ELF cache for
    //       use here.
    let elf_cache = None;
    let resolver = ElfResolver::from_parser(parser, debug_dirs, elf_cache)?;
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
    debug_dirs: Box<[PathBuf]>,
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
    ///
    /// This option only has an effect if `debug_syms` of the particular
    /// symbol source is set to `true`. Furthermore, it is a necessary
    /// prerequisite for retrieving inlined function information (see
    /// [`Self::enable_inlined_fns`]).
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
            self.debug_dirs = DEFAULT_DEBUG_DIRS.iter().map(PathBuf::from).collect();
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
            perf_map_cache: FileCache::builder().enable_auto_reload(auto_reload).build(),
            process_vma_cache: RefCell::new(HashMap::new()),
            process_cache: InsertMap::new(),
            kernel_cache: KernelCache::default(),
            vdso_parser: OnceCell::new(),
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
            debug_dirs: DEFAULT_DEBUG_DIRS.iter().map(PathBuf::from).collect(),
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
    /// Whether or not to symbolize addresses in a vDSO (virtual dynamic
    /// shared object).
    vdso: bool,
    /// Symbols representing the symbolized addresses.
    all_symbols: Vec<Symbolized<'sym>>,
}

impl SymbolizeHandler<'_> {
    #[cfg(feature = "apk")]
    fn handle_apk_addr(&mut self, addr: Addr, file_off: u64, entry_path: &EntryPath) -> Result<()> {
        let result = if self.map_files {
            self.symbolizer
                .apk_resolver(entry_path, file_off, self.debug_syms)?
        } else {
            let path = &entry_path.symbolic_path;
            self.symbolizer
                .apk_resolver(path, file_off, self.debug_syms)?
        };

        match result {
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
            let path = &entry_path.symbolic_path;
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
        if let Some(perf_map) = self.symbolizer.perf_map_resolver(self.pid)? {
            let symbolized = self
                .symbolizer
                .symbolize_with_resolver(addr, &Resolver::Cached(perf_map))?;
            let () = self.all_symbols.push(symbolized);
        } else {
            let () = self.handle_unknown_addr(addr, Reason::UnknownAddr);
        }
        Ok(())
    }

    fn handle_vdso_addr(
        &mut self,
        addr: Addr,
        file_off: u64,
        vdso_range: &Range<Addr>,
    ) -> Result<()> {
        let parser = self.symbolizer.vdso_parser(self.pid, vdso_range)?;
        match parser.file_offset_to_virt_offset(file_off)? {
            Some(addr) => {
                let symbol = self
                    .symbolizer
                    .symbolize_with_resolver(addr, &Resolver::Cached(parser))?;
                let () = self.all_symbols.push(symbol);
            }
            None => self.handle_unknown_addr(addr, Reason::InvalidFileOffset),
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
        let file_off = addr - entry.range.start + entry.offset;

        if let Some(path_name) = &entry.path_name {
            if let Some(resolver) = self
                .symbolizer
                .process_dispatch_resolver(entry.range.clone(), path_name)?
            {
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
            Some(PathName::Component(component)) => {
                match component.as_str() {
                    component if self.vdso && component == VDSO_MAPS_COMPONENT => {
                        let () = self.handle_vdso_addr(addr, file_off, &entry.range)?;
                    }
                    _ => {
                        let () = self.handle_unknown_addr(addr, Reason::Unsupported);
                    }
                }
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
/// hand out references to mmap'ed (or potentially static) data.
#[derive(Debug)]
pub(crate) enum Resolver<'tmp, 'slf> {
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


/// A helper type for coercing an iterator that is guaranteed to have
/// only a single element into said element, via generic means.
#[repr(transparent)]
struct Single<T>(T);

impl<A> FromIterator<A> for Single<A> {
    fn from_iter<I>(i: I) -> Self
    where
        I: IntoIterator<Item = A>,
    {
        let mut iter = i.into_iter();
        let slf = Single(iter.next().unwrap());
        debug_assert!(iter.next().is_none());
        slf
    }
}


/// A helper trait used for abstracting over input cardinality while
/// only heap allocating as necessary.
trait Addrs: AsRef<[Addr]> {
    type OutTy<'slf>: FromIterator<Result<Symbolized<'slf>>>;
}

impl Addrs for &[Addr] {
    type OutTy<'slf> = Result<Vec<Symbolized<'slf>>>;
}

impl Addrs for [Addr; 1] {
    type OutTy<'slf> = Single<Result<Symbolized<'slf>>>;
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
    perf_map_cache: FileCache<PerfMap>,
    /// Cache of VMA data on per-process basis.
    ///
    /// This member is only populated by explicit requests for caching
    /// data by the user.
    process_vma_cache: RefCell<HashMap<Pid, Box<[maps::MapsEntry]>>>,
    process_cache: InsertMap<PathName, Option<Box<dyn Resolve>>>,
    /// Cache of kernel related data.
    kernel_cache: KernelCache,
    /// The ELF parser used for the system-wide vDSO.
    vdso_parser: OnceCell<Box<ElfParser<StaticMem>>>,
    find_sym_opts: FindSymOpts,
    demangle: bool,
    #[cfg(feature = "dwarf")]
    debug_dirs: Box<[PathBuf]>,
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

    /// Register an [`ElfResolver`] to use for subsequent symbolization
    /// requests.
    ///
    /// Register an existing externally managed [`ElfResolver`] object
    /// to use in subsequent symbolization requests involving `path`.
    /// Doing so allows for reuse of already parsed ELF data.
    ///
    /// This method will fail if a cached [`ElfResolver`] is already
    /// present for the given path.
    pub fn register_elf_resolver(
        &mut self,
        path: &Path,
        elf_resolver: Rc<ElfResolver>,
    ) -> Result<()> {
        self.elf_cache.register(path, elf_resolver)
    }

    /// Symbolize an address using the provided [`Resolver`].
    #[cfg_attr(feature = "tracing", crate::log::instrument(skip_all, fields(addr = format_args!("{addr:#x}"), resolver = ?resolver.inner())))]
    fn symbolize_with_resolver<'slf>(
        &'slf self,
        addr: Addr,
        resolver: &Resolver<'_, 'slf>,
    ) -> Result<Symbolized<'slf>> {
        symbolize_with_resolver(addr, resolver, &self.find_sym_opts, self.demangle)
    }

    #[cfg(feature = "gsym")]
    fn create_gsym_resolver(&self, path: &Path, file: &File) -> Result<GsymResolver<'static>> {
        let resolver = GsymResolver::from_file(path.to_path_buf(), file)?;
        Ok(resolver)
    }

    #[cfg(feature = "gsym")]
    fn gsym_resolver<'slf>(&'slf self, path: &Path) -> Result<&'slf GsymResolver<'static>> {
        let (file, cell) = self.gsym_cache.entry(path)?;
        let resolver = cell.get_or_try_init_(|| self.create_gsym_resolver(path, file))?;
        Ok(resolver)
    }

    #[cfg(feature = "apk")]
    fn create_apk_resolver<'slf>(
        &'slf self,
        apk: &zip::Archive,
        apk_path: &dyn PathLike,
        file_off: u64,
        debug_dirs: Option<&[PathBuf]>,
        resolver_map: &'slf InsertMap<Range<u64>, Box<dyn Resolve>>,
    ) -> Result<Option<(&'slf dyn Resolve, Addr)>> {
        let actual_path = apk_path.actual_path();
        // Find the APK entry covering the calculated file offset.
        for apk_entry in apk.entries() {
            let apk_entry = apk_entry.with_context(|| {
                format!("failed to iterate `{}` members", actual_path.display())
            })?;
            let bounds = apk_entry.data_offset..apk_entry.data_offset + apk_entry.data.len() as u64;

            if bounds.contains(&file_off) {
                let resolver = resolver_map.get_or_try_insert(bounds.clone(), || {
                    let mmap = apk
                        .mmap()
                        .constrain(bounds.clone())
                        .ok_or_invalid_input(|| {
                            format!(
                                "invalid APK entry data bounds ({bounds:?}) in {}",
                                actual_path.display()
                            )
                        })?;
                    let info = ApkMemberInfo {
                        apk_path: actual_path,
                        member_path: apk_entry.path,
                        member_mmap: mmap,
                        _non_exhaustive: (),
                    };

                    let resolver = if let Some(Dbg(apk_dispatch)) = &self.apk_dispatch {
                        if let Some(resolver) = (apk_dispatch)(info.clone())? {
                            resolver
                        } else {
                            default_apk_dispatcher(apk_path, info, debug_dirs)?
                        }
                    } else {
                        default_apk_dispatcher(apk_path, info, debug_dirs)?
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

    #[cfg(feature = "apk")]
    fn apk_resolver<'slf>(
        &'slf self,
        path: &dyn PathLike,
        file_off: u64,
        debug_syms: bool,
    ) -> Result<Option<(&'slf dyn Resolve, Addr)>> {
        let actual_path = path.actual_path();
        let (file, cell) = self.apk_cache.entry(actual_path)?;
        let (apk, resolvers) = cell.get_or_try_init_(|| {
            let mmap = Mmap::builder()
                .map(file)
                .with_context(|| format!("failed to memory map `{}`", actual_path.display()))?;
            let apk = zip::Archive::with_mmap(mmap)
                .with_context(|| format!("failed to open zip file `{}`", actual_path.display()))?;
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
        let resolver = cell.get_or_try_init_(|| self.create_breakpad_resolver(path, file))?;
        Ok(resolver)
    }

    fn create_perf_map_resolver(&self, path: &Path, file: &File) -> Result<PerfMap> {
        let perf_map = PerfMap::from_file(path, file)?;
        Ok(perf_map)
    }

    fn perf_map_resolver(&self, pid: Pid) -> Result<Option<&PerfMap>> {
        let path = PerfMap::path(pid);

        match self.perf_map_cache.entry(&path) {
            Ok((file, cell)) => {
                let perf_map =
                    cell.get_or_try_init_(|| self.create_perf_map_resolver(&path, file))?;
                Ok(Some(perf_map))
            }
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
            Err(err) => {
                Err(err).with_context(|| format!("failed to open perf map `{}`", path.display()))
            }
        }
    }

    fn vdso_parser<'slf>(
        &'slf self,
        pid: Pid,
        range: &Range<Addr>,
    ) -> Result<&'slf ElfParser<StaticMem>> {
        let parser = self.vdso_parser.get_or_try_init_(|| {
            let parser = create_vdso_parser(pid, range)?;
            Result::<_, Error>::Ok(Box::new(parser))
        })?;
        Ok(parser)
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
        vdso: bool,
    ) -> Result<Vec<Symbolized<'_>>> {
        let mut handler = SymbolizeHandler {
            symbolizer: self,
            pid,
            debug_syms,
            perf_map,
            map_files,
            vdso,
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
                let ksym_resolver = self.kernel_cache.ksym_resolver(kallsyms)?;
                Some(ksym_resolver)
            }
            MaybeDefault::Default => {
                let kallsyms = Path::new(KALLSYMS);
                let result = self.kernel_cache.ksym_resolver(kallsyms);
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
                    .elf_resolver(vmlinux, self.maybe_debug_dirs(*debug_syms))?;
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
                        .elf_resolver(&vmlinux, self.maybe_debug_dirs(*debug_syms));
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

        let ksym_resolver = ksym_resolver.map(Rc::clone);
        let elf_resolver = elf_resolver.map(Rc::clone);
        let kaslr_offset = kaslr_offset
            .map(Ok)
            .unwrap_or_else(|| self.kernel_cache.kaslr_offset())?;
        KernelResolver::new(ksym_resolver, elf_resolver, kaslr_offset)
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
                    .elf_resolver(path, self.maybe_debug_dirs(false));
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

    fn symbolize_impl<'in_, 'slf, A>(
        &'slf self,
        src: &Source,
        input: Input<A>,
        maybe_fold_error: fn(Error) -> Result<Symbolized<'slf>>,
    ) -> Result<A::OutTy<'slf>>
    where
        A: Copy + Addrs + 'in_,
    {
        match src {
            #[cfg(feature = "apk")]
            Source::Apk(Apk {
                path,
                debug_syms,
                _non_exhaustive: (),
            }) => {
                let addrs = match input {
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
                    Input::FileOffset(offsets) => offsets,
                };

                let symbols = addrs
                    .as_ref()
                    .iter()
                    .copied()
                    .map(
                        |offset| match self.apk_resolver(path, offset, *debug_syms)? {
                            Some((elf_resolver, elf_addr)) => self.symbolize_with_resolver(
                                elf_addr,
                                &Resolver::Cached(elf_resolver.as_symbolize()),
                            ),
                            None => Ok(Symbolized::Unknown(Reason::InvalidFileOffset)),
                        },
                    )
                    .map(|result| result.or_else(maybe_fold_error))
                    .collect();
                Ok(symbols)
            }
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
                let symbols = addrs
                    .as_ref()
                    .iter()
                    .copied()
                    .map(|addr| self.symbolize_with_resolver(addr, &Resolver::Cached(resolver)))
                    .map(|result| result.or_else(maybe_fold_error))
                    .collect();
                Ok(symbols)
            }
            Source::Elf(Elf {
                path,
                debug_syms,
                _non_exhaustive: (),
            }) => {
                let resolver = self
                    .elf_cache
                    .elf_resolver(path, self.maybe_debug_dirs(*debug_syms))?;
                match input {
                    Input::VirtOffset(addrs) => {
                        let symbols = addrs
                            .as_ref()
                            .iter()
                            .copied()
                            .map(|addr| {
                                self.symbolize_with_resolver(
                                    addr,
                                    &Resolver::Cached(resolver.deref()),
                                )
                            })
                            .map(|result| result.or_else(maybe_fold_error))
                            .collect();
                        Ok(symbols)
                    }
                    Input::AbsAddr(..) => Err(Error::with_unsupported(
                        "ELF symbolization does not support absolute address inputs",
                    )),
                    Input::FileOffset(offsets) => {
                        let symbols = offsets
                            .as_ref()
                            .iter()
                            .copied()
                            .map(
                                |offset| match resolver.file_offset_to_virt_offset(offset)? {
                                    Some(addr) => self.symbolize_with_resolver(
                                        addr,
                                        &Resolver::Cached(resolver.deref()),
                                    ),
                                    None => Ok(Symbolized::Unknown(Reason::InvalidFileOffset)),
                                },
                            )
                            .map(|result| result.or_else(maybe_fold_error))
                            .collect();
                        Ok(symbols)
                    }
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
                let symbols = addrs
                    .as_ref()
                    .iter()
                    .copied()
                    .map(|addr| self.symbolize_with_resolver(addr, &Resolver::Uncached(&resolver)))
                    .map(|result| result.or_else(maybe_fold_error))
                    .collect();
                Ok(symbols)
            }
            Source::Process(Process {
                pid,
                debug_syms,
                perf_map,
                map_files,
                vdso,
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

                let symbols = self.symbolize_user_addrs(
                    addrs.as_ref(),
                    *pid,
                    *debug_syms,
                    *perf_map,
                    *map_files,
                    *vdso,
                )?;
                Ok(symbols
                    .into_iter()
                    .map(Ok)
                    .map(|result| result.or_else(maybe_fold_error))
                    .collect())
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
                let symbols = addrs
                    .as_ref()
                    .iter()
                    .copied()
                    .map(|addr| {
                        self.symbolize_with_resolver(addr, &Resolver::Uncached(resolver.deref()))
                    })
                    .map(|result| result.or_else(maybe_fold_error))
                    .collect();
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
                let symbols = addrs
                    .as_ref()
                    .iter()
                    .copied()
                    .map(|addr| self.symbolize_with_resolver(addr, &Resolver::Cached(resolver)))
                    .map(|result| result.or_else(maybe_fold_error))
                    .collect();
                Ok(symbols)
            }
            Source::Phantom(()) => unreachable!(),
        }
    }

    /// Symbolize a batch of addresses.
    ///
    /// Symbolize a batch of addresses using the provided symbolization
    /// [`Source`]. The [`Input`] enum describes what type of address is
    /// provided. Not all symbol sources support all address types,
    /// e.g., due to inherent limitations of the source. If an address
    /// type is not supported the method will return an [`Error`] of the
    /// [`Unsupported`][ErrorKind::Unsupported] kind.
    ///
    /// This method returns exactly one [`Symbolized`] object for each
    /// input address, in the order of input addresses. Unless an error
    /// occurs that would effect all addresses, problems preventing
    /// symbolization of individual addresses are reported via the
    /// [`Symbolized::Unknown`] variant. If you need more detailed error
    /// information for such a failure, redo the operation using
    /// [`symbolize_single`][Self::symbolize_single].
    ///
    /// The following table lists which features the various formats
    /// (represented by the [`Source`] argument) support. If a feature
    /// is not supported, the corresponding data in the [`Sym`] result
    /// will not be populated.
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
        let fold_error = |_err| Ok(Symbolized::Unknown(Reason::IgnoredError));
        // TODO: Use `Result::flatten` once our MSRV is 1.89.
        self.symbolize_impl(src, input, fold_error)
            .and_then(|result| result)
    }

    /// Symbolize a single input address/offset.
    ///
    /// In general, it is more performant to symbolize addresses in batches
    /// using [`symbolize`][Self::symbolize]. However, in cases where only a
    /// single address is available, this method provides a more convenient API.
    ///
    /// Note that this method also exhibits a slightly different error
    /// reporting behavior compared to [`symbolize`][Self::symbolize]:
    /// when symbolization of an address fails, a more comprehensive
    /// error is reported. When possible errors are not folded into the
    /// [`Symbolized::Unknown`] variant but conveyed directly as
    /// [`Result::Err`].
    #[cfg_attr(feature = "tracing", crate::log::instrument(skip_all, fields(src = ?src, input = format_args!("{input:#x?}")), err))]
    pub fn symbolize_single<'slf>(
        &'slf self,
        src: &Source,
        input: Input<u64>,
    ) -> Result<Symbolized<'slf>> {
        let input = input.map(|addr| [addr; 1]);
        let keep_error = |err| Err(err);
        self.symbolize_impl(src, input, keep_error)?.0
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

    use std::env::current_exe;
    use std::io::Write as _;
    use std::slice;

    use tempfile::NamedTempFile;
    use test_fork::fork;
    use test_log::test;

    use crate::elf::types::Elf64_Ehdr;
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
        let debug_dirs = None;
        let elf_cache = None;
        let resolver = ElfResolver::from_parser(parser, debug_dirs, elf_cache).unwrap();
        let resolver = Resolver::Cached(&resolver);
        assert_ne!(format!("{resolver:?}"), "");
        assert_ne!(format!("{:?}", resolver.inner()), "");

        let entries = maps::parse(Pid::Slf).unwrap();
        let () = entries.for_each(|entry| {
            assert_ne!(format!("{:?}", DebugMapsEntry(&entry.unwrap())), "");
        });
    }

    /// Test forcing a double check of all `Symbolizer` size changes.
    #[cfg(target_pointer_width = "64")]
    #[test]
    fn symbolizer_size() {
        // TODO: This size is rather large and we should look into
        //       minimizing it.
        assert_eq!(size_of::<Symbolizer>(), 1016);
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
        let name = maybe_demangle_impl(symbol, SrcLang::Rust);
        assert_eq!(name, "core::panicking::panic_fmt");

        let symbol = Cow::Borrowed("_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc");
        let name = maybe_demangle_impl(symbol, SrcLang::Cpp);
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
            vdso: false,
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

    /// Check that we instantiate only a minimal number of resolvers
    /// when using process symbolization with `map_files` (i.e., going
    /// through symbolic links).
    ///
    /// Effectively, this is an integration test that makes sure that we
    /// dereference symbolic links properly and not duplicate binary
    /// parsing over and over, but it peeks at implementation details.
    // Run in separate process to make sure that VMAs are not influenced
    // by tests running concurrently.
    #[fork]
    #[test]
    fn resolver_instantiation() {
        let exe = current_exe().unwrap();
        let addrs = maps::parse(Pid::Slf)
            .unwrap()
            .filter_map(|result| {
                let entry = result.unwrap();
                let path = entry.path_name.and_then(|path_name| {
                    path_name.as_path().map(|path| path.symbolic_path.clone())
                });
                if path == Some(exe.clone()) {
                    Some(entry.range.start)
                } else {
                    None
                }
            })
            .collect::<Box<[_]>>();

        assert!(addrs.len() > 1, "{:x?}", addrs.as_ref());

        let src = Source::Process(Process::new(Pid::Slf));
        let symbolizer = Symbolizer::new();
        // We don't really care whether we could symbolize the addresses
        // (unlikely), just that there was no error.
        let _result = symbolizer.symbolize(&src, Input::AbsAddr(&addrs)).unwrap();

        assert_eq!(symbolizer.elf_cache.entry_count(), 1);
    }

    /// Check the error reporting behavior of the
    /// `Symbolizer::symbolize` and `Symbolizer::symbolize_single`
    /// methods.
    #[test]
    fn symbolize_error_reporting() {
        #[repr(C)]
        struct ElfFile {
            ehdr: Elf64_Ehdr,
        }

        let elf = ElfFile {
            ehdr: Elf64_Ehdr {
                e_ident: [127, 69, 76, 70, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                e_type: 3,
                e_machine: 62,
                e_version: 1,
                e_entry: 4208,
                e_phoff: size_of::<Elf64_Ehdr>() as _,
                e_shoff: 0,
                e_flags: 0,
                e_ehsize: 64,
                e_phentsize: 56,
                e_phnum: 1000,
                e_shentsize: 0,
                e_shnum: 1000,
                e_shstrndx: 0,
            },
        };

        // Craft some broken ELF file to test error behavior.
        let mut file = NamedTempFile::new().unwrap();
        let dump = unsafe {
            slice::from_raw_parts((&elf as *const ElfFile).cast::<u8>(), size_of::<ElfFile>())
        };
        let () = file.write_all(dump).unwrap();
        let path = file.path();

        let module = path.as_os_str().to_os_string();
        let parser = ElfParser::from_file(file.as_file(), module.clone()).unwrap();
        let debug_dirs = None;
        let elf_cache = None;
        let resolver = ElfResolver::from_parser(Rc::new(parser), debug_dirs, elf_cache).unwrap();
        let resolver = Rc::new(resolver);

        for batch in [false, true] {
            let mut symbolizer = Symbolizer::new();
            let () = symbolizer
                .register_elf_resolver(path, Rc::clone(&resolver))
                .unwrap();

            let mut elf = Elf::new(path);
            elf.debug_syms = false;
            let src = Source::from(elf);
            if batch {
                let symbolized = symbolizer
                    .symbolize(&src, Input::VirtOffset([0x1337].as_slice()))
                    .unwrap();
                assert_eq!(symbolized.len(), 1);
                let symbolized = symbolized.first().unwrap();
                let Symbolized::Unknown(reason) = symbolized else {
                    panic!("unexpected symbolization result: {symbolized:?}");
                };
                assert_eq!(*reason, Reason::IgnoredError);
            } else {
                // `symbolize_single` is expected to report the error
                // directly and not fold it into the `Symbolized::Unknown`
                // variant.
                let _err = symbolizer
                    .symbolize_single(&src, Input::VirtOffset(0x1337))
                    .unwrap_err();
            }
        }
    }
}
