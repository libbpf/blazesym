use std::cell::RefCell;
#[cfg(test)]
use std::env;
use std::ffi::OsStr;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::io::Error;
use std::io::ErrorKind;
use std::mem;
use std::path::Path;
use std::rc::Rc;

use crate::elf::ElfParser;
use crate::inspect::FindAddrOpts;
use crate::inspect::SymInfo;
use crate::inspect::SymType;
use crate::util::find_lowest_match_by_key;
use crate::util::find_match_or_lower_bound_by_key;
use crate::Addr;

use super::parser::debug_info_parse_symbols;
use super::parser::parse_debug_line_elf_parser;
use super::parser::AddrSrcInfo;
use super::parser::DWSymInfo;


impl From<&DWSymInfo<'_>> for SymInfo {
    fn from(other: &DWSymInfo) -> Self {
        let DWSymInfo {
            name,
            addr,
            size,
            sym_type,
            ..
        } = other;

        SymInfo {
            name: name.to_string(),
            addr: *addr as Addr,
            size: *size,
            sym_type: *sym_type,
            file_offset: 0,
            obj_file_name: None,
        }
    }
}

#[derive(Clone, Debug)]
enum Either<A, B> {
    A(A),
    B(B),
}

impl<A, B, T> Iterator for Either<A, B>
where
    A: Iterator<Item = T>,
    B: Iterator<Item = T>,
{
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::A(a) => a.next(),
            Self::B(b) => b.next(),
        }
    }
}


/// A type managing lookup of symbols.
struct DebugSyms<'mmap> {
    /// Debug symbols, ordered by address.
    syms: Box<[DWSymInfo<'mmap>]>,
    /// An index on top of `syms` sorted by name.
    // TODO: The index could be optimized to use smaller-than-word-size integers
    //       if we work with only a few symbols.
    by_name_idx: Box<[usize]>,
}

impl<'mmap> DebugSyms<'mmap> {
    /// Create a new `DebugSyms` object from the given set of symbols.
    fn new(syms: Vec<DWSymInfo<'mmap>>) -> Self {
        let mut syms = syms;
        let () = syms.sort_by(|sym1, sym2| {
            sym1.addr
                .cmp(&sym2.addr)
                .then_with(|| sym1.size.cmp(&sym2.size).reverse())
        });

        let mut by_name_idx = (0..syms.len()).collect::<Vec<_>>();
        let () = by_name_idx.sort_by(|idx1, idx2| {
            let sym1 = &syms[*idx1];
            let sym2 = &syms[*idx2];
            sym1.name
                .cmp(sym2.name)
                .then_with(|| sym1.addr.cmp(&sym2.addr))
        });

        Self {
            syms: syms.into_boxed_slice(),
            by_name_idx: by_name_idx.into_boxed_slice(),
        }
    }

    /// Find a symbol by address.
    fn find_by_addr<'slf>(
        &'slf self,
        addr: Addr,
    ) -> impl Iterator<Item = &'slf DWSymInfo<'mmap>> + Clone + 'slf {
        let idx =
            if let Some(idx) = find_match_or_lower_bound_by_key(&self.syms, addr, |sym| sym.addr) {
                idx
            } else {
                return Either::A([].into_iter())
            };

        let syms = self.syms[idx..]
            .iter()
            .take_while(move |sym| sym.contains(addr));
        Either::B(syms)
    }

    /// Find a symbol by name.
    fn find_by_name<'slf>(
        &'slf self,
        name: &'slf str,
    ) -> impl Iterator<Item = &'slf DWSymInfo<'mmap>> + Clone + 'slf {
        let idx = if let Some(idx) =
            find_lowest_match_by_key(&self.by_name_idx, &name, |idx| self.syms[*idx].name)
        {
            idx
        } else {
            return Either::A([].into_iter())
        };

        let syms = self.by_name_idx[idx..].iter().map_while(move |idx| {
            let sym = &self.syms[*idx];
            if sym.name == name {
                Some(sym)
            } else {
                None
            }
        });

        Either::B(syms)
    }
}


struct Cache<'mmap> {
    /// The ELF parser object used for reading data.
    parser: &'mmap ElfParser,
    /// Cached debug symbols.
    debug_syms: Option<DebugSyms<'mmap>>,
    /// Source location information for individual addresses; ordered by
    /// [`AddrSrcInfo::addr`].
    addr_info: Option<Vec<AddrSrcInfo<'mmap>>>,
}

impl<'mmap> Cache<'mmap> {
    /// Create a new `Cache` using the provided ELF parser.
    fn new(parser: &'mmap ElfParser) -> Self {
        Self {
            parser,
            debug_syms: None,
            addr_info: None,
        }
    }

    /// Extract the symbol information from DWARF if having not done it before.
    // Note: This function should really return a reference to
    //       `self.debug_syms`, but current borrow checker limitations
    //       effectively prevent us from doing so.
    fn ensure_debug_syms(&mut self) -> Result<(), Error> {
        if self.debug_syms.is_some() {
            return Ok(())
        }

        let debug_syms = debug_info_parse_symbols(self.parser)?;
        self.debug_syms = Some(DebugSyms::new(debug_syms));
        Ok(())
    }

    /// Extract the symbol information from DWARF if having not done it before.
    fn ensure_addr_src_info(&mut self) -> Result<&[AddrSrcInfo<'mmap>], Error> {
        // Can't use `if let` here because of borrow checker woes.
        if self.addr_info.is_some() {
            let addr_info = self.addr_info.as_ref().unwrap();
            return Ok(addr_info)
        }

        let mut addr_info = parse_debug_line_elf_parser(self.parser)?;
        let () = addr_info.sort_by(|info1, info2| {
            info1
                .addr
                .cmp(&info2.addr)
                .then_with(|| info1.dir.cmp(&info2.dir))
                .then_with(|| info1.file.cmp(&info2.file))
        });
        self.addr_info = Some(addr_info);
        Ok(self.addr_info.as_ref().unwrap())
    }
}

impl Debug for Cache<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "Cache")
    }
}

/// DwarfResolver provides abilities to query DWARF information of binaries.
#[derive(Debug)]
pub(crate) struct DwarfResolver {
    /// A cache for relevant parts of the DWARF file.
    /// SAFETY: We must not hand out references with a 'static lifetime to
    ///         this member. Rather, they should never outlive `self`.
    ///         Furthermore, this member has to be listed before `parser`
    ///         to make sure we never end up with a dangling reference.
    cache: RefCell<Cache<'static>>,
    parser: Rc<ElfParser>,
    line_number_info: bool,
    enable_debug_info_syms: bool,
}

impl DwarfResolver {
    pub fn get_parser(&self) -> &ElfParser {
        &self.parser
    }

    pub fn from_parser(
        parser: Rc<ElfParser>,
        line_number_info: bool,
        debug_info_symbols: bool,
    ) -> Self {
        Self {
            cache: RefCell::new(Cache::new(unsafe {
                // SAFETY: We own the parser and never hand out any 'static
                //         references to cache data.
                mem::transmute::<_, &'static ElfParser>(parser.as_ref())
            })),
            parser,
            line_number_info,
            enable_debug_info_syms: debug_info_symbols,
        }
    }

    /// Open a binary to load and parse .debug_line for later uses.
    ///
    /// `filename` is the name of an ELF binary/or shared object that
    /// has .debug_line section.
    pub fn open(
        filename: &Path,
        debug_line_info: bool,
        debug_info_symbols: bool,
    ) -> Result<DwarfResolver, Error> {
        let parser = ElfParser::open(filename)?;
        Ok(Self::from_parser(
            Rc::new(parser),
            debug_line_info,
            debug_info_symbols,
        ))
    }

    /// Find line information of an address.
    ///
    /// `addr` is an offset from the head of the loaded binary/or shared
    /// object. This function returns a tuple of `(dir_name, file_name,
    /// line_no)`.
    // TODO: We likely want to return a more structured type.
    pub fn find_line(&self, addr: Addr) -> Result<Option<(&Path, &OsStr, usize)>, Error> {
        if self.line_number_info {
            let mut cache = self.cache.borrow_mut();
            let addr_info = cache.ensure_addr_src_info()?;

            let idx = find_lowest_match_by_key(addr_info, &addr, |info| info.addr);
            if let Some(idx) = idx {
                let info = &addr_info[idx];
                // TODO: Should not unwrap.
                let dir = info.dir.as_ref().unwrap();
                let file = info.file.as_ref().unwrap();
                Ok(Some((dir, file, info.line as usize)))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    /// Extract the symbol information from DWARf if having not done it before.
    fn ensure_debug_syms(&self, cache: &mut Cache) -> Result<(), Error> {
        if self.enable_debug_info_syms {
            let () = cache.ensure_debug_syms()?;
            Ok(())
        } else {
            Err(Error::new(
                ErrorKind::Unsupported,
                "debug info symbol information has been disabled",
            ))
        }
    }

    /// Lookup the symbol(s) at an address.
    pub(crate) fn find_syms(&self, addr: Addr) -> Result<Vec<(&str, Addr)>, Error> {
        let mut cache = self.cache.borrow_mut();
        let () = self.ensure_debug_syms(&mut cache)?;
        // SANITY: The above `ensure_debug_syms` ensures we have `debug_syms`
        //         available.
        let debug_syms = cache.debug_syms.as_ref().unwrap();
        let syms = debug_syms
            .find_by_addr(addr)
            .map(|sym| (sym.name, sym.addr))
            .collect();

        Ok(syms)
    }

    /// Find the address of a symbol from DWARF.
    ///
    /// # Arguments
    ///
    /// * `name` - is the symbol name to find.
    /// * `opts` - is the context giving additional parameters.
    pub(crate) fn find_addr(&self, name: &str, opts: &FindAddrOpts) -> Result<Vec<SymInfo>, Error> {
        if let SymType::Variable = opts.sym_type {
            return Err(Error::new(ErrorKind::Unsupported, "Not implemented"))
        }

        let mut cache = self.cache.borrow_mut();
        let () = self.ensure_debug_syms(&mut cache)?;
        // SANITY: The above `ensure_debug_syms` ensures we have `debug_syms`
        //         available.
        let debug_syms = cache.debug_syms.as_ref().unwrap();
        let syms = debug_syms.find_by_name(name).map(SymInfo::from).collect();

        Ok(syms)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::path::PathBuf;

    use test_log::test;


    fn mksym(name: &'static str, addr: Addr) -> DWSymInfo<'static> {
        DWSymInfo {
            name,
            addr,
            size: 0,
            sym_type: SymType::Function,
        }
    }

    fn mksyms(syms: &[(&'static str, Addr)]) -> DebugSyms<'static> {
        let syms = syms.iter().map(|(name, addr)| mksym(name, *addr)).collect();
        DebugSyms::new(syms)
    }

    /// Check that our `DebugSyms` type allows for proper lookup by address.
    #[test]
    fn debug_symbol_by_addr_lookup() {
        let syms = [];
        let syms = mksyms(&syms);
        assert_eq!(syms.find_by_addr(0).count(), 0);
        assert_eq!(syms.find_by_addr(42).count(), 0);
        assert_eq!(syms.find_by_addr(0xfffffffff).count(), 0);

        let syms = [
            ("dead", 0xdeadbeef),
            ("foo", 0x42),
            ("bar", 0xffff),
            ("inlined-foo", 0x42),
        ];
        let syms = mksyms(&syms);
        assert_eq!(syms.find_by_addr(0).count(), 0);

        let found = syms.find_by_addr(0xdeadbeef).collect::<Vec<_>>();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "dead");
        assert_eq!(found[0].addr, 0xdeadbeef);

        let mut found = syms.find_by_addr(0x42).collect::<Vec<_>>();
        let () = found.sort_by_key(|sym| sym.name);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].name, "foo");
        assert_eq!(found[1].name, "inlined-foo");
    }

    /// Check that our `DebugSyms` type allows for proper lookup by name.
    #[test]
    fn debug_symbol_by_name_lookup() {
        let syms = [];
        let syms = mksyms(&syms);
        assert_eq!(syms.find_by_name("").count(), 0);
        assert_eq!(syms.find_by_name("foobar").count(), 0);

        let syms = [("foobar", 0x123), ("foobar", 0x126), ("bar", 0x127)];
        let syms = mksyms(&syms);
        assert_eq!(syms.find_by_name("").count(), 0);

        let found = syms.find_by_name("foobar").collect::<Vec<_>>();
        // Reported symbols are guaranteed to be ordered in increasing order of
        // address.
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].addr, 0x123);
        assert_eq!(found[1].addr, 0x126);

        let found = syms.find_by_name("bar").collect::<Vec<_>>();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].addr, 0x127);
    }

    /// Check that we can find the source code location of an address.
    #[test]
    fn source_location_finding() {
        let bin_name = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-stable-addresses.bin");
        let resolver = DwarfResolver::open(bin_name.as_ref(), true, false).unwrap();

        let (dir, file, line) = resolver.find_line(0x2000100).unwrap().unwrap();
        assert_ne!(dir, PathBuf::new());
        assert_eq!(file, "test-stable-addresses.c");
        assert_eq!(line, 8);
    }

    /// Check that we can look up a symbol in DWARF debug information.
    #[test]
    fn lookup_symbol() {
        let test_dwarf = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-stable-addresses-dwarf-only.bin");
        let opts = FindAddrOpts {
            offset_in_file: false,
            obj_file_name: false,
            sym_type: SymType::Function,
        };
        let resolver = DwarfResolver::open(test_dwarf.as_ref(), true, true).unwrap();

        let symbols = resolver.find_addr("factorial", &opts).unwrap();
        assert_eq!(symbols.len(), 1);

        // `factorial` resides at address 0x2000100.
        let symbol = symbols.first().unwrap();
        assert_eq!(symbol.addr, 0x2000100);
    }

    /// Check that we fail to look up variables.
    #[test]
    fn lookup_symbol_wrong_type() {
        let test_dwarf = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-stable-addresses-dwarf-only.bin");
        let opts = FindAddrOpts {
            offset_in_file: false,
            obj_file_name: false,
            sym_type: SymType::Variable,
        };
        let resolver = DwarfResolver::open(test_dwarf.as_ref(), true, true).unwrap();

        let err = resolver.find_addr("factorial", &opts).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Unsupported);
    }
}
