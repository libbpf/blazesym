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
use super::parser::DWSymInfo;
use super::parser::DebugLineCU;


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
    /// Debug symbols, ordered by name.
    syms: Box<[DWSymInfo<'mmap>]>,
}

impl<'mmap> DebugSyms<'mmap> {
    /// Create a new `DebugSyms` object from the given set of symbols.
    fn new(mut syms: Vec<DWSymInfo<'mmap>>) -> Self {
        let () = syms.sort_by_key(|sym| sym.name);
        Self {
            syms: syms.into_boxed_slice(),
        }
    }

    /// Find a symbol by name.
    fn find_by_name<'slf>(
        &'slf self,
        name: &'slf str,
    ) -> impl Iterator<Item = &'slf DWSymInfo<'mmap>> + Clone + 'slf {
        let idx = if let Some(idx) = find_lowest_match_by_key(&self.syms, &name, |sym| sym.name) {
            idx
        } else {
            return Either::A([].into_iter())
        };

        let syms = self.syms[idx..]
            .iter()
            .take_while(move |item| item.name == name);

        Either::B(syms)
    }
}


struct Cache<'mmap> {
    /// The ELF parser object used for reading data.
    parser: &'mmap ElfParser,
    /// Cached debug symbols.
    debug_syms: Option<DebugSyms<'mmap>>,
}

impl<'mmap> Cache<'mmap> {
    /// Create a new `Cache` using the provided ELF parser.
    fn new(parser: &'mmap ElfParser) -> Self {
        Self {
            parser,
            debug_syms: None,
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
    debug_line_cus: Vec<DebugLineCU>,
    addr_to_dlcu: Vec<(Addr, u32)>,
    enable_debug_info_syms: bool,
}

impl DwarfResolver {
    pub fn get_parser(&self) -> &ElfParser {
        &self.parser
    }

    pub fn from_parser_for_addresses(
        parser: Rc<ElfParser>,
        addresses: &[Addr],
        line_number_info: bool,
        debug_info_symbols: bool,
    ) -> Result<DwarfResolver, Error> {
        let debug_line_cus: Vec<DebugLineCU> = if line_number_info {
            parse_debug_line_elf_parser(&parser, addresses).unwrap_or_default()
        } else {
            vec![]
        };

        let mut addr_to_dlcu = Vec::with_capacity(debug_line_cus.len());
        for (idx, dlcu) in debug_line_cus.iter().enumerate() {
            if dlcu.matrix.is_empty() {
                continue
            }
            let first_addr = dlcu.matrix[0].addr;
            addr_to_dlcu.push((first_addr, idx as u32));
        }
        addr_to_dlcu.sort_by_key(|v| v.0);

        Ok(DwarfResolver {
            cache: RefCell::new(Cache::new(unsafe {
                // SAFETY: We own the parser and never hand out any 'static
                //         references to cache data.
                mem::transmute::<_, &'static ElfParser>(parser.as_ref())
            })),
            parser,
            debug_line_cus,
            addr_to_dlcu,
            enable_debug_info_syms: debug_info_symbols,
        })
    }

    /// Open a binary to load .debug_line only enough for a given list of addresses.
    ///
    /// When `addresses` is not empty, the returned instance only has
    /// data that related to these addresses.  For this case, the
    /// instance have the ability that can serve only these addresses.
    /// This would be much faster.
    ///
    /// If `addresses` is empty, the returned instance has all data
    /// from the given file.  If the instance will be used for long
    /// running, you would want to load all data into memory to have
    /// the ability of handling all possible addresses.
    fn open_for_addresses(
        filename: &Path,
        addresses: &[Addr],
        line_number_info: bool,
        debug_info_symbols: bool,
    ) -> Result<DwarfResolver, Error> {
        let parser = ElfParser::open(filename)?;
        Self::from_parser_for_addresses(
            Rc::new(parser),
            addresses,
            line_number_info,
            debug_info_symbols,
        )
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
        Self::open_for_addresses(filename, &[], debug_line_info, debug_info_symbols)
    }

    fn find_dlcu_index(&self, addr: Addr) -> Option<usize> {
        let a2a = &self.addr_to_dlcu;
        let a2a_idx = find_match_or_lower_bound_by_key(a2a, addr, |a2dlcu| a2dlcu.0)?;
        let dlcu_idx = a2a[a2a_idx].1 as usize;

        Some(dlcu_idx)
    }

    /// Find line information of an address.
    ///
    /// `addr` is an offset from the head of the loaded binary/or shared
    /// object. This function returns a tuple of `(dir_name, file_name,
    /// line_no)`.
    pub fn find_line(&self, addr: Addr) -> Option<(&Path, &OsStr, usize)> {
        let idx = self.find_dlcu_index(addr)?;
        let dlcu = &self.debug_line_cus[idx];

        dlcu.find_line(addr)
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
        let elf_r = self.parser.find_addr(name, opts)?;
        if !elf_r.is_empty() {
            // Since it is found from symtab, symtab should be
            // complete and DWARF shouldn't provide more information.
            return Ok(elf_r)
        }

        let mut cache = self.cache.borrow_mut();
        let () = self.ensure_debug_syms(&mut cache)?;
        // SANITY: The above `ensure_debug_syms` ensures we have `debug_syms`
        //         available.
        let debug_syms = cache.debug_syms.as_ref().unwrap();
        let syms = debug_syms.find_by_name(name).map(SymInfo::from).collect();

        Ok(syms)
    }

    #[cfg(test)]
    fn pick_address_for_test(&self) -> (Addr, &Path, &OsStr, usize) {
        let (addr, idx) = self.addr_to_dlcu[self.addr_to_dlcu.len() / 3];
        let dlcu = &self.debug_line_cus[idx as usize];
        let (dir, file, line) = dlcu.stringify_row(0).unwrap();
        (addr, dir, file, line)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn test_dwarf_resolver() {
        let bin_name = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-dwarf-v4.bin");
        let resolver = DwarfResolver::open(bin_name.as_ref(), true, false).unwrap();
        let (addr, dir, file, line) = resolver.pick_address_for_test();

        let (dir_ret, file_ret, line_ret) = resolver.find_line(addr).unwrap();
        assert_eq!(dir, dir_ret);
        assert_eq!(file, file_ret);
        assert_eq!(line, line_ret);
    }

    /// Check that we can look up a symbol in DWARF debug information.
    #[test]
    fn lookup_symbol() {
        let test_dwarf = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-stable-addresses-dwarf.bin");
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
            .join("test-stable-addresses-dwarf.bin");
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
