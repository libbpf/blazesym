#[cfg(test)]
use std::env;
use std::ffi::OsStr;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::mem;
use std::ops::Deref as _;
use std::path::Path;
use std::rc::Rc;

use gimli::Dwarf;

use crate::elf::ElfParser;
use crate::inspect::FindAddrOpts;
use crate::inspect::SymInfo;
use crate::inspect::SymType;
use crate::Addr;
use crate::Error;
use crate::Result;

use super::reader;
use super::units::Units;


/// DwarfResolver provides abilities to query DWARF information of binaries.
pub(crate) struct DwarfResolver {
    /// The lazily parsed compilation units of the DWARF file.
    /// SAFETY: We must not hand out references with a 'static lifetime to
    ///         this member. Rather, they should never outlive `self`.
    ///         Furthermore, this member has to be listed before `parser`
    ///         to make sure we never end up with a dangling reference.
    units: Units<'static>,
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
    ) -> Result<Self, Error> {
        // SAFETY: We own the `ElfParser` and make sure that it stays
        //         around while the `Units` object uses it. As such, it
        //         is fine to conjure a 'static lifetime here.
        let static_parser =
            unsafe { mem::transmute::<&ElfParser, &'static ElfParser>(parser.deref()) };
        let mut load_section = |section| reader::load_section(static_parser, section);
        let dwarf = Dwarf::load(&mut load_section)?;
        let units = Units::parse(dwarf)?;
        let slf = Self {
            units,
            parser,
            line_number_info,
            enable_debug_info_syms: debug_info_symbols,
        };
        Ok(slf)
    }

    /// Open a binary to load and parse .debug_line for later uses.
    ///
    /// `filename` is the name of an ELF binary/or shared object that
    /// has .debug_line section.
    pub fn open(filename: &Path, debug_line_info: bool, debug_info_symbols: bool) -> Result<Self> {
        let parser = ElfParser::open(filename)?;
        Self::from_parser(Rc::new(parser), debug_line_info, debug_info_symbols)
    }

    /// Find line information of an address.
    ///
    /// `addr` is an offset from the head of the loaded binary/or shared
    /// object. This function returns a tuple of `(dir_name, file_name,
    /// line_no)`.
    // TODO: We likely want to return a more structured type.
    pub fn find_line(&self, addr: Addr) -> Result<Option<(&Path, &OsStr, u32)>> {
        // TODO: This conditional logic is weird and potentially
        //       unnecessary. Consider removing it or moving it higher
        //       in the call chain.
        if self.line_number_info {
            let location = self.units.find_location(addr as u64)?.map(|location| {
                let dir = location.dir;
                let file = location.file;
                let line = location.line.unwrap_or(0);
                (dir, file, line)
            });
            Ok(location)
        } else {
            Ok(None)
        }
    }

    /// Lookup the symbol(s) at an address.
    pub(crate) fn find_syms(&self, addr: Addr) -> Result<Vec<(&str, Addr)>, Error> {
        // TODO: This conditional logic is weird and potentially
        //       unnecessary. Consider removing it or moving it higher
        //       in the call chain.
        if !self.enable_debug_info_syms {
            return Err(Error::with_unsupported(
                "debug info symbol information has been disabled",
            ))
        }

        let function = self.units.find_function(addr as u64)?;
        if let Some(function) = function {
            let name = function
                .name
                .map(|name| name.to_string())
                .transpose()?
                .unwrap_or("");
            let addr = function
                .range
                .map(|range| range.begin as usize)
                .unwrap_or(0);
            Ok(vec![(name, addr)])
        } else {
            Ok(Vec::new())
        }
    }

    /// Find the address of a symbol from DWARF.
    ///
    /// # Arguments
    ///
    /// * `name` - is the symbol name to find.
    /// * `opts` - is the context giving additional parameters.
    pub(crate) fn find_addr(&self, name: &str, opts: &FindAddrOpts) -> Result<Vec<SymInfo>> {
        // TODO: This conditional logic is weird and potentially
        //       unnecessary. Consider removing it or moving it higher
        //       in the call chain.
        if !self.enable_debug_info_syms {
            return Err(Error::with_unsupported(
                "debug info symbol information has been disabled",
            ))
        }

        if let SymType::Variable = opts.sym_type {
            return Err(Error::with_unsupported("not implemented"))
        }

        let syms = self
            .units
            .find_name(name)
            .map(|result| {
                match result {
                    Ok(function) => {
                        // SANITY: We found the function by name, so it must have the
                        //         name attribute set.
                        let name = function.name.unwrap().to_string().unwrap().to_string();
                        let addr = function
                            .range
                            .as_ref()
                            .map(|range| range.begin as Addr)
                            .unwrap_or(0);
                        let size = function
                            .range
                            .as_ref()
                            .and_then(|range| range.end.checked_sub(range.begin))
                            .map(|size| size as usize)
                            .unwrap_or(0);
                        let info = SymInfo {
                            name,
                            addr,
                            size,
                            sym_type: SymType::Function,
                            file_offset: 0,
                            obj_file_name: None,
                        };
                        Ok(info)
                    }
                    Err(err) => Err(Error::from(err)),
                }
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(syms)
    }
}

impl Debug for DwarfResolver {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str(stringify!(DwarfResolver))
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::env::current_exe;
    use std::path::PathBuf;

    use test_log::test;

    use crate::ErrorKind;


    /// Exercise the `Debug` representation of various types.
    #[test]
    fn debug_repr() {
        let bin_name = current_exe().unwrap();
        let resolver = DwarfResolver::open(&bin_name, true, true).unwrap();
        assert_ne!(format!("{resolver:?}"), "");
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
