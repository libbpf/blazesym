use std::cell::RefCell;
#[cfg(test)]
use std::env;
use std::fmt::Debug;
use std::io::Error;
use std::io::ErrorKind;
use std::mem;
#[cfg(test)]
use std::path::Path;
use std::rc::Rc;

use regex::Regex;

use crate::elf::ElfParser;
use crate::util::find_match_or_lower_bound_by;
use crate::Addr;
use crate::FindAddrOpts;
use crate::SymbolInfo;
use crate::SymbolType;

use super::parser::debug_info_parse_symbols;
use super::parser::parse_debug_line_elf_parser;
use super::parser::DWSymInfo;
use super::parser::DebugLineCU;


/// DwarfResolver provides abilities to query DWARF information of binaries.
#[derive(Debug)]
pub struct DwarfResolver {
    parser: Rc<ElfParser>,
    debug_line_cus: Vec<DebugLineCU>,
    addr_to_dlcu: Vec<(Addr, u32)>,
    enable_debug_info_syms: bool,
    debug_info_syms: RefCell<Option<Vec<DWSymInfo<'static>>>>,
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
            let first_addr = dlcu.matrix[0].address;
            addr_to_dlcu.push((first_addr, idx as u32));
        }
        addr_to_dlcu.sort_by_key(|v| v.0);

        Ok(DwarfResolver {
            parser,
            debug_line_cus,
            addr_to_dlcu,
            enable_debug_info_syms: debug_info_symbols,
            debug_info_syms: RefCell::new(None),
        })
    }

    /// Open a binary to load .debug_line only enough for a given list of addresses.
    ///
    /// When `addresses` is not empty, the returned instance only has
    /// data that related to these addresses.  For this case, the
    /// isntance have the ability that can serve only these addresses.
    /// This would be much faster.
    ///
    /// If `addresses` is empty, the returned instance has all data
    /// from the given file.  If the instance will be used for long
    /// running, you would want to load all data into memory to have
    /// the ability of handling all possible addresses.
    #[cfg(test)]
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
    #[cfg(test)]
    pub fn open(
        filename: &Path,
        debug_line_info: bool,
        debug_info_symbols: bool,
    ) -> Result<DwarfResolver, Error> {
        Self::open_for_addresses(filename, &[], debug_line_info, debug_info_symbols)
    }

    fn find_dlcu_index(&self, address: Addr) -> Option<usize> {
        let a2a = &self.addr_to_dlcu;
        let a2a_idx = find_match_or_lower_bound_by(a2a, address, |a2dlcu| a2dlcu.0)?;
        let dlcu_idx = a2a[a2a_idx].1 as usize;

        Some(dlcu_idx)
    }

    /// Find line information of an address.
    ///
    /// `address` is an offset from the head of the loaded binary/or
    /// shared object.  This function returns a tuple of `(dir_name, file_name, line_no)`.
    pub fn find_line_as_ref(&self, address: Addr) -> Option<(&str, &str, usize)> {
        let idx = self.find_dlcu_index(address)?;
        let dlcu = &self.debug_line_cus[idx];

        dlcu.find_line(address)
    }

    /// Find line information of an address.
    ///
    /// `address` is an offset from the head of the loaded binary/or
    /// shared object.  This function returns a tuple of `(dir_name, file_name, line_no)`.
    ///
    /// This function is pretty much the same as `find_line_as_ref()`
    /// except returning a copies of `String` instead of `&str`.
    #[cfg(test)]
    fn find_line(&self, address: Addr) -> Option<(String, String, usize)> {
        let (dir, file, line_no) = self.find_line_as_ref(address)?;
        Some((String::from(dir), String::from(file), line_no))
    }

    /// Extract the symbol information from DWARf if having not done it before.
    fn ensure_debug_info_syms(&self) -> Result<(), Error> {
        if self.enable_debug_info_syms {
            let mut dis_ref = self.debug_info_syms.borrow_mut();
            if dis_ref.is_some() {
                return Ok(())
            }
            let mut debug_info_syms = debug_info_parse_symbols(&self.parser, None)?;
            debug_info_syms.sort_by_key(|v: &DWSymInfo| -> &str { v.name });
            *dis_ref = Some(unsafe { mem::transmute(debug_info_syms) });
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
    pub(crate) fn find_address(
        &self,
        name: &str,
        opts: &FindAddrOpts,
    ) -> Result<Vec<SymbolInfo>, Error> {
        if let SymbolType::Variable = opts.sym_type {
            return Err(Error::new(ErrorKind::Unsupported, "Not implemented"))
        }
        let elf_r = self.parser.find_address(name, opts)?;
        if !elf_r.is_empty() {
            // Since it is found from symtab, symtab should be
            // complete and DWARF shouldn't provide more information.
            return Ok(elf_r)
        }

        self.ensure_debug_info_syms()?;
        let dis_ref = self.debug_info_syms.borrow();
        let debug_info_syms = dis_ref.as_ref().unwrap();
        let mut idx =
            match debug_info_syms.binary_search_by_key(&name.to_string(), |v| v.name.to_string()) {
                Ok(idx) => idx,
                _ => return Ok(vec![]),
            };
        while idx > 0 && debug_info_syms[idx].name.eq(name) {
            idx -= 1;
        }
        if !debug_info_syms[idx].name.eq(name) {
            idx += 1;
        }
        let mut found = vec![];
        while debug_info_syms[idx].name.eq(name) {
            let DWSymInfo {
                address,
                size,
                sym_type,
                ..
            } = debug_info_syms[idx];
            found.push(SymbolInfo {
                name: name.to_string(),
                address: address as Addr,
                size,
                sym_type,
                file_offset: 0,
                obj_file_name: None,
            });
            idx += 1;
        }
        Ok(found)
    }

    /// Find the address of symbols matching a pattern from DWARF.
    ///
    /// #Arguments
    ///
    /// * `pattern` - is a regex pattern to match symbols.
    /// * `opts` - is the context giving additional parameters.
    ///
    /// Return a list of symbols including addresses and other information.
    pub(crate) fn find_address_regex(
        &self,
        pattern: &str,
        opts: &FindAddrOpts,
    ) -> Result<Vec<SymbolInfo>, Error> {
        if let SymbolType::Variable = opts.sym_type {
            return Err(Error::new(ErrorKind::Unsupported, "Not implemented"))
        }
        let r = self.parser.find_address_regex(pattern, opts)?;
        if !r.is_empty() {
            return Ok(r)
        }

        self.ensure_debug_info_syms()?;

        let dis_ref = self.debug_info_syms.borrow();
        if dis_ref.is_none() {
            return Ok(vec![])
        }
        let debug_info_syms = dis_ref.as_ref().unwrap();
        let mut syms = vec![];
        let re = Regex::new(pattern).unwrap();
        for sym in debug_info_syms {
            if re.is_match(sym.name) {
                let DWSymInfo {
                    address,
                    size,
                    sym_type,
                    ..
                } = sym;
                syms.push(SymbolInfo {
                    name: sym.name.to_string(),
                    address: *address as Addr,
                    size: *size,
                    sym_type: *sym_type,
                    file_offset: 0,
                    obj_file_name: None,
                });
            }
        }

        Ok(syms)
    }

    #[cfg(test)]
    fn pick_address_for_test(&self) -> (Addr, &str, &str, usize) {
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

    #[test]
    fn test_dwarf_find_addr_regex() {
        let bin_name = env::args().next().unwrap();
        let dwarf = DwarfResolver::open(bin_name.as_ref(), false, true).unwrap();
        let opts = FindAddrOpts {
            offset_in_file: false,
            obj_file_name: false,
            sym_type: SymbolType::Unknown,
        };
        let syms = dwarf
            .find_address_regex("DwarfResolver.*find_address_regex.*", &opts)
            .unwrap();
        assert!(!syms.is_empty());
    }

    /// Check that we can look up a symbol in DWARF debug information.
    #[test]
    fn lookup_symbol() {
        let test_dwarf = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-dwarf.bin");
        let opts = FindAddrOpts {
            offset_in_file: false,
            obj_file_name: false,
            sym_type: SymbolType::Function,
        };
        let resolver = DwarfResolver::open(test_dwarf.as_ref(), true, true).unwrap();

        let symbols = resolver.find_address("factorial", &opts).unwrap();
        assert_eq!(symbols.len(), 1);

        // `factorial` resides at address 0x2000100.
        let symbol = symbols.first().unwrap();
        assert_eq!(symbol.address, 0x2000100);
    }

    /// Check that we fail to look up variables.
    #[test]
    fn lookup_symbol_wrong_type() {
        let test_dwarf = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-dwarf.bin");
        let opts = FindAddrOpts {
            offset_in_file: false,
            obj_file_name: false,
            sym_type: SymbolType::Variable,
        };
        let resolver = DwarfResolver::open(test_dwarf.as_ref(), true, true).unwrap();

        let err = resolver.find_address("factorial", &opts).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Unsupported);
    }
}
