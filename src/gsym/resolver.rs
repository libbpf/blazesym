use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::fs::File;
use std::io::Error;
use std::io::ErrorKind;
use std::io::Read as _;
use std::mem;
use std::path::Path;
use std::path::PathBuf;

use crate::Addr;
use crate::AddressLineInfo;
use crate::FindAddrOpts;
use crate::SymResolver;
use crate::SymbolInfo;

use super::linetab::run_op;
use super::linetab::LineTableRow;
use super::linetab::RunResult;
use super::parser::parse_address_data;
use super::parser::parse_line_table_header;
use super::parser::GsymContext;
use super::types::InfoTypeLineTableInfo;

/// The symbol resolver for the GSYM format.
pub struct GsymResolver {
    file_name: PathBuf,
    ctx: GsymContext<'static>,
    _data: Vec<u8>,
    loaded_address: Addr,
    range: (Addr, Addr),
}

impl GsymResolver {
    pub fn new(file_name: PathBuf, loaded_address: Addr) -> Result<GsymResolver, Error> {
        let mut fo = File::open(&file_name)?;
        let mut data = vec![];
        fo.read_to_end(&mut data)?;
        let ctx = GsymContext::parse_header(&data)?;
        let range = ctx.address_range().ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidData,
                "failed to determine gsym resolver address range",
            )
        })?;

        Ok(GsymResolver {
            file_name,
            // SAFETY: the lifetime of ctx depends on data, which is
            // owned by the object.  So, it is safe to strip the
            // lifetime of ctx.
            ctx: unsafe { mem::transmute(ctx) },
            _data: data,
            loaded_address,
            range,
        })
    }
}

impl SymResolver for GsymResolver {
    fn get_address_range(&self) -> (Addr, Addr) {
        (
            self.loaded_address + self.range.0,
            self.loaded_address + self.range.1,
        )
    }

    fn find_symbols(&self, addr: Addr) -> Vec<(&str, Addr)> {
        fn find_address_impl(gsym: &GsymResolver, addr: Addr) -> Option<Vec<(&str, Addr)>> {
            let addr = addr.checked_sub(gsym.loaded_address)?;
            let idx = gsym.ctx.find_address(addr)?;

            let found = gsym.ctx.addr_at(idx)?;
            if addr < found {
                return None
            }

            let info = gsym.ctx.addr_info(idx)?;
            let name = gsym.ctx.get_str(info.name as usize)?;

            Some(vec![(name, found + gsym.loaded_address)])
        }

        find_address_impl(self, addr).unwrap_or_default()
    }

    fn find_address(&self, _name: &str, _opts: &FindAddrOpts) -> Option<Vec<SymbolInfo>> {
        // It is inefficient to find the address of a symbol with
        // GSYM.  We may support it in the future if needed.
        None
    }

    fn find_address_regex(&self, _pattern: &str, _opts: &FindAddrOpts) -> Option<Vec<SymbolInfo>> {
        None
    }

    /// Finds the source code location for a given address.
    ///
    /// This function takes in an address and returns the file path,
    /// line number and column of the line in the source code that
    /// the address corresponds to. If it doesn't find any match it
    /// returns `None`.
    ///
    /// # Arguments
    ///
    /// * `addr` - The address to find the source code location for.
    ///
    /// # Returns
    ///
    /// The `AddressLineInfo` corresponding to the address or `None`.
    fn find_line_info(&self, addr: Addr) -> Option<AddressLineInfo> {
        let addr = addr.checked_sub(self.loaded_address)?;
        let idx = self.ctx.find_address(addr)?;
        let symaddr = self.ctx.addr_at(idx)?;
        if addr < symaddr {
            return None
        }
        let addrinfo = self.ctx.addr_info(idx)?;
        if addr >= (symaddr + addrinfo.size as Addr) {
            return None
        }

        let addrdatas = parse_address_data(addrinfo.data)?;
        for adr_ent in addrdatas {
            if adr_ent.typ != InfoTypeLineTableInfo {
                continue
            }
            // Continue to execute all GSYM line table operations
            // until the end of the buffer is reached or a row
            // containing addr is located.
            let mut data = adr_ent.data;
            let lntab_hdr = parse_line_table_header(&mut data)?;
            let mut lntab_row = LineTableRow::line_table_row_from(&lntab_hdr, symaddr);
            let mut last_lntab_row = lntab_row.clone();
            let mut row_cnt = 0;
            while !data.is_empty() {
                match run_op(&mut lntab_row, &lntab_hdr, &mut data) {
                    Some(RunResult::Ok) => {}
                    Some(RunResult::NewRow) => {
                        row_cnt += 1;
                        if addr < lntab_row.address {
                            if row_cnt == 1 {
                                // The address is lower than the first row.
                                return None
                            }
                            // Rollback to the last row.
                            lntab_row = last_lntab_row;
                            break
                        }
                        last_lntab_row = lntab_row.clone();
                    }
                    Some(RunResult::End) | None => break,
                }
            }

            if row_cnt == 0 {
                continue
            }

            let finfo = self.ctx.file_info(lntab_row.file_idx as usize)?;
            let dirname = self.ctx.get_str(finfo.directory as usize)?;
            let filename = self.ctx.get_str(finfo.filename as usize)?;
            let path = Path::new(dirname).join(filename).to_str()?.to_string();
            return Some(AddressLineInfo {
                path,
                line_no: lntab_row.file_line as usize,
                column: 0,
            })
        }
        None
    }

    fn addr_file_off(&self, _addr: Addr) -> Option<u64> {
        // Unavailable
        None
    }

    fn get_obj_file_name(&self) -> &Path {
        &self.file_name
    }
}

impl Debug for GsymResolver {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "GSYM {}", self.file_name.display())
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::env;

    use test_log::test;

    /// Make sure that we can find file line information for a function, if available.
    #[test]
    fn test_find_line_info() {
        let test_gsym = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test.gsym");
        let resolver = GsymResolver::new(test_gsym, 0).unwrap();

        // `main` resides at address 0x2000000, and it's located at line 19.
        let info = resolver.find_line_info(0x2000000).unwrap();
        assert_eq!(info.line_no, 19);
        assert!(info.path.ends_with("test-stable-addresses.c"));

        // `factorial` resides at address 0x2000100, and it's located at line 7.
        let info = resolver.find_line_info(0x2000100).unwrap();
        assert_eq!(info.line_no, 7);
        assert!(info.path.ends_with("test-stable-addresses.c"));
    }
}
