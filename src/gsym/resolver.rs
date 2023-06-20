use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::io::Error;
use std::io::ErrorKind;
use std::mem;
use std::path::Path;
use std::path::PathBuf;

use crate::inspect::FindAddrOpts;
use crate::inspect::SymInfo;
use crate::mmap::Mmap;
use crate::symbolize::AddrLineInfo;
use crate::Addr;
use crate::SymResolver;

use super::linetab::run_op;
use super::linetab::LineTableRow;
use super::linetab::RunResult;
use super::parser::parse_address_data;
use super::parser::parse_line_table_header;
use super::parser::GsymContext;
use super::types::InfoTypeLineTableInfo;


enum Data<'dat> {
    Mmap(Mmap),
    Slice(&'dat [u8]),
}

/// The symbol resolver for the GSYM format.
pub struct GsymResolver<'dat> {
    file_name: Option<PathBuf>,
    // SAFETY: This member should be listed before `ctx` to make sure we never
    //         end up with dangling references.
    _data: Data<'dat>,
    ctx: GsymContext<'dat>,
}

impl GsymResolver<'static> {
    /// Create a `GsymResolver` that load data from the provided file.
    pub fn new(file_name: PathBuf) -> Result<Self, Error> {
        let mmap = Mmap::builder().open(&file_name)?;
        let ctx = GsymContext::parse_header(&mmap)?;
        let slf = Self {
            file_name: Some(file_name),
            // SAFETY: We own the underlying `Mmap` object and never hand out
            //         any 'static references to its data. So it is safe for us
            //         to transmute the lifetime.
            ctx: unsafe { mem::transmute(ctx) },
            _data: Data::Mmap(mmap),
        };

        Ok(slf)
    }
}

impl<'dat> GsymResolver<'dat> {
    /// Create a `GsymResolver` that works on the provided "raw" Gsym data.
    #[cfg(test)]
    pub(crate) fn with_data(data: &'dat [u8]) -> Result<Self, Error> {
        let ctx = GsymContext::parse_header(data)?;
        let slf = Self {
            file_name: None,
            ctx,
            _data: Data::Slice(data),
        };

        Ok(slf)
    }
}

impl SymResolver for GsymResolver<'_> {
    fn find_syms(&self, addr: Addr) -> Result<Vec<(&str, Addr)>, Error> {
        if let Some(idx) = self.ctx.find_addr(addr) {
            let found = self.ctx.addr_at(idx).ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidData,
                    format!("failed to read address table entry {idx}"),
                )
            })?;
            if addr < found {
                return Ok(Vec::new())
            }

            let info = self.ctx.addr_info(idx).ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidData,
                    format!("failed to read address information entry {idx}"),
                )
            })?;
            let name = self.ctx.get_str(info.name as usize).ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidData,
                    format!("failed to read string table entry at offset {}", info.name),
                )
            })?;

            Ok(vec![(name, found)])
        } else {
            Ok(Vec::new())
        }
    }

    fn find_addr(&self, _name: &str, _opts: &FindAddrOpts) -> Result<Vec<SymInfo>, Error> {
        // It is inefficient to find the address of a symbol with
        // GSYM.  We may support it in the future if needed.
        Ok(Vec::new())
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
    /// The `AddrLineInfo` corresponding to the address or `None`.
    #[cfg_attr(feature = "tracing", crate::log::instrument(skip(self), fields(file = debug(&self.file_name))))]
    fn find_line_info(&self, addr: Addr) -> Result<Option<AddrLineInfo>, Error> {
        fn find_line_info_impl(ctx: &GsymContext<'_>, addr: Addr) -> Option<AddrLineInfo> {
            let idx = ctx.find_addr(addr)?;
            let symaddr = ctx.addr_at(idx)?;
            if addr < symaddr {
                return None
            }
            let addrinfo = ctx.addr_info(idx)?;
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

                let finfo = ctx.file_info(lntab_row.file_idx as usize)?;
                let dirname = ctx.get_str(finfo.directory as usize)?;
                let filename = ctx.get_str(finfo.filename as usize)?;
                let path = Path::new(dirname).join(filename);
                return Some(AddrLineInfo {
                    path,
                    line: lntab_row.file_line as usize,
                    column: 0,
                })
            }
            None
        }

        let addr_info = find_line_info_impl(&self.ctx, addr);
        Ok(addr_info)
    }

    fn addr_file_off(&self, _addr: Addr) -> Option<u64> {
        // Unavailable
        None
    }
}

impl Debug for GsymResolver<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let path = self
            .file_name
            .as_deref()
            .unwrap_or_else(|| Path::new("<unknown-file>"));
        write!(f, "GSYM {}", path.display())
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::env;
    use std::fs::read as read_file;

    use test_log::test;


    /// Check that we can create a `GsymResolver` using a "raw" slice of data.
    #[test]
    fn creation_from_raw_data() {
        let test_gsym = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-stable-addresses.gsym");
        let data = read_file(test_gsym).unwrap();

        let resolver = GsymResolver::with_data(&data).unwrap();
        assert_eq!(resolver.file_name, None);
    }

    /// Make sure that we can find file line information for a function, if available.
    #[test]
    fn find_line_info() {
        let test_gsym = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-stable-addresses.gsym");
        let resolver = GsymResolver::new(test_gsym).unwrap();

        // `main` resides at address 0x2000000, and it's located at the given
        // line.
        let info = resolver.find_line_info(0x2000000).unwrap().unwrap();
        assert_eq!(info.line, 34);
        assert!(info.path.ends_with("test-stable-addresses.c"));

        // `factorial` resides at address 0x2000100, and it's located at the
        // given line.
        let info = resolver.find_line_info(0x2000100).unwrap().unwrap();
        assert_eq!(info.line, 8);
        assert!(info.path.ends_with("test-stable-addresses.c"));
    }
}
