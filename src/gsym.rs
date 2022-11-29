use std::fs::File;
use std::io::{Error, Read};
use std::mem;
use std::path::{Path, PathBuf};

use super::{AddressLineInfo, FindAddrOpts, SymResolver, SymbolInfo};

mod linetab;
mod parser;
mod types;

use linetab::{line_table_row_from, run_op, RunResult};
use parser::{find_address, parse_address_data, parse_line_table_header, GsymContext};
use types::InfoTypeLineTableInfo;

/// The symbol resolver for the GSYM format.
pub struct GsymResolver {
    file_name: PathBuf,
    ctx: GsymContext<'static>,
    #[allow(dead_code)]
    data: Vec<u8>,
    loaded_address: u64,
}

impl GsymResolver {
    pub fn new(file_name: PathBuf, loaded_address: u64) -> Result<GsymResolver, Error> {
        let mut fo = File::open(&file_name)?;
        let mut data = vec![];
        fo.read_to_end(&mut data)?;
        let ctx = GsymContext::parse_header(&data)?;

        Ok(GsymResolver {
            file_name,
            // SAFETY: the lifetime of ctx depends on data, which is
            // owned by the object.  So, it is safe to strip the
            // lifetime of ctx.
            ctx: unsafe { mem::transmute(ctx) },
            data,
            loaded_address,
        })
    }
}

impl SymResolver for GsymResolver {
    fn get_address_range(&self) -> (u64, u64) {
        let sz = self.ctx.num_addresses();
        if sz == 0 {
            return (0, 0);
        }

        let start = self.ctx.addr_at(0) + self.loaded_address;
        let end =
            self.ctx.addr_at(sz - 1) + self.ctx.addr_info(sz - 1).size as u64 + self.loaded_address;
        (start, end)
    }

    fn find_symbols(&self, addr: u64) -> Vec<(&str, u64)> {
        let addr = addr - self.loaded_address;
        let idx = find_address(&self.ctx, addr);
        let found = self.ctx.addr_at(idx);
        if addr < found {
            return vec![];
        }

        let info = self.ctx.addr_info(idx);
        let name = self.ctx.get_str(info.name as usize);
        vec![(name, found + self.loaded_address)]
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
    /// line number and column of the line in the source code where
    /// the address corresponds to. If it doesn't find any match it
    /// returns None.
    ///
    /// # Arguments
    ///
    /// * `addr` - A 64-bit unsigned integer representing the address to find the source code location for.
    ///
    /// # Returns
    ///
    /// `Some(AddressLineInfo)` if the location is found, otherwise `None`.
    ///
    fn find_line_info(&self, addr: u64) -> Option<AddressLineInfo> {
        let addr = addr - self.loaded_address;
        let idx = find_address(&self.ctx, addr);
        let symaddr = self.ctx.addr_at(idx);
        if addr < symaddr {
            return None;
        }
        let addrinfo = self.ctx.addr_info(idx);
        if addr >= (symaddr + addrinfo.size as u64) {
            return None;
        }

        let addrdatas = parse_address_data(addrinfo.data);
        for adr_ent in addrdatas {
            if adr_ent.typ != InfoTypeLineTableInfo {
                continue;
            }
            // Continue to execute all GSYM line table operations
            // until the end of the buffer is reached or a row
            // containing addr is located.
            let (lntab_hdr, hdr_bytes) = parse_line_table_header(adr_ent.data).ok()?;
            let ops = &adr_ent.data[hdr_bytes..];
            let mut lntab_row = line_table_row_from(&lntab_hdr, symaddr);
            let mut last_lntab_row = lntab_row.clone();
            let mut row_cnt = 0;
            let mut pc = 0;
            while pc < ops.len() {
                match run_op(&mut lntab_row, &lntab_hdr, ops, pc) {
                    RunResult::Ok(bytes) => {
                        pc += bytes;
                    }
                    RunResult::NewRow(bytes) => {
                        pc += bytes;
                        row_cnt += 1;
                        if addr < lntab_row.address {
                            if row_cnt == 1 {
                                // The address is lower than the first row.
                                return None;
                            }
                            // Rollback to the last row.
                            lntab_row = last_lntab_row;
                            break;
                        }
                        last_lntab_row = lntab_row.clone();
                    }
                    RunResult::End | RunResult::Err => {
                        break;
                    }
                }
            }

            if row_cnt == 0 {
                continue;
            }

            let finfo = self.ctx.file_info(lntab_row.file_idx as usize);
            let dirname = self.ctx.get_str(finfo.directory as usize);
            let filename = self.ctx.get_str(finfo.filename as usize);
            let path = Path::new(dirname)
                .join(filename)
                .to_str()
                .unwrap()
                .to_string();
            return Some(AddressLineInfo {
                path,
                line_no: lntab_row.file_line as usize,
                column: 0,
            });
        }
        None
    }

    fn addr_file_off(&self, _addr: u64) -> Option<u64> {
        // Unavailable
        None
    }

    fn get_obj_file_name(&self) -> &Path {
        &self.file_name
    }

    fn repr(&self) -> String {
        format!("GSYM {:?}", self.file_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_find_line_info() {
        let args: Vec<String> = env::args().collect();
        let bin_name = &args[0];
        let test_gsym = Path::new(bin_name)
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("data")
            .join("test.gsym");
        let resolver = GsymResolver::new(test_gsym, 0).unwrap();

        let linfo = resolver.find_line_info(0x0000000002000001);
        assert!(linfo.is_some());
        let linfo = linfo.unwrap();
        assert_eq!(linfo.line_no, 49);
        assert!(linfo.path.ends_with("gsym-example.c"));
    }
}
