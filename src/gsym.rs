use std::fs::File;
use std::io::{Error, Read};
use std::mem;
use std::path::PathBuf;

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

    fn find_symbol(&self, addr: u64) -> Option<(&str, u64)> {
        let addr = addr - self.loaded_address;
        let idx = find_address(&self.ctx, addr);
        let found = self.ctx.addr_at(idx);
        if addr < found {
            return None;
        }

        let info = self.ctx.addr_info(idx);
        let name = self.ctx.get_str(info.name as usize);
        Some((name, found + self.loaded_address))
    }

    fn find_address(&self, _name: &str, _opts: &FindAddrOpts) -> Option<Vec<SymbolInfo>> {
        // It is inefficient to find the address of a symbol with
        // GSYM.  We may support it in the future if needed.
        None
    }

    fn find_address_regex(&self, _pattern: &str, _opts: &FindAddrOpts) -> Option<Vec<SymbolInfo>> {
        None
    }

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
        for addrdata in addrdatas {
            if addrdata.typ != InfoTypeLineTableInfo {
                continue;
            }
            let lthdr = parse_line_table_header(addrdata.data);
            if lthdr.is_err() {
                #[cfg(debug_assertions)]
                eprintln!("invalid line table header");
                return None;
            }
            let (lthdr, bytes) = lthdr.unwrap();
            let ops = &addrdata.data[bytes..];
            let mut ltr = line_table_row_from(&lthdr, symaddr);
            let mut saved_ltr = ltr.clone();
            let mut row_cnt = 0;
            let mut pc = 0;
            while pc < ops.len() {
                match run_op(&mut ltr, &lthdr, ops, pc) {
                    RunResult::Ok(bytes) => {
                        pc += bytes as usize;
                    }
                    RunResult::NewRow(bytes) => {
                        pc += bytes as usize;
                        row_cnt += 1;
                        if addr < ltr.address {
                            if row_cnt == 1 {
                                return None;
                            }
                            ltr = saved_ltr.clone();
                            break;
                        }
                        saved_ltr = ltr.clone();
                    }
                    RunResult::End | RunResult::Err => {
                        break;
                    }
                }
            }

            if row_cnt == 0 {
                continue;
            }

            let finfo = self.ctx.file_info(ltr.file_idx as usize);
            let dirname = self.ctx.get_str(finfo.directory as usize);
            let filename = self.ctx.get_str(finfo.filename as usize);
            let path = format!("{}/{}", dirname, filename);
            return Some(AddressLineInfo {
                path,
                line_no: ltr.file_line as usize,
                column: 0,
            });
        }
        None
    }

    fn addr_file_off(&self, _addr: u64) -> Option<u64> {
        // Unavailable
        None
    }

    fn get_obj_file_name(&self) -> String {
        self.file_name.to_str().unwrap().to_string()
    }

    fn repr(&self) -> String {
        format!("GSYM {:?}", self.file_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::path::Path;

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
        let resolver = GsymResolver::new(test_gsym.to_path_buf(), 0).unwrap();

        let linfo = resolver.find_line_info(0x29bdaa);
        assert!(linfo.is_some());
        let linfo = linfo.unwrap();
        assert!(linfo.path.ends_with("set_len_on_drop.rs"));
        assert_eq!(linfo.line_no, 26);
    }

    #[test]
    fn test_find_symbol() {
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
        let resolver = GsymResolver::new(test_gsym.to_path_buf(), 0).unwrap();

        let (name, addr) = resolver.find_symbol(0x29bdaa).unwrap();
        assert!(name.starts_with("_ZN83_$LT$alloc..vec..set_len_on_drop..SetLenOnDrop$u20$as$u20$core..ops..drop..Drop$GT$4drop"));
        assert_eq!(addr, 0x29bda0);
    }
}
