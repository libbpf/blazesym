use std::borrow::Cow;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::path::Path;
use std::path::PathBuf;

use crate::inspect::FindAddrOpts;
use crate::inspect::Inspect;
use crate::inspect::SymInfo;
use crate::once::OnceCell;
use crate::symbolize::FindSymOpts;
use crate::symbolize::Reason;
use crate::symbolize::ResolvedSym;
use crate::symbolize::SrcLang;
use crate::symbolize::Symbolize;
use crate::util::find_match_or_lower_bound_by_key;
use crate::Addr;
use crate::Result;
use crate::SymType;

pub const KALLSYMS: &str = "/proc/kallsyms";
const DFL_KSYM_CAP: usize = 200000;

#[derive(Debug)]
pub struct Ksym {
    pub addr: Addr,
    pub name: String,
}

impl<'ksym> From<&'ksym Ksym> for ResolvedSym<'ksym> {
    fn from(other: &'ksym Ksym) -> Self {
        let Ksym { name, addr } = other;
        ResolvedSym {
            name,
            addr: *addr,
            // There is no size information in kallsyms.
            size: None,
            // Kernel symbols don't carry any source code language
            // information.
            lang: SrcLang::Unknown,
            // kallsyms doesn't have source code location information.
            code_info: None,
            inlined: Box::new([]),
        }
    }
}

impl<'ksym> From<&'ksym Ksym> for SymInfo<'ksym> {
    fn from(other: &'ksym Ksym) -> Self {
        let Ksym { name, addr } = other;
        SymInfo {
            name: Cow::Borrowed(name),
            addr: *addr,
            size: 0,
            sym_type: SymType::Function,
            file_offset: None,
            obj_file_name: None,
        }
    }
}


/// The symbol resolver for /proc/kallsyms.
///
/// The users should provide the path of kallsyms, so you can provide
/// a copy from other devices.
pub struct KSymResolver {
    /// An index over `syms` that is sorted by name.
    by_name_idx: OnceCell<Box<[usize]>>,
    syms: Vec<Ksym>,
    file_name: PathBuf,
}

impl KSymResolver {
    pub fn load_file_name(filename: PathBuf) -> Result<Self> {
        let f = File::open(&filename)?;
        let mut reader = BufReader::new(f);
        let mut line = String::new();
        let mut syms = Vec::with_capacity(DFL_KSYM_CAP);

        loop {
            let sz = reader.read_line(&mut line)?;
            if sz == 0 {
                break
            }
            let tokens = line.split_whitespace().collect::<Vec<_>>();
            if tokens.len() < 3 {
                break
            }
            let (addr, _symbol, func) = (tokens[0], tokens[1], tokens[2]);
            if let Ok(addr) = Addr::from_str_radix(addr, 16) {
                if addr == 0 {
                    line.truncate(0);
                    continue
                }
                let name = String::from(func);
                syms.push(Ksym { addr, name });
            }

            line.truncate(0);
        }

        syms.sort_by(|a, b| a.addr.cmp(&b.addr));

        let slf = Self {
            syms,
            by_name_idx: OnceCell::new(),
            file_name: filename,
        };
        Ok(slf)
    }

    fn find_ksym(&self, addr: Addr) -> Result<&Ksym, Reason> {
        let result = find_match_or_lower_bound_by_key(&self.syms, addr, |ksym: &Ksym| ksym.addr)
            .and_then(|idx| self.syms.get(idx));
        match result {
            Some(sym) => Ok(sym),
            None => {
                if self.syms.is_empty() {
                    Err(Reason::MissingSyms)
                } else {
                    Err(Reason::UnknownAddr)
                }
            }
        }
    }

    fn create_by_name_idx(syms: &[Ksym]) -> Vec<usize> {
        let mut by_name_idx = (0..syms.len()).collect::<Vec<_>>();
        let () = by_name_idx.sort_by(|idx1, idx2| {
            let sym1 = &syms[*idx1];
            let sym2 = &syms[*idx2];
            sym1.name
                .cmp(&sym2.name)
                .then_with(|| sym1.addr.cmp(&sym2.addr))
        });

        by_name_idx
    }

    /// Retrieve the path to the kallsyms file used by this resolver.
    pub(crate) fn file_name(&self) -> &Path {
        &self.file_name
    }
}

impl Symbolize for KSymResolver {
    fn find_sym(&self, addr: Addr, _opts: &FindSymOpts) -> Result<Result<ResolvedSym<'_>, Reason>> {
        let sym = self.find_ksym(addr).map(ResolvedSym::from);
        Ok(sym)
    }
}

impl Inspect for KSymResolver {
    fn find_addr<'slf>(&'slf self, name: &str, opts: &FindAddrOpts) -> Result<Vec<SymInfo<'slf>>> {
        if let SymType::Variable = opts.sym_type {
            return Ok(Vec::new())
        }

        let by_name_idx = self.by_name_idx.get_or_init(|| {
            let by_name_idx = Self::create_by_name_idx(&self.syms);
            let by_name_idx = by_name_idx.into_boxed_slice();
            by_name_idx
        });

        let result =
            find_match_or_lower_bound_by_key(by_name_idx, name, |idx| &self.syms[*idx].name);
        let syms = if let Some(idx) = result {
            by_name_idx[idx..]
                .iter()
                .map(|idx| SymInfo::from(&self.syms[*idx]))
                .collect()
        } else {
            Vec::new()
        };
        Ok(syms)
    }

    fn for_each(&self, opts: &FindAddrOpts, f: &mut dyn FnMut(&SymInfo<'_>)) -> Result<()> {
        if let SymType::Variable = opts.sym_type {
            return Ok(())
        }

        for ksym in &self.syms {
            let sym = SymInfo::from(ksym);
            let () = f(&sym);
        }
        Ok(())
    }
}

impl Debug for KSymResolver {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "KSymResolver")
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use test_log::test;

    use crate::ErrorKind;


    /// Exercise the `Debug` representation of various types.
    #[test]
    fn debug_repr() {
        let resolver = KSymResolver {
            syms: Vec::new(),
            by_name_idx: OnceCell::new(),
            file_name: PathBuf::new(),
        };
        assert_ne!(format!("{resolver:?}"), "");

        let ksym = Ksym {
            addr: 0x1337,
            name: "3l33t".to_string(),
        };
        assert_ne!(format!("{ksym:?}"), "");
    }

    /// Check that we can use a `KSymResolver` to find symbols.
    #[test]
    fn ksym_resolver_load_find() {
        let result = KSymResolver::load_file_name(PathBuf::from(KALLSYMS));
        let resolver = match result {
            Ok(resolver) => resolver,
            Err(err) if err.kind() == ErrorKind::NotFound => return,
            Err(err) => panic!("failed to instantiate KSymResolver: {err}"),
        };

        assert!(
            resolver.syms.len() > 10000,
            "kallsyms seems to be unavailable or with all 0 addresses. (Check {KALLSYMS})"
        );

        let ensure_addr_for_name = |name, addr| {
            let opts = FindAddrOpts {
                offset_in_file: false,
                sym_type: SymType::Function,
            };
            let found = resolver.find_addr(name, &opts).unwrap();
            assert!(
                found.iter().any(|x| x.addr == addr),
                "{addr:#x} {found:#x?}"
            );
        };


        // Find the address of the symbol placed at the middle
        let sym = &resolver.syms[resolver.syms.len() / 2];
        let addr = sym.addr;
        let found = resolver
            .find_sym(addr, &FindSymOpts::Basic)
            .unwrap()
            .unwrap();
        ensure_addr_for_name(found.name, addr);

        // 0 is an invalid address.  We remove all symbols with 0 as
        // their address from the list.
        assert!(resolver.find_sym(0, &FindSymOpts::Basic).unwrap().is_err());

        // Find the address of the last symbol
        let sym = &resolver.syms.last().unwrap();
        let addr = sym.addr;
        let found = resolver
            .find_sym(addr, &FindSymOpts::Basic)
            .unwrap()
            .unwrap();
        ensure_addr_for_name(found.name, addr);

        let found = resolver
            .find_sym(addr + 1, &FindSymOpts::Basic)
            .unwrap()
            .unwrap();
        // Should still find the previous symbol, which is the last one.
        ensure_addr_for_name(found.name, addr);
    }

    #[test]
    fn find_ksym() {
        let resolver = KSymResolver {
            syms: vec![
                Ksym {
                    addr: 0x123,
                    name: "1".to_string(),
                },
                Ksym {
                    addr: 0x123,
                    name: "1.5".to_string(),
                },
                Ksym {
                    addr: 0x1234,
                    name: "2".to_string(),
                },
                Ksym {
                    addr: 0x12345,
                    name: "3".to_string(),
                },
            ],
            by_name_idx: OnceCell::new(),
            file_name: PathBuf::new(),
        };

        // The address is less than the smallest address of all symbols.
        assert!(resolver.find_ksym(1).is_err());

        // The address match symbols exactly (the first address.)
        let sym = resolver.find_ksym(0x123).unwrap();
        assert_eq!(sym.addr, 0x123);
        assert_eq!(sym.name, "1");

        // The address is in between two symbols (the first address.)
        let sym = resolver.find_ksym(0x124).unwrap();
        assert_eq!(sym.addr, 0x123);
        assert_eq!(sym.name, "1.5");

        // The address match symbols exactly.
        let sym = resolver.find_ksym(0x1234).unwrap();
        assert_eq!(sym.addr, 0x1234);
        assert_eq!(sym.name, "2");

        // The address is in between two symbols.
        let sym = resolver.find_ksym(0x1235).unwrap();
        assert_eq!(sym.addr, 0x1234);
        assert_eq!(sym.name, "2");

        // The address match symbols exactly (the biggest address.)
        let sym = resolver.find_ksym(0x12345).unwrap();
        assert_eq!(sym.addr, 0x12345);
        assert_eq!(sym.name, "3");

        // The address is bigger than the biggest address of all symbols.
        let sym = resolver.find_ksym(0x1234568).unwrap();
        assert_eq!(sym.addr, 0x12345);
        assert_eq!(sym.name, "3");
    }

    /// Check that we can correctly iterate over all symbols.
    #[test]
    fn symbol_iteration() {
        let resolver = KSymResolver {
            syms: vec![
                Ksym {
                    addr: 0x123,
                    name: "j".to_string(),
                },
                Ksym {
                    addr: 0x123,
                    name: "b".to_string(),
                },
                Ksym {
                    addr: 0x1234,
                    name: "a".to_string(),
                },
                Ksym {
                    addr: 0x12345,
                    name: "z".to_string(),
                },
            ],
            by_name_idx: OnceCell::new(),
            file_name: PathBuf::new(),
        };

        let opts = FindAddrOpts::default();
        let mut syms = Vec::with_capacity(resolver.syms.len());
        let () = resolver
            .for_each(&opts, &mut |sym| syms.push(sym.name.to_string()))
            .unwrap();
        let () = syms.sort();
        assert_eq!(syms, vec!["a", "b", "j", "z"]);
    }

    /// Check that [`KSymResolver::find_addr`] and
    /// [`KSymResolver::for_each`] behave as expected for variable
    /// inquiries.
    #[test]
    fn variable_operations() {
        let resolver = KSymResolver {
            syms: vec![
                Ksym {
                    addr: 0x123,
                    name: "j".to_string(),
                },
                Ksym {
                    addr: 0x123,
                    name: "b".to_string(),
                },
                Ksym {
                    addr: 0x1234,
                    name: "a".to_string(),
                },
                Ksym {
                    addr: 0x12345,
                    name: "z".to_string(),
                },
            ],
            by_name_idx: OnceCell::new(),
            file_name: PathBuf::new(),
        };

        let opts = FindAddrOpts {
            sym_type: SymType::Variable,
            ..Default::default()
        };
        let result = resolver.find_addr("a", &opts).unwrap();
        assert_eq!(result, Vec::new());

        let () = resolver
            .for_each(&opts, &mut |_sym| unreachable!())
            .unwrap();
    }
}
