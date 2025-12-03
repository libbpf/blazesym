use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Read;
use std::path::Path;
use std::str::FromStr as _;

use crate::symbolize::Reason;
use crate::util::find_match_or_lower_bound_by_key;
use crate::Addr;
use crate::Result;


/// A single kernel module with a name, base address, and size.
#[derive(Debug)]
struct Mod {
    name: Box<str>,
    addr: Addr,
    size: u64,
}

impl Mod {
    #[inline]
    fn addr(&self) -> Addr {
        self.addr
    }
}


/// A map for efficient lookup of modules based on address.
#[derive(Debug)]
pub struct ModMap {
    modules: Vec<Mod>, // Sorted by start address
}

impl ModMap {
    /// Parse a `/proc/modules`-style file from the given path.
    pub fn new(path: &Path) -> Result<Self> {
        let file = File::open(path)?;
        Self::from_reader(file)
    }

    fn from_reader<R>(reader: R) -> Result<Self>
    where
        R: Read,
    {
        let mut reader = BufReader::new(reader);
        let mut line = String::new();
        let mut modules = Vec::new();

        loop {
            let () = line.clear();
            let size = reader.read_line(&mut line)?;
            if size == 0 {
                break
            }

            // Each line has format:
            // <module_name> <size> <instances> <dependencies> <state> <address> (<flags>)
            let mut parts = line.split_ascii_whitespace();
            #[rustfmt::skip]
            let (name, addr, size) = {
              let name = if let Some(part) = parts.next() { part } else { continue };
              let size = if let Some(part) = parts.next() { part } else { continue };
              let _insts = if let Some(part) = parts.next() { part } else { continue };
              let _deps = if let Some(part) = parts.next() { part } else { continue };
              let _state = if let Some(part) = parts.next() { part } else { continue };
              let addr = if let Some(part) = parts.next() { part } else { continue };
              (name, addr, size)
            };

            let addr = if let Ok(addr) = Addr::from_str_radix(addr.trim_start_matches("0x"), 16) {
                // A start address of 0 means that the address was
                // masked -- it is not usable for our purposes.
                if addr == 0 {
                    continue
                }
                addr
            } else {
                continue
            };

            let size = if let Ok(size) = u64::from_str(size) {
                size
            } else {
                continue
            };

            let () = modules.push(Mod {
                name: name.into(),
                addr,
                size,
            });
        }

        let () = modules.sort_unstable_by_key(|m| m.addr);

        Ok(Self { modules })
    }

    /// Look up the module belonging to the provided address.
    pub fn find_module(&self, addr: u64) -> Result<(&str, Addr), Reason> {
        let result =
            find_match_or_lower_bound_by_key(&self.modules, addr, Mod::addr).and_then(|idx| {
                self.modules
                    .get(idx)
                    .and_then(|m| (m.addr..m.addr + m.size).contains(&addr).then_some(m))
            });
        match result {
            Some(module) => Ok((&module.name, module.addr)),
            None => {
                if self.modules.is_empty() {
                    Err(Reason::MissingSyms)
                } else {
                    Err(Reason::UnknownAddr)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::kernel::MODULES;


    /// Check that we can find modules based on their address.
    #[test]
    fn module_finding() {
        let modules = br"\
intel_lpss_pci 24576 0 - Live 0xffffffffa012c000
intel_lpss 12288 1 intel_lpss_pci, Live 0xffffffffa0121000
cfg80211 782336 3 iwlmvm,mac80211,iwlwifi, Live 0xffffffffa0012000
mfd_core 12288 1 intel_lpss, Live 0xffffffffa000a000
intel_pch_thermal 12288 0 - Live 0xffffffffa0000000
autofs4 53248 8 - Live 0xffffffffa0201000 (E)
";

        let map = ModMap::from_reader(&mut modules.as_slice()).unwrap();
        assert_eq!(
            map.find_module(0xffffffffa012c000).unwrap(),
            ("intel_lpss_pci", 0xffffffffa012c000)
        );
        assert_eq!(
            map.find_module(0xffffffffa012c000 + 24575).unwrap(),
            ("intel_lpss_pci", 0xffffffffa012c000)
        );
        assert_eq!(
            map.find_module(0xffffffffa012c000 + 24576),
            Err(Reason::UnknownAddr)
        );
        assert_eq!(
            map.find_module(0xffffffffa000a200).unwrap(),
            ("mfd_core", 0xffffffffa000a000)
        );
        assert_eq!(
            map.find_module(0xffffffffa0201200).unwrap(),
            ("autofs4", 0xffffffffa0201000)
        );
        assert_eq!(
            map.find_module(0xffffffffffffffff),
            Err(Reason::UnknownAddr)
        );
    }

    /// Make sure that we report the appropriate reason if all modules
    /// have an address of 0.
    #[test]
    fn no_mods_present() {
        let modules = br"\
cfg80211 782336 3 iwlmvm,mac80211,iwlwifi, Live 0x0000000000000000
mfd_core 12288 1 intel_lpss, Live 0x0000000000000000
intel_pch_thermal 12288 0 - Live 0x0000000000000000
";
        let map = ModMap::from_reader(&mut modules.as_slice()).unwrap();
        let reason = map.find_module(0x0).unwrap_err();
        assert_eq!(reason, Reason::MissingSyms);
        let reason = map.find_module(0x1337).unwrap_err();
        assert_eq!(reason, Reason::MissingSyms);
    }

    /// Check that we can load the system's `/proc/modules` file.
    #[test]
    fn load_system_modules() {
        let _map = ModMap::new(Path::new(MODULES)).unwrap();
    }
}
