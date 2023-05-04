use std::io::Result;

use crate::dwarf::DwarfResolver;
use crate::elf::ElfResolver;
use crate::SymResolver;

use super::source::Elf;
use super::source::Source;
use super::FindAddrOpts;
use super::SymInfo;
use super::SymType;


/// An inspector of various "sources".
///
/// Object of this type can be used to perform inspections of supported sources.
/// E.g., using an ELF file as a source, information about a symbol can be
/// inquired based on its name.
#[derive(Debug, Default)]
pub struct Inspector {
    _private: (),
}

impl Inspector {
    /// Create a new `Inspector`.
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Look up information (address etc.) about a list of symbols,
    /// given their names.
    pub fn lookup(&self, names: &[&str], src: &Source) -> Result<Vec<Vec<SymInfo>>> {
        let opts = FindAddrOpts {
            offset_in_file: true,
            obj_file_name: true,
            sym_type: SymType::Unknown,
        };

        match src {
            Source::Elf(Elf {
                path,
                debug_info,
                _non_exhaustive: (),
            }) => {
                let symbols = if *debug_info {
                    let debug_line_info = true;
                    let debug_info_symbols = true;
                    let resolver = DwarfResolver::open(path, debug_line_info, debug_info_symbols)?;

                    names
                        .iter()
                        .map(|name| resolver.find_addr(name, &opts).ok().unwrap_or_default())
                        .collect()
                } else {
                    let resolver = ElfResolver::new(path)?;
                    names
                        .iter()
                        .map(|name| resolver.find_addr(name, &opts).unwrap_or_default())
                        .collect()
                };

                Ok(symbols)
            }
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::io::ErrorKind;
    use std::path::Path;


    /// Check that we error our as expected when encountering a source
    /// that is not present.
    #[test]
    fn non_present_file() {
        fn test(src: &Source) {
            let inspector = Inspector::new();
            let err = inspector.lookup(&["factorial"], src).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::NotFound);
        }

        let file = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("does-not-exist");
        let src = Source::Elf(Elf::new(&file));
        let () = test(&src);

        let mut elf = Elf::new(file);
        elf.debug_info = !elf.debug_info;
        let src = Source::Elf(elf);
        let () = test(&src);
    }
}
