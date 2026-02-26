use std::collections::BTreeMap;
use std::collections::HashMap;


/// A single pre-resolved relocation entry.
#[derive(Debug, Clone, Copy)]
struct RelocationEntry {
    /// The pre-resolved addend (for `SHT_RELA`: `sym.st_value + r_addend`,
    /// for `SHT_REL`: `sym.st_value`).
    addend: u64,
    /// Whether this is an implicit-addend (`SHT_REL`) relocation.
    implicit: bool,
}


/// A map from section offsets to pre-resolved relocation addends.
///
/// For a given DWARF section, this maps byte offsets within that section
/// to the relocation that should be applied when reading at that offset.
#[derive(Debug, Clone, Default)]
pub(crate) struct RelocationMap {
    entries: BTreeMap<u64, RelocationEntry>,
}

impl RelocationMap {
    pub(super) fn insert(&mut self, offset: u64, addend: u64, implicit: bool) {
        let _prev = self
            .entries
            .insert(offset, RelocationEntry { addend, implicit });
    }

    pub(crate) fn relocate(&self, offset: u64, value: u64) -> u64 {
        if let Some(entry) = self.entries.get(&offset) {
            if entry.implicit {
                value.wrapping_add(entry.addend)
            } else {
                entry.addend
            }
        } else {
            value
        }
    }
}


/// Holds per-section relocation maps for an ELF file.
///
/// For `ET_REL` files, this contains relocation maps keyed by the target
/// section index. For non-relocatable files, this is empty.
pub(crate) struct SectionRelocations {
    /// Relocation maps keyed by target section index.
    maps: HashMap<usize, RelocationMap>,
    /// A shared empty relocation map for sections without relocations.
    empty: RelocationMap,
}

impl SectionRelocations {
    /// Create an empty `SectionRelocations` (for non-relocatable files).
    pub(crate) fn empty() -> Self {
        Self {
            maps: HashMap::new(),
            empty: RelocationMap::default(),
        }
    }

    pub(super) fn new(maps: HashMap<usize, RelocationMap>) -> Self {
        Self {
            maps,
            empty: RelocationMap::default(),
        }
    }

    /// Get the relocation map for the section at `target_idx`.
    ///
    /// Returns the empty map if no relocations exist for that section.
    pub(crate) fn get(&self, target_idx: usize) -> &RelocationMap {
        self.maps.get(&target_idx).unwrap_or(&self.empty)
    }
}


#[cfg(test)]
mod tests {
    use super::*;


    /// Exercise the `Debug` representation of relocation types.
    #[test]
    fn debug_repr() {
        let map = RelocationMap::default();
        assert_ne!(format!("{map:?}"), "");

        let entry = RelocationEntry {
            addend: 42,
            implicit: false,
        };
        assert_ne!(format!("{entry:?}"), "");
    }

    /// Test explicit (RELA) relocation.
    #[test]
    fn relocate_explicit() {
        let mut map = RelocationMap::default();
        let () = map.insert(0x100, 0xABCD, false);

        assert_eq!(map.relocate(0x100, 999), 0xABCD);
        assert_eq!(map.relocate(0x200, 999), 999);
    }

    /// Test implicit (REL) relocation.
    #[test]
    fn relocate_implicit() {
        let mut map = RelocationMap::default();
        let () = map.insert(0x100, 0x10, true);

        assert_eq!(map.relocate(0x100, 0x20), 0x30);
        assert_eq!(map.relocate(0x200, 0x20), 0x20);
    }

    /// Test wrapping behavior of implicit relocation.
    #[test]
    fn relocate_implicit_wrapping() {
        let mut map = RelocationMap::default();
        let () = map.insert(0x0, 1, true);

        assert_eq!(map.relocate(0x0, u64::MAX), 0);
    }

    /// Check that `SectionRelocations::empty()` returns identity maps
    /// for any index.
    #[test]
    fn section_relocations_empty() {
        let relocs = SectionRelocations::empty();
        assert_eq!(relocs.get(0).relocate(0x0, 42), 42);
        assert_eq!(relocs.get(99).relocate(0x0, 42), 42);
    }

    /// Make sure that `SectionRelocations::new(maps)` returns populated
    /// map for known index and empty map for unknown.
    #[test]
    fn section_relocations_with_maps() {
        let mut map = RelocationMap::default();
        let () = map.insert(0x0, 0xFF, false);

        let mut maps = HashMap::new();
        let _prev = maps.insert(3, map);

        let relocs = SectionRelocations::new(maps);
        assert_eq!(relocs.get(3).relocate(0x0, 0), 0xFF);
        assert_eq!(relocs.get(7).relocate(0x0, 42), 42);
    }
}
