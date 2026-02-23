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
