// Based on gimli-rs/addr2line (https://github.com/gimli-rs/addr2line):
// > Copyright (c) 2016-2018 The gimli Developers
// >
// > Permission is hereby granted, free of charge, to any
// > person obtaining a copy of this software and associated
// > documentation files (the "Software"), to deal in the
// > Software without restriction, including without
// > limitation the rights to use, copy, modify, merge,
// > publish, distribute, sublicense, and/or sell copies of
// > the Software, and to permit persons to whom the Software
// > is furnished to do so, subject to the following
// > conditions:
// >
// > The above copyright notice and this permission notice
// > shall be included in all copies or substantial portions
// > of the Software.
// >
// > THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
// > ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
// > TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
// > PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
// > SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// > CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// > OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
// > IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// > DEALINGS IN THE SOFTWARE.

use std::ops::ControlFlow;

use crate::log::warn;
use crate::once::OnceCell;
use crate::ErrorExt as _;
use crate::Result;

use super::function::Function;
use super::lines::Lines;
use super::location::Location;
use super::range::RangeAttributes;
use super::reader::R;
use super::unit::Unit;
use super::unit::UnitRange;


fn format_offset(offset: gimli::UnitSectionOffset<usize>) -> String {
    match offset {
        gimli::UnitSectionOffset::DebugInfoOffset(o) => {
            format!(".debug_info+0x{:08x}", o.0)
        }
        gimli::UnitSectionOffset::DebugTypesOffset(o) => {
            format!(".debug_types+0x{:08x}", o.0)
        }
    }
}


pub(crate) struct Units<'dwarf> {
    /// The DWARF data.
    dwarf: gimli::Dwarf<R<'dwarf>>,
    /// The ranges of the units encountered.
    unit_ranges: Box<[UnitRange]>,
    /// All units along with meta-data.
    units: Box<[Unit<'dwarf>]>,
}

impl<'dwarf> Units<'dwarf> {
    pub(crate) fn parse(sections: gimli::Dwarf<R<'dwarf>>) -> Result<Self> {
        // Find all the references to compilation units in .debug_aranges.
        // Note that we always also iterate through all of .debug_info to
        // find compilation units, because .debug_aranges may be missing some.
        let mut aranges = Vec::new();
        let mut headers = sections.debug_aranges.headers();
        while let Some(header) = headers.next()? {
            aranges.push((header.debug_info_offset(), header.offset()));
        }
        aranges.sort_by_key(|i| i.0);

        let mut unit_ranges = Vec::new();
        let mut res_units = Vec::new();
        let mut units = sections.units();
        while let Some(header) = units.next()? {
            let unit_id = res_units.len();
            let offset = match header.offset().as_debug_info_offset() {
                Some(offset) => offset,
                None => continue,
            };
            // We mainly want compile units, but we may need to follow references to entries
            // within other units for function names.  We don't need anything from type
            // units.
            match header.type_() {
                gimli::UnitType::Type { .. } | gimli::UnitType::SplitType { .. } => continue,
                _ => {}
            }
            let dw_unit = sections.unit(header).with_context(|| {
                format!(
                    "failed to retrieve DWARF unit for unit header @ {}",
                    format_offset(header.offset())
                )
            })?;

            let mut lang = None;
            let mut have_unit_range = false;
            {
                let mut entries = dw_unit.entries_raw(None)?;

                let abbrev = match entries.read_abbreviation()? {
                    Some(abbrev) => abbrev,
                    None => continue,
                };

                let mut ranges = RangeAttributes::default();
                for spec in abbrev.attributes() {
                    let attr = entries.read_attribute(*spec)?;
                    match attr.name() {
                        gimli::DW_AT_low_pc => match attr.value() {
                            gimli::AttributeValue::Addr(val) => ranges.low_pc = Some(val),
                            gimli::AttributeValue::DebugAddrIndex(index) => {
                                ranges.low_pc = Some(sections.address(&dw_unit, index)?);
                            }
                            _ => {}
                        },
                        gimli::DW_AT_high_pc => match attr.value() {
                            gimli::AttributeValue::Addr(val) => ranges.high_pc = Some(val),
                            gimli::AttributeValue::DebugAddrIndex(index) => {
                                ranges.high_pc = Some(sections.address(&dw_unit, index)?);
                            }
                            gimli::AttributeValue::Udata(val) => ranges.size = Some(val),
                            _ => {}
                        },
                        gimli::DW_AT_ranges => {
                            ranges.ranges_offset =
                                sections.attr_ranges_offset(&dw_unit, attr.value())?;
                        }
                        gimli::DW_AT_language => {
                            if let gimli::AttributeValue::Language(val) = attr.value() {
                                lang = Some(val);
                            }
                        }
                        _ => {}
                    }
                }

                // Find the address ranges for the CU, using in order of preference:
                // - DW_AT_ranges
                // - .debug_aranges
                // - DW_AT_low_pc/DW_AT_high_pc
                //
                // Using DW_AT_ranges before .debug_aranges is possibly an arbitrary choice,
                // but the feeling is that DW_AT_ranges is more likely to be reliable or
                // complete if it is present.
                //
                // .debug_aranges must be used before DW_AT_low_pc/DW_AT_high_pc because
                // it has been observed on macOS that DW_AT_ranges was not emitted even for
                // discontiguous CUs.
                let i = match ranges.ranges_offset {
                    Some(_) => None,
                    None => aranges.binary_search_by_key(&offset, |x| x.0).ok(),
                };
                if let Some(mut i) = i {
                    // There should be only one set per CU, but in practice multiple
                    // sets have been observed. This is probably a compiler bug, but
                    // either way we need to handle it.
                    while i > 0 && aranges[i - 1].0 == offset {
                        i -= 1;
                    }
                    for (_, aranges_offset) in aranges[i..].iter().take_while(|x| x.0 == offset) {
                        let aranges_header = sections.debug_aranges.header(*aranges_offset)?;
                        let mut aranges = aranges_header.entries();
                        while let Some(arange) = aranges.next()? {
                            if arange.length() != 0 {
                                unit_ranges.push(UnitRange {
                                    range: arange.range(),
                                    unit_id,
                                    max_end: 0,
                                });
                                have_unit_range = true;
                            }
                        }
                    }
                } else {
                    let unit = gimli::UnitRef::new(&sections, &dw_unit);
                    have_unit_range |= ranges.for_each_range(unit, |range| {
                        unit_ranges.push(UnitRange {
                            range,
                            unit_id,
                            max_end: 0,
                        });
                    })?;
                }
            }

            let lines = OnceCell::new();
            if !have_unit_range {
                // The unit did not declare any ranges.
                // Try to get some ranges from the line program sequences.
                if let Some(ref ilnp) = dw_unit.line_program {
                    if let Ok(lines) = lines.get_or_try_init(|| {
                        let unit = gimli::UnitRef::new(&sections, &dw_unit);
                        Lines::parse(unit, ilnp.clone())
                    }) {
                        for sequence in lines.sequences.iter() {
                            unit_ranges.push(UnitRange {
                                range: gimli::Range {
                                    begin: sequence.start,
                                    end: sequence.end,
                                },
                                unit_id,
                                max_end: 0,
                            })
                        }
                    }
                }
            }

            res_units.push(Unit::new(offset, dw_unit, lang, lines))
        }

        // Sort this for faster lookups.
        unit_ranges.sort_by_key(|i| i.range.begin);

        // Calculate the `max_end` field now that we've determined the order of
        // CUs.
        let mut max = 0;
        for i in unit_ranges.iter_mut() {
            max = max.max(i.range.end);
            i.max_end = max;
        }

        let slf = Self {
            dwarf: sections,
            unit_ranges: unit_ranges.into_boxed_slice(),
            units: res_units.into_boxed_slice(),
        };
        Ok(slf)
    }

    /// Find the unit containing the given offset, and convert the
    /// offset into a unit offset.
    pub(super) fn find_unit(
        &self,
        offset: gimli::DebugInfoOffset<<R<'_> as gimli::Reader>::Offset>,
    ) -> Result<
        (
            gimli::UnitRef<'_, R<'dwarf>>,
            gimli::UnitOffset<<R<'dwarf> as gimli::Reader>::Offset>,
        ),
        gimli::Error,
    > {
        let unit = match self
            .units
            .binary_search_by_key(&offset.0, |unit| unit.offset().0)
        {
            // There is never a DIE at the unit offset or before the first unit.
            Ok(_) | Err(0) => return Err(gimli::Error::NoEntryAtGivenOffset),
            Err(i) => self.units[i - 1].dw_unit(),
        };

        let unit_offset = offset
            .to_unit_offset(&unit.header)
            .ok_or(gimli::Error::NoEntryAtGivenOffset)?;
        let unit = gimli::UnitRef::new(&self.dwarf, unit);
        Ok((unit, unit_offset))
    }

    /// Finds the CUs for the function address given.
    ///
    /// There might be multiple CUs whose range contains this address.
    /// Weak symbols have shown up in the wild which cause this to happen
    /// but otherwise this can happen if the CU has non-contiguous functions
    /// but only reports a single range.
    ///
    /// Consequently we return an iterator for all CUs which may contain the
    /// address, and the caller must check if there is actually a function or
    /// location in the CU for that address.
    fn find_units(&self, probe: u64) -> impl Iterator<Item = &Unit<'dwarf>> {
        self.find_units_range(probe, probe + 1)
            .map(|(unit, _range)| unit)
    }

    /// Finds the CUs covering the range of addresses given.
    ///
    /// The range is [low, high) (ie, the upper bound is exclusive). This can
    /// return multiple ranges for the same unit.
    #[inline]
    fn find_units_range(
        &self,
        probe_low: u64,
        probe_high: u64,
    ) -> impl Iterator<Item = (&Unit<'dwarf>, &gimli::Range)> {
        // First up find the position in the array which could have our function
        // address.
        let pos = match self
            .unit_ranges
            .binary_search_by_key(&probe_high, |i| i.range.begin)
        {
            // Although unlikely, we could find an exact match.
            Ok(i) => i + 1,
            // No exact match was found, but this probe would fit at slot `i`.
            // This means that slot `i` is bigger than `probe`, along with all
            // indices greater than `i`, so we need to search all previous
            // entries.
            Err(i) => i,
        };

        // Once we have our index we iterate backwards from that position
        // looking for a matching CU.
        self.unit_ranges[..pos]
            .iter()
            .rev()
            .take_while(move |i| {
                // We know that this CU's start is beneath the probe already because
                // of our sorted array.
                debug_assert!(i.range.begin <= probe_high);

                // Each entry keeps track of the maximum end address seen so far,
                // starting from the beginning of the array of unit ranges. We're
                // iterating in reverse so if our probe is beyond the maximum range
                // of this entry, then it's guaranteed to not fit in any prior
                // entries, so we break out.
                probe_low < i.max_end
            })
            .filter_map(move |i| {
                // If this CU doesn't actually contain this address, move to the
                // next CU.
                if probe_low >= i.range.end || probe_high <= i.range.begin {
                    return None
                }
                Some((&self.units[i.unit_id], &i.range))
            })
    }

    pub(super) fn find_function(
        &self,
        probe: u64,
    ) -> Result<Option<(&Function<'dwarf>, &Unit<'dwarf>)>, gimli::Error> {
        for unit in self.find_units(probe) {
            if let Some(function) = unit.find_function(probe, self)? {
                return Ok(Some((function, unit)))
            }
        }
        Ok(None)
    }

    /// Find the list of inlined functions that contain `probe`.
    pub(super) fn find_inlined_functions<'slf>(
        &'slf self,
        probe: u64,
        function: &'slf Function<'dwarf>,
        unit: &'slf Unit<'dwarf>,
    ) -> Result<
        Option<
            impl ExactSizeIterator<
                    Item = Result<(&'dwarf str, Option<Location<'slf>>), gimli::Error>,
                > + 'slf,
        >,
        gimli::Error,
    > {
        let unit_ref = gimli::UnitRef::new(&self.dwarf, unit.dw_unit());
        let inlined_fns = function.parse_inlined_functions(unit_ref, self)?;
        let iter = inlined_fns.find_inlined_functions(probe).map(move |inlined_fn| {
            let name = inlined_fn
                .name
                .map(|name| name.to_string())
                .transpose()?
                .unwrap_or("");

            let code_info = if let Some(call_file) = inlined_fn.call_file {
                if let Some(lines) = unit.parse_lines(unit_ref)? {
                    if let Some((dir, file)) = lines.files.get(call_file as usize) {
                        let code_info = Location {
                            dir,
                            file,
                            line: Some(inlined_fn.call_line),
                            column: Some(inlined_fn.call_column),
                        };
                        Some(code_info)
                    } else {
                        warn!(
                            "encountered invalid inlined function `call_file` index ({call_file}); ignoring..."
                        );
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            };
            Ok((name, code_info))
        });
        Ok(Some(iter))
    }

    /// Find the source file and line corresponding to the given virtual memory
    /// address.
    pub(crate) fn find_location(&self, probe: u64) -> Result<Option<Location<'_>>, gimli::Error> {
        for unit in self.find_units(probe) {
            if let Some(location) = unit.find_location(probe, self)? {
                return Ok(Some(location))
            }
        }
        Ok(None)
    }

    pub(crate) fn find_name<'s, 'slf: 's>(
        &'slf self,
        name: &'s str,
    ) -> impl Iterator<Item = Result<&'slf Function<'dwarf>, gimli::Error>> + 's {
        self.units
            .iter()
            .filter_map(move |unit| unit.find_name(name, self).transpose())
    }

    pub(crate) fn for_each_function<F>(&self, mut f: F) -> Result<(), gimli::Error>
    where
        F: FnMut(&Function<'dwarf>) -> ControlFlow<()>,
    {
        for unit in self.units.iter() {
            let functions = unit.parse_functions(self)?;

            for function in functions.functions.iter() {
                if let ControlFlow::Break(()) = f(function) {
                    return Ok(())
                }
            }
        }
        Ok(())
    }

    /// Retrieve a [`gimli::UnitRef`] for the provided `unit`.
    #[inline]
    pub(crate) fn unit_ref<'unit>(
        &'unit self,
        unit: &'unit gimli::Unit<R<'dwarf>>,
    ) -> gimli::UnitRef<'unit, R<'dwarf>> {
        gimli::UnitRef::new(&self.dwarf, unit)
    }

    /// Initialize all function data structures. This is used for benchmarks.
    #[cfg(test)]
    #[cfg(feature = "nightly")]
    fn parse_functions(&self) -> Result<(), gimli::Error> {
        for unit in self.units.iter() {
            let _functions = unit.parse_functions(self)?;
        }
        Ok(())
    }

    /// Initialize all inlined function data structures. This is used for
    /// benchmarks.
    #[cfg(test)]
    #[cfg(feature = "nightly")]
    fn parse_inlined_functions(&self) -> Result<(), gimli::Error> {
        for unit in self.units.iter() {
            let _functions = unit.parse_inlined_functions(self)?;
        }
        Ok(())
    }

    /// Initialize all line data structures. This is used for benchmarks.
    #[cfg(test)]
    #[cfg(feature = "nightly")]
    fn parse_lines(&self) -> Result<(), gimli::Error> {
        for unit in self.units.iter() {
            let unit_ref = self.unit_ref(unit.dw_unit());
            let _lines = unit.parse_lines(unit_ref)?;
        }
        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::env;
    use std::ffi::OsStr;
    #[cfg(feature = "nightly")]
    use std::hint::black_box;
    use std::path::Path;

    use gimli::Dwarf;

    #[cfg(feature = "nightly")]
    use test::Bencher;

    use test_log::test;

    use crate::dwarf::reader;
    use crate::elf::ElfParser;


    /// Check that we can format a section offset as expected.
    #[test]
    fn offset_formatting() {
        let offset = gimli::UnitSectionOffset::DebugInfoOffset(gimli::DebugInfoOffset(42usize));
        assert_eq!(format_offset(offset), format!(".debug_info+0x0000002a"));

        let offset = gimli::UnitSectionOffset::DebugTypesOffset(gimli::DebugTypesOffset(1337usize));
        assert_eq!(format_offset(offset), format!(".debug_types+0x00000539"));
    }

    /// Check that we can parse function and line information in various
    /// DWARF versions.
    #[test]
    fn function_and_line_parsing() {
        let binaries = [
            "test-dwarf-v2.bin",
            "test-dwarf-v3.bin",
            "test-dwarf-v4.bin",
            "test-dwarf-v5.bin",
            "test-dwarf-v5-zlib.bin",
            #[cfg(feature = "zstd")]
            "test-dwarf-v5-zstd.bin",
        ];

        for binary in binaries {
            let bin_name = Path::new(&env!("CARGO_MANIFEST_DIR"))
                .join("data")
                .join(binary);

            let parser = ElfParser::open(bin_name.as_path()).unwrap();
            let mut load_section = |section| reader::load_section(&parser, section);
            let dwarf = Dwarf::<R>::load(&mut load_section).unwrap();
            let units = Units::parse(dwarf).unwrap();

            // Double check that we actually did what we set out to do
            // by checking that we can find a function that we know
            // should exist.
            let mut funcs = units.find_name("fibonacci");
            let func = funcs.next().unwrap().unwrap();
            assert_eq!(func.name.unwrap().to_string().unwrap(), "fibonacci");

            let addr = func.range.as_ref().unwrap().begin;
            let loc = units.find_location(addr).unwrap().unwrap();
            assert_ne!(loc.dir, Path::new(""));
            assert_eq!(loc.file, OsStr::new("test-exe.c"));
            assert_eq!(loc.line.unwrap(), 4);

            assert!(funcs.next().is_none());
        }
    }

    /// Check that we fail to find any data for an address not
    /// represented.
    #[test]
    fn no_matching_data() {
        let binaries = [
            "test-dwarf-v2.bin",
            "test-dwarf-v3.bin",
            "test-dwarf-v4.bin",
            "test-dwarf-v5.bin",
            "test-dwarf-v5-zlib.bin",
            #[cfg(feature = "zstd")]
            "test-dwarf-v5-zstd.bin",
        ];

        for binary in binaries {
            let bin_name = Path::new(&env!("CARGO_MANIFEST_DIR"))
                .join("data")
                .join(binary);

            let parser = ElfParser::open(bin_name.as_path()).unwrap();
            let mut load_section = |section| reader::load_section(&parser, section);
            let dwarf = Dwarf::<R>::load(&mut load_section).unwrap();
            let units = Units::parse(dwarf).unwrap();

            // Bogus address typically somewhere in kernel space but
            // unlikely to be in any of our binaries.
            let bogus_addr = 0xffffffffffff68d0;

            let func = units.find_function(bogus_addr).unwrap();
            assert!(func.is_none());

            let loc = units.find_location(bogus_addr).unwrap();
            assert_eq!(loc, None);
        }
    }

    /// Benchmark the parsing of all functions, end-to-end.
    #[cfg(feature = "nightly")]
    #[bench]
    fn bench_function_parsing_blazesym(b: &mut Bencher) {
        let bin_name = env::current_exe().unwrap();
        let parser = ElfParser::open(bin_name.as_path()).unwrap();
        let mut load_section = |section| reader::load_section(&parser, section);

        let () = b.iter(|| {
            let dwarf = Dwarf::<R>::load(&mut load_section).unwrap();
            let units = Units::parse(black_box(dwarf)).unwrap();
            let _funcs = black_box(units.parse_functions().unwrap());
        });
    }

    /// Benchmark the parsing of all functions, end-to-end, using
    /// addr2line.
    #[cfg(feature = "nightly")]
    #[bench]
    fn bench_function_parsing_addr2line(b: &mut Bencher) {
        let bin_name = env::current_exe().unwrap();
        let parser = ElfParser::open(bin_name.as_path()).unwrap();
        let mut load_section = |section| reader::load_section(&parser, section);

        let () = b.iter(|| {
            let dwarf = Dwarf::<R>::load(&mut load_section).unwrap();
            let ctx = addr2line::Context::from_dwarf(dwarf).unwrap();
            let _funcs = black_box(ctx.parse_functions().unwrap());
        });
    }

    /// Benchmark the parsing of inlined function information, end-to-end.
    #[cfg(feature = "nightly")]
    #[bench]
    fn bench_inlined_function_parsing_blazesym(b: &mut Bencher) {
        let bin_name = env::current_exe().unwrap();
        let parser = ElfParser::open(bin_name.as_path()).unwrap();
        let mut load_section = |section| reader::load_section(&parser, section);

        let () = b.iter(|| {
            let dwarf = Dwarf::<R>::load(&mut load_section).unwrap();
            let units = Units::parse(black_box(dwarf)).unwrap();
            let _lines = black_box(units.parse_inlined_functions().unwrap());
        });
    }

    /// Benchmark the parsing of inlined function information, end-to-end, using
    /// addr2line.
    #[cfg(feature = "nightly")]
    #[bench]
    fn bench_inlined_function_parsing_addr2line(b: &mut Bencher) {
        let bin_name = env::current_exe().unwrap();
        let parser = ElfParser::open(bin_name.as_path()).unwrap();
        let mut load_section = |section| reader::load_section(&parser, section);

        let () = b.iter(|| {
            let dwarf = Dwarf::<R>::load(&mut load_section).unwrap();
            let ctx = addr2line::Context::from_dwarf(dwarf).unwrap();
            let _lines = black_box(ctx.parse_inlined_functions().unwrap());
        });
    }

    /// Benchmark the parsing of source location information, end-to-end.
    #[cfg(feature = "nightly")]
    #[bench]
    fn bench_line_parsing_blazesym(b: &mut Bencher) {
        let bin_name = env::current_exe().unwrap();
        let parser = ElfParser::open(bin_name.as_path()).unwrap();
        let mut load_section = |section| reader::load_section(&parser, section);

        let () = b.iter(|| {
            let dwarf = Dwarf::<R>::load(&mut load_section).unwrap();
            let units = Units::parse(black_box(dwarf)).unwrap();
            let _lines = black_box(units.parse_lines().unwrap());
        });
    }

    /// Benchmark the parsing of source location information,
    /// end-to-end, using addr2line.
    #[cfg(feature = "nightly")]
    #[bench]
    fn bench_line_parsing_addr2line(b: &mut Bencher) {
        let bin_name = env::current_exe().unwrap();
        let parser = ElfParser::open(bin_name.as_path()).unwrap();
        let mut load_section = |section| reader::load_section(&parser, section);

        let () = b.iter(|| {
            let dwarf = Dwarf::<R>::load(&mut load_section).unwrap();
            let ctx = addr2line::Context::from_dwarf(dwarf).unwrap();
            let _lines = black_box(ctx.parse_lines().unwrap());
        });
    }
}
