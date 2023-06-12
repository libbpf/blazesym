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

use std::cmp::Ordering;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;

use gimli::Error;

use super::range::RangeAttributes;
use super::reader::R;


fn name_entry<R>(
    unit: &gimli::Unit<R>,
    offset: gimli::UnitOffset<R::Offset>,
    sections: &gimli::Dwarf<R>,
    recursion_limit: usize,
) -> Result<Option<R>, Error>
where
    R: gimli::Reader,
{
    let mut entries = unit.entries_raw(Some(offset))?;
    let abbrev = if let Some(abbrev) = entries.read_abbreviation()? {
        abbrev
    } else {
        return Err(gimli::Error::NoEntryAtGivenOffset)
    };

    let mut name = None;
    let mut next = None;
    for spec in abbrev.attributes() {
        match entries.read_attribute(*spec) {
            Ok(ref attr) => match attr.name() {
                gimli::DW_AT_linkage_name | gimli::DW_AT_MIPS_linkage_name => {
                    if let Ok(val) = sections.attr_string(unit, attr.value()) {
                        return Ok(Some(val))
                    }
                }
                gimli::DW_AT_name => {
                    if let Ok(val) = sections.attr_string(unit, attr.value()) {
                        name = Some(val);
                    }
                }
                gimli::DW_AT_abstract_origin | gimli::DW_AT_specification => {
                    next = Some(attr.value());
                }
                _ => {}
            },
            Err(e) => return Err(e),
        }
    }

    if name.is_some() {
        return Ok(name)
    }

    if let Some(next) = next {
        return name_attr(next, unit, sections, recursion_limit - 1)
    }

    Ok(None)
}


fn name_attr<R>(
    attr: gimli::AttributeValue<R>,
    unit: &gimli::Unit<R>,
    sections: &gimli::Dwarf<R>,
    recursion_limit: usize,
) -> Result<Option<R>, Error>
where
    R: gimli::Reader,
{
    if recursion_limit == 0 {
        return Ok(None)
    }

    match attr {
        gimli::AttributeValue::UnitRef(offset) => {
            name_entry(unit, offset, sections, recursion_limit)
        }
        // TODO: Need to handle `AttributeValue::DebugInfoRef` and
        //       `AttributeValue::DebugInfoRefSup`.
        _ => Ok(None),
    }
}


/// A single address range for a function.
///
/// It is possible for a function to have multiple address ranges; this
/// is handled by having multiple `FunctionAddress` entries with the same
/// `function` field.
#[derive(Debug)]
pub(crate) struct FunctionAddress {
    range: gimli::Range,
    /// An index into `Functions::functions`.
    pub(crate) function: usize,
}


pub(crate) struct Function<'dwarf> {
    pub(crate) dw_die_offset: gimli::UnitOffset<<R<'dwarf> as gimli::Reader>::Offset>,
    /// The function's name, if present.
    pub(crate) name: Option<R<'dwarf>>,
    /// The function's range (begin and end address).
    pub(crate) range: Option<gimli::Range>,
}

impl Debug for Function<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let Self {
            dw_die_offset,
            name,
            range,
        } = self;

        f.debug_struct(stringify!(Function))
            .field("dw_die_offset", dw_die_offset)
            .field(
                "name",
                match name.as_ref().and_then(|r| r.to_string().ok()) {
                    Some(ref s) => s,
                    None => &name,
                },
            )
            .field("range", range)
            .finish()
    }
}


#[derive(Debug)]
pub(crate) struct Functions<'dwarf> {
    /// List of all `DW_TAG_subprogram` details in the unit.
    pub(crate) functions: Box<[Function<'dwarf>]>,
    /// List of `DW_TAG_subprogram` address ranges in the unit.
    pub(crate) addresses: Box<[FunctionAddress]>,
}

impl<'dwarf> Functions<'dwarf> {
    pub(crate) fn parse(
        unit: &gimli::Unit<R<'dwarf>>,
        sections: &gimli::Dwarf<R<'dwarf>>,
    ) -> Result<Self, Error> {
        let mut functions = Vec::new();
        let mut addresses = Vec::new();
        let mut entries = unit.entries_raw(None)?;
        while !entries.is_empty() {
            let dw_die_offset = entries.next_offset();
            if let Some(abbrev) = entries.read_abbreviation()? {
                if abbrev.tag() == gimli::DW_TAG_subprogram {
                    let mut name = None;
                    let mut ranges = RangeAttributes::default();
                    for spec in abbrev.attributes() {
                        match entries.read_attribute(*spec) {
                            Ok(ref attr) => {
                                match attr.name() {
                                    gimli::DW_AT_linkage_name | gimli::DW_AT_MIPS_linkage_name => {
                                        if let Ok(val) = sections.attr_string(unit, attr.value()) {
                                            name = Some(val);
                                        }
                                    }
                                    gimli::DW_AT_name => {
                                        if name.is_none() {
                                            name = sections.attr_string(unit, attr.value()).ok();
                                        }
                                    }
                                    gimli::DW_AT_abstract_origin | gimli::DW_AT_specification => {
                                        if name.is_none() {
                                            name = name_attr(attr.value(), unit, sections, 16)?;
                                        }
                                    }
                                    gimli::DW_AT_low_pc => match attr.value() {
                                        gimli::AttributeValue::Addr(val) => {
                                            ranges.low_pc = Some(val)
                                        }
                                        gimli::AttributeValue::DebugAddrIndex(index) => {
                                            ranges.low_pc = Some(sections.address(unit, index)?);
                                        }
                                        _ => {}
                                    },
                                    gimli::DW_AT_high_pc => match attr.value() {
                                        gimli::AttributeValue::Addr(val) => {
                                            ranges.high_pc = Some(val)
                                        }
                                        gimli::AttributeValue::DebugAddrIndex(index) => {
                                            ranges.high_pc = Some(sections.address(unit, index)?);
                                        }
                                        gimli::AttributeValue::Udata(val) => {
                                            ranges.size = Some(val)
                                        }
                                        _ => {}
                                    },
                                    gimli::DW_AT_ranges => {
                                        ranges.ranges_offset =
                                            sections.attr_ranges_offset(unit, attr.value())?;
                                    }
                                    _ => {}
                                };
                            }
                            Err(e) => return Err(e),
                        }
                    }

                    let function_index = functions.len();
                    let added = ranges.for_each_range(sections, unit, |range| {
                        addresses.push(FunctionAddress {
                            range,
                            function: function_index,
                        });
                    })?;

                    if added {
                        let function = Function {
                            dw_die_offset,
                            name,
                            range: ranges.bounds(),
                        };
                        functions.push(function);
                    }
                } else {
                    entries.skip_attributes(abbrev.attributes())?;
                }
            }
        }

        // The binary search requires the addresses to be sorted.
        //
        // It also requires them to be non-overlapping.  In practice, overlapping
        // function ranges are unlikely, so we don't try to handle that yet.
        //
        // It's possible for multiple functions to have the same address range if the
        // compiler can detect and remove functions with identical code.  In that case
        // we'll nondeterministically return one of them.
        addresses.sort_by_key(|x| x.range.begin);

        Ok(Functions {
            functions: functions.into_boxed_slice(),
            addresses: addresses.into_boxed_slice(),
        })
    }

    pub(crate) fn find_address(&self, probe: u64) -> Option<usize> {
        self.addresses
            .binary_search_by(|address| {
                if probe < address.range.begin {
                    Ordering::Greater
                } else if probe >= address.range.end {
                    Ordering::Less
                } else {
                    Ordering::Equal
                }
            })
            .ok()
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use test_log::test;


    /// Exercise the `Debug` representation of various types.
    #[test]
    fn debug_repr() {
        let addr = FunctionAddress {
            range: gimli::Range {
                begin: 0x42,
                end: 0x43,
            },
            function: 1337,
        };
        assert_ne!(format!("{addr:?}"), "");

        let func = Function {
            dw_die_offset: gimli::UnitOffset(24),
            name: None,
            range: None,
        };
        assert_ne!(format!("{func:?}"), "");

        let funcs = Functions {
            functions: Box::default(),
            addresses: Box::default(),
        };
        assert_ne!(format!("{funcs:?}"), "");
    }
}
