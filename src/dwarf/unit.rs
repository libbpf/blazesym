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

use std::cell::OnceCell;

use super::function::Function;
use super::function::Functions;
use super::lines::Lines;
use super::location::Location;
use super::reader::R;
use super::units::Units;


/// A DWO unit has its own DWARF sections.
#[derive(Debug)]
struct DwoUnit<'dwarf> {
    dwarf: gimli::Dwarf<R<'dwarf>>,
    dw_unit: gimli::Unit<R<'dwarf>>,
}

impl<'dwarf> DwoUnit<'dwarf> {
    fn unit_ref<'unit>(&'unit self) -> gimli::UnitRef<'unit, R<'dwarf>> {
        gimli::UnitRef::new(&self.dwarf, &self.dw_unit)
    }
}


pub(super) struct UnitRange {
    pub unit_id: usize,
    pub max_end: u64,
    pub range: gimli::Range,
}


#[derive(Debug)]
pub(super) struct Unit<'dwarf> {
    offset: gimli::DebugInfoOffset<<R<'dwarf> as gimli::Reader>::Offset>,
    /// The gimli unit, lazily constructed from the header.
    dw_unit: OnceCell<gimli::Result<Box<gimli::Unit<R<'dwarf>>>>>,
    /// The unit header, stored for lazy construction of `dw_unit`.
    header: gimli::UnitHeader<R<'dwarf>>,
    lang: OnceCell<gimli::Result<Option<gimli::DwLang>>>,
    lines: OnceCell<gimli::Result<Lines<'dwarf>>>,
    funcs: OnceCell<gimli::Result<Functions<'dwarf>>>,
    dwo: OnceCell<gimli::Result<Option<Box<DwoUnit<'dwarf>>>>>,
}

impl<'dwarf> Unit<'dwarf> {
    pub(super) fn new(
        offset: gimli::DebugInfoOffset<<R<'dwarf> as gimli::Reader>::Offset>,
        unit: Box<gimli::Unit<R<'dwarf>>>,
        lang: Option<gimli::DwLang>,
        lines: OnceCell<Lines<'dwarf>>,
    ) -> Self {
        let header = unit.header.clone();
        Self {
            offset,
            dw_unit: OnceCell::from(Ok(unit)),
            header,
            lang: OnceCell::from(Ok(lang)),
            lines: lines
                .into_inner()
                .map(Result::Ok)
                .map(OnceCell::from)
                .unwrap_or_default(),
            funcs: OnceCell::new(),
            dwo: OnceCell::new(),
        }
    }

    /// Create a unit with deferred `gimli::Unit` construction.
    ///
    /// The full `gimli::Unit` (which involves abbreviation parsing and
    /// line program header parsing) is deferred until first access.
    pub(super) fn new_deferred(
        offset: gimli::DebugInfoOffset<<R<'dwarf> as gimli::Reader>::Offset>,
        header: gimli::UnitHeader<R<'dwarf>>,
    ) -> Self {
        Self {
            offset,
            dw_unit: OnceCell::new(),
            header,
            lang: OnceCell::new(),
            lines: OnceCell::new(),
            funcs: OnceCell::new(),
            dwo: OnceCell::new(),
        }
    }

    /// Get or lazily construct the `gimli::Unit`.
    fn ensure_dw_unit(&self, units: &Units<'dwarf>) -> gimli::Result<&gimli::Unit<R<'dwarf>>> {
        let dw_unit = self
            .dw_unit
            .get_or_init(|| units.dwarf().unit(self.header.clone()).map(Box::new))
            .as_ref()
            .map_err(|err| *err)?;

        Ok(dw_unit)
    }

    fn process_dwo(
        &self,
        dw_unit: &gimli::Unit<R<'dwarf>>,
        dwo_dwarf: Option<gimli::Dwarf<R<'dwarf>>>,
    ) -> gimli::Result<Option<Box<DwoUnit<'dwarf>>>> {
        let dwo_dwarf = match dwo_dwarf {
            None => return Ok(None),
            Some(dwo_dwarf) => dwo_dwarf,
        };
        let mut dwo_units = dwo_dwarf.units();
        let dwo_header = match dwo_units.next()? {
            Some(dwo_header) => dwo_header,
            None => return Ok(None),
        };

        let mut dwo_unit = dwo_dwarf.unit(dwo_header)?;
        let () = dwo_unit.copy_relocated_attributes(dw_unit);

        let dwo = Box::new(DwoUnit {
            dwarf: dwo_dwarf,
            dw_unit: dwo_unit,
        });
        Ok(Some(dwo))
    }

    pub(super) fn unit_ref<'unit>(
        &'unit self,
        units: &'unit Units<'dwarf>,
    ) -> gimli::Result<gimli::UnitRef<'unit, R<'dwarf>>> {
        let dw_unit = self.ensure_dw_unit(units)?;

        let map_dwo_result = |dwo_result: &'unit gimli::Result<Option<Box<DwoUnit<'dwarf>>>>| {
            dwo_result
                .as_ref()
                .map(|dwo_unit| match dwo_unit {
                    Some(dwo_unit) => dwo_unit.unit_ref(),
                    None => units.unit_ref(dw_unit),
                })
                .map_err(|err| *err)
        };

        if let Some(result) = self.dwo.get() {
            return map_dwo_result(result)
        }

        let dwo_id = match dw_unit.dwo_id {
            Some(dwo_id) => dwo_id,
            None => return map_dwo_result(self.dwo.get_or_init(|| Ok(None))),
        };

        let result = self
            .dwo
            .get_or_init(|| self.process_dwo(dw_unit, units.load_dwo(dwo_id)?));
        map_dwo_result(result)
    }

    pub(super) fn parse_functions<'unit>(
        &'unit self,
        units: &Units<'dwarf>,
    ) -> gimli::Result<&'unit Functions<'dwarf>> {
        let unit = self.unit_ref(units)?;
        let functions = self.parse_functions_dwarf_and_unit(unit, units)?;
        Ok(functions)
    }

    #[cfg(test)]
    #[cfg(feature = "nightly")]
    pub(super) fn parse_inlined_functions<'unit>(
        &'unit self,
        units: &Units<'dwarf>,
    ) -> gimli::Result<&'unit Functions<'dwarf>> {
        self.funcs
            .get_or_init(|| {
                let unit = self.unit_ref(units)?;
                let funcs = Functions::parse(unit, units)?;
                let () = funcs.parse_inlined_functions(unit, units)?;
                Ok(funcs)
            })
            .as_ref()
            .map_err(|err| *err)
    }

    pub(super) fn parse_lines(
        &self,
        units: &Units<'dwarf>,
    ) -> gimli::Result<Option<&Lines<'dwarf>>> {
        let dw_unit = self.ensure_dw_unit(units)?;
        let ilnp = match dw_unit.line_program {
            Some(ref ilnp) => ilnp,
            None => return Ok(None),
        };
        let lines = self
            .lines
            .get_or_init(|| {
                // NB: line information is always stored in the main
                //     debug file so this does not need to handle DWOs.
                let unit = units.unit_ref(dw_unit);
                Lines::parse(unit, ilnp.clone())
            })
            .as_ref()
            .map_err(|err| *err)?;
        Ok(Some(lines))
    }

    pub(super) fn find_location(
        &self,
        probe: u64,
        units: &Units<'dwarf>,
    ) -> gimli::Result<Option<Location<'_>>> {
        if let Some(lines) = self.parse_lines(units)? {
            lines.find_location(probe)
        } else {
            Ok(None)
        }
    }

    fn parse_functions_dwarf_and_unit(
        &self,
        unit: gimli::UnitRef<'_, R<'dwarf>>,
        units: &Units<'dwarf>,
    ) -> gimli::Result<&Functions<'dwarf>> {
        self.funcs
            .get_or_init(|| Functions::parse(unit, units))
            .as_ref()
            .map_err(|err| *err)
    }

    pub(super) fn find_function(
        &self,
        probe: u64,
        units: &Units<'dwarf>,
    ) -> gimli::Result<Option<&Function<'dwarf>>> {
        let unit = self.unit_ref(units)?;
        let functions = self.parse_functions_dwarf_and_unit(unit, units)?;
        let function = match functions.find_address(probe) {
            Some(address) => {
                let function_index = functions.addresses[address].function;
                let function = &functions.functions[function_index];
                Some(function)
            }
            None => None,
        };
        Ok(function)
    }

    pub(super) fn find_name<'slf>(
        &'slf self,
        name: &str,
        units: &Units<'dwarf>,
    ) -> gimli::Result<Option<&'slf Function<'dwarf>>> {
        let unit = self.unit_ref(units)?;
        let functions = self.parse_functions_dwarf_and_unit(unit, units)?;
        for func in functions.functions.iter() {
            let name = Some(name.as_bytes());
            if func.name.as_ref().map(|r| r.inner().slice()) == name {
                return Ok(Some(func))
            }
        }
        Ok(None)
    }

    /// Retrieve the unit's debug info offset.
    #[inline]
    pub(super) fn offset(&self) -> gimli::DebugInfoOffset<<R<'dwarf> as gimli::Reader>::Offset> {
        self.offset
    }

    /// Retrieve the underlying [`gimli::Unit`] header.
    #[inline]
    pub(super) fn header(&self) -> &gimli::UnitHeader<R<'dwarf>> {
        &self.header
    }

    /// Attempt to retrieve the compilation unit's source code language.
    #[inline]
    pub(super) fn language(&self, units: &Units<'dwarf>) -> gimli::Result<Option<gimli::DwLang>> {
        let dw_unit = self.ensure_dw_unit(units)?;

        let lang = self.lang.get_or_init(|| {
            let unit_ref = units.unit_ref(dw_unit);
            let mut entries = unit_ref.entries_raw(None)?;
            if let Some(abbrev) = entries.read_abbreviation()? {
                for spec in abbrev.attributes() {
                    let attr = entries.read_attribute(*spec)?;
                    if attr.name() == gimli::DW_AT_language {
                        if let gimli::AttributeValue::Language(val) = attr.value() {
                            return Ok(Some(val))
                        }
                        break;
                    }
                }
            }
            gimli::Result::Ok(None)
        });

        *lang
    }
}
