use std::ops::Range;

use crate::util::ReadRaw as _;
use crate::ErrorExt as _;
use crate::IntoError as _;
use crate::Result;


#[derive(Clone)]
pub(super) struct InlineInfo {
    pub name: u32,
    pub call_file: Option<u32>,
    pub call_line: Option<u32>,

    ranges: Vec<Range<u64>>,
    children: Vec<Self>,
}

impl InlineInfo {
    /// Advance `data` past one `InlineInfo` node and all its descendants.
    fn skip(data: &mut &[u8]) -> Result<bool> {
        let range_cnt = data
            .read_u64_leb128()
            .ok_or_invalid_data(|| "failed to read range count from inline information")?;
        if range_cnt == 0 {
            return Ok(false);
        }

        for _ in 0..range_cnt {
            let _offset = data
                .read_u64_leb128()
                .ok_or_invalid_data(|| "failed to read offset from inline information")?;
            let _size = data
                .read_u64_leb128()
                .ok_or_invalid_data(|| "failed to read size from inline information")?;
        }

        let child_cnt = data
            .read_u8()
            .ok_or_invalid_data(|| "failed to read child count from inline information")?;
        let has_children = child_cnt != 0;
        let _name = data
            .read_u32()
            .ok_or_invalid_data(|| "failed to read name from inline information")?;
        let _call_file = data
            .read_u64_leb128()
            .ok_or_invalid_data(|| "failed to read call file from inline information")?;
        let _call_line = data
            .read_u64_leb128()
            .ok_or_invalid_data(|| "failed to read call line from inline information")?;

        if has_children {
            while Self::skip(data)? {
                // Do nothing; we just skip the data.
            }
        }

        Ok(true)
    }

    /// Parse Gsym `InlineInfo` from raw bytes.
    pub(crate) fn parse(
        data: &mut &[u8],
        base_addr: u64,
        lookup_addr: u64,
    ) -> Result<Option<Self>> {
        let range_cnt = data
            .read_u64_leb128()
            .ok_or_invalid_data(|| "failed to read range count from inline information")?;
        let range_cnt = usize::try_from(range_cnt)
            .ok()
            .ok_or_invalid_data(|| "range count ({}) is too big")?;
        if range_cnt == 0 {
            return Ok(None)
        }

        let mut ranges = Vec::new();
        let mut child_base_addr = 0u64;

        for i in 0..range_cnt {
            let offset = data
                .read_u64_leb128()
                .ok_or_invalid_data(|| "failed to read offset from inline information")?;
            let size = data
                .read_u64_leb128()
                .ok_or_invalid_data(|| "failed to read size from inline information")?;

            let start = base_addr
                .checked_add(offset)
                .ok_or_invalid_data(|| {
                    format!("offset {offset:#x} overflowed base address {base_addr:#x}")
                })
                .context("failed calculate start address")?;
            let end = start
                .checked_add(size)
                .ok_or_invalid_data(|| {
                    format!("size {size:#x} overflowed start address {start:#x}")
                })
                .context("failed calculate end address")?;
            if i == 0 {
                child_base_addr = start;
            }

            let range = start..end;
            if range.contains(&lookup_addr) {
                let () = ranges.push(range);
            }
        }

        let child_cnt = data
            .read_u8()
            .ok_or_invalid_data(|| "failed to read child count from inline information")?;
        let has_children = child_cnt != 0;
        let name = data
            .read_u32()
            .ok_or_invalid_data(|| "failed to read name from inline information")?;

        let call_file = data
            .read_u64_leb128()
            .ok_or_invalid_data(|| "failed to read call file from inline information")?;
        let call_file = u32::try_from(call_file)
            .ok()
            .ok_or_invalid_data(|| "call file index ({}) is too big")?;
        let call_line = data
            .read_u64_leb128()
            .ok_or_invalid_data(|| "failed to read call line from inline information")?;
        let call_line = u32::try_from(call_line).unwrap_or(u32::MAX);

        let mut children = Vec::new();
        if has_children {
            if ranges.is_empty() {
                // This inlined function does not contain `lookup_addr`, no need
                // to decode ranges, just skip.
                while Self::skip(data)? {
                    // Do nothing; we just skip the data.
                }
            } else {
                while let Some(child) = Self::parse(data, child_base_addr, lookup_addr)? {
                    let () = children.push(child);
                }
            }
        }

        let slf = Self {
            name,
            call_file: Some(call_file),
            call_line: Some(call_line),
            ranges,
            children,
        };
        Ok(Some(slf))
    }

    fn inline_stack_impl<'slf>(&'slf self, addr: u64, inlined: &mut Vec<&'slf Self>) -> bool {
        for range in &self.ranges {
            if range.contains(&addr) {
                if self.name > 0 {
                    let () = inlined.push(self);
                }

                for child in &self.children {
                    if child.inline_stack_impl(addr, inlined) {
                        break
                    }
                }
                return !inlined.is_empty()
            }
        }
        false
    }

    pub(crate) fn inline_stack(&self, addr: u64) -> Vec<&Self> {
        let mut inlined = Vec::new();
        let _done = self.inline_stack_impl(addr, &mut inlined);
        inlined
    }
}
