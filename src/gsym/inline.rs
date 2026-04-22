use crate::util::ReadRaw as _;
use crate::ErrorExt as _;
use crate::IntoError as _;
use crate::Result;


pub(super) struct InlineFrame {
    pub name: u32,
    pub call_file: u32,
    pub call_line: u32,
}

pub(super) struct InlineInfo;

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

    fn parse_into_stack(
        data: &mut &[u8],
        base_addr: u64,
        lookup_addr: u64,
        stack: &mut Vec<InlineFrame>,
    ) -> Result<bool> {
        let range_cnt = data
            .read_u64_leb128()
            .ok_or_invalid_data(|| "failed to read range count from inline information")?;
        let range_cnt = usize::try_from(range_cnt)
            .ok()
            .ok_or_invalid_data(|| format!("range count ({range_cnt}) is too big"))?;
        if range_cnt == 0 {
            return Ok(false);
        }

        let mut matches = false;
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

            if (start..end).contains(&lookup_addr) {
                matches = true;
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
            .ok_or_invalid_data(|| format!("call file index ({call_file}) is too big"))?;
        let call_line = data
            .read_u64_leb128()
            .ok_or_invalid_data(|| "failed to read call line from inline information")?;
        let call_line = u32::try_from(call_line).unwrap_or(u32::MAX);

        if matches {
            if name > 0 {
                let () = stack.push(InlineFrame {
                    name,
                    call_file,
                    call_line,
                });
            }

            if has_children {
                while Self::parse_into_stack(data, child_base_addr, lookup_addr, stack)? {}
            }
        } else if has_children {
            while Self::skip(data)? {}
        }

        Ok(true)
    }

    /// Parse the inline info tree for `lookup_addr` and produce a flat
    /// inline stack directly, without building an intermediate tree.
    pub(crate) fn parse_inline_stack(
        data: &mut &[u8],
        base_addr: u64,
        lookup_addr: u64,
    ) -> Result<Vec<InlineFrame>> {
        let mut stack = Vec::new();
        let _parsed = Self::parse_into_stack(data, base_addr, lookup_addr, &mut stack)?;
        Ok(stack)
    }
}
