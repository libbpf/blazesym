//! Opcode runner of GSYM line table.
//!
//! See <https://github.com/YtnbFirewings/gsym>
use super::types::{LineTableHeader, LineTableRow};
use crate::tools::{decode_leb128, decode_leb128_s};

const DBG_END_SEQUENCE: u8 = 0x00; // End of the line table
const DBG_SET_FILE: u8 = 0x01; // Set LineTableRow.file_idx, don't push a row
const DBG_ADVANCE_PC: u8 = 0x02; // Increment LineTableRow.address, and push a row
const DBG_ADVANCE_LINE: u8 = 0x03; // Set LineTableRow.file_line, don't push a row
const DBG_FIRST_SPECIAL: u8 = 0x04; // All special opcodes push a row.

pub enum RunResult {
    /// Run the operator successfully.
    Ok(usize),
    /// This operator creates a new row.
    NewRow(usize),
    /// The end of the program (the operator stream.)
    End,
    /// Fails to run the operator at the position.
    Err,
}

/// Create a LineTableRow to use as the states of a line table virtual
/// machine.
///
/// The returned LineTableRow can be passed to [`run_op()`] as `ctx`.
///
/// # Arguments
///
/// * `lthdr` - is a LineTableHeader returned by [`parse_line_table_header()`].
/// * `symaddr` - the address of the symbol that `lthdr` belongs to.
pub fn line_table_row_from(lthdr: &LineTableHeader, symaddr: u64) -> LineTableRow {
    LineTableRow {
        address: symaddr,
        file_idx: 1,
        file_line: lthdr.first_line,
    }
}

/// Run a GSYM line table operator/instruction in the buffer.
///
/// # Arguments
///
/// * `ctx` - a line table row to present the current states of the
///           virtual machine.  [`line_table_row_from()`] can create a
///           LineTableRow to keep the states of a virtual machine.
/// * `ltbl_hdr` - is a LineTableHeader.
/// * `ops` - is the buffer of the operators following the
///           LineTableHeader in a GSYM file.
/// * `pc` - is the program counter of the virtual machine.
///
/// Return a RunResult. `Ok()` and `NewRow()`will return the size of
/// this instruction.  So, the caller should adjust the value of `pc`
/// according to the value returned.
#[inline]
pub fn run_op(
    ctx: &mut LineTableRow,
    ltbl_hdr: &LineTableHeader,
    ops: &[u8],
    pc: usize,
) -> RunResult {
    let mut off = pc;
    let op = ops[off];
    off += 1;
    match op {
        DBG_END_SEQUENCE => RunResult::End,
        DBG_SET_FILE => {
            if let Some((f, bytes)) = decode_leb128(&ops[off..]) {
                off += bytes as usize;
                ctx.file_idx = f as u32;
                RunResult::Ok(off - pc)
            } else {
                RunResult::Err
            }
        }
        DBG_ADVANCE_PC => {
            if let Some((adv, bytes)) = decode_leb128(&ops[off..]) {
                off += bytes as usize;
                ctx.address += adv;
                RunResult::NewRow(off - pc)
            } else {
                RunResult::Err
            }
        }
        DBG_ADVANCE_LINE => {
            if let Some((adv, bytes)) = decode_leb128_s(&ops[off..]) {
                off += bytes as usize;
                ctx.file_line = (ctx.file_line as i64 + adv) as u32;
                RunResult::Ok(off - pc)
            } else {
                RunResult::Err
            }
        }
        // Special operators.
        //
        // All operators that have a value greater than or equal to
        // DBG_FIRST_SPECIAL are considered special operators. These
        // operators change both the line number and address of the
        // virtual machine and emit a new row.
        _ => {
            let adjusted = (op - DBG_FIRST_SPECIAL) as i64;
            // The range of line number delta is from min_delta to
            // max_delta, including max_delta.
            let range = ltbl_hdr.max_delta - ltbl_hdr.min_delta + 1;
            let line_delta = ltbl_hdr.min_delta + (adjusted % range);
            let addr_delta = adjusted / range;

            let file_line = ctx.file_line as i32 + line_delta as i32;
            if file_line < 1 {
                return RunResult::Err;
            }

            ctx.file_line = file_line as u32;
            ctx.address = (ctx.address as i64 + addr_delta) as u64;
            RunResult::NewRow(off - pc)
        }
    }
}
