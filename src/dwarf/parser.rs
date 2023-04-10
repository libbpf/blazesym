#[cfg(test)]
use std::env;
use std::ffi::CStr;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::io::Error;
use std::io::ErrorKind;
use std::mem;
#[cfg(test)]
use std::path::Path;

use crate::elf::ElfParser;
use crate::util::decode_leb128;
use crate::util::decode_leb128_s;
use crate::util::decode_udword;
use crate::util::decode_uhalf;
use crate::util::decode_uword;
use crate::util::find_match_or_lower_bound_by;
use crate::util::Pod;
use crate::util::ReadRaw as _;
use crate::Addr;
use crate::SymbolType;

use super::constants;
use super::debug_info;


#[repr(C, packed)]
pub(crate) struct DebugLinePrologueV2 {
    total_length: u32,
    version: u16,
    prologue_length: u32,
    minimum_instruction_length: u8,
    default_is_stmt: u8,
    line_base: i8,
    line_range: u8,
    opcode_base: u8,
}

// SAFETY: `DebugLinePrologueV2` is valid for any bit pattern.
unsafe impl Pod for DebugLinePrologueV2 {}


/// DebugLinePrologue is actually a V4.
///
/// DebugLinePrologueV2 will be converted to this type.
#[repr(C, packed)]
pub(crate) struct DebugLinePrologue {
    total_length: u32,
    version: u16,
    prologue_length: u32,
    minimum_instruction_length: u8,
    maximum_ops_per_instruction: u8,
    default_is_stmt: u8,
    line_base: i8,
    line_range: u8,
    opcode_base: u8,
}

impl Debug for DebugLinePrologue {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let total_length = self.total_length;
        let version = self.version;

        f.debug_struct("DebugLinePrologue")
            .field("total_length", &total_length)
            .field("version", &version)
            .finish()
    }
}

// SAFETY: `DebugLinePrologue` is valid for any bit pattern.
unsafe impl Pod for DebugLinePrologue {}


/// The file information of a file for a CU.
#[derive(Debug)]
pub(crate) struct DebugLineFileInfo {
    name: String,
    dir_idx: u32, // Index to include_directories of DebugLineCU.
    _mod_tm: u64,
    _size: usize,
}

/// Represent a Compile Unit (CU) in a .debug_line section.
#[derive(Debug)]
pub(crate) struct DebugLineCU {
    pub prologue: DebugLinePrologue,
    pub _standard_opcode_lengths: Vec<u8>,
    pub include_directories: Vec<String>,
    pub files: Vec<DebugLineFileInfo>,
    pub matrix: Vec<DebugLineStates>,
}

impl DebugLineCU {
    pub(crate) fn find_line(&self, address: Addr) -> Option<(&str, &str, usize)> {
        let idx = find_match_or_lower_bound_by(&self.matrix, address, |dls| dls.address)?;
        let states = &self.matrix[idx];
        if states.end_sequence {
            // This is the first byte after the last instruction
            return None
        }

        self.stringify_row(idx)
    }

    pub(crate) fn stringify_row(&self, idx: usize) -> Option<(&str, &str, usize)> {
        let states = &self.matrix[idx];
        let (dir, file) = {
            if states.file > 0 {
                let file = &self.files[states.file - 1];
                let dir = {
                    if file.dir_idx == 0 {
                        ""
                    } else {
                        self.include_directories[file.dir_idx as usize - 1].as_str()
                    }
                };
                (dir, file.name.as_str())
            } else {
                ("", "")
            }
        };

        Some((dir, file, states.line))
    }
}

/// Parse the list of directory paths for a CU.
fn parse_debug_line_dirs(data: &mut &[u8]) -> Result<Vec<String>, Error> {
    let mut strs = Vec::<String>::new();

    loop {
        let string = data
            .read_cstr()
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidData,
                    "failed to find NUL terminated string",
                )
            })?
            .to_str()
            .map_err(|_| Error::new(ErrorKind::InvalidData, "Invalid UTF-8 string"))?;
        // If the first byte is 0 we reached the end. In our case that
        // maps to an empty NUL terminated string.
        if string.is_empty() {
            break Ok(strs)
        }
        strs.push(string.to_string());
    }
}

/// Parse the list of file information for a CU.
fn parse_debug_line_files(data: &mut &[u8]) -> Result<Vec<DebugLineFileInfo>, Error> {
    let mut strs = Vec::<DebugLineFileInfo>::new();

    loop {
        let name = data
            .read_cstr()
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidData,
                    "failed to find NUL terminated string",
                )
            })?
            .to_str()
            .map_err(|_| Error::new(ErrorKind::InvalidData, "Invalid UTF-8 string"))?;
        // If the first byte is 0 we reached the end. In our case that
        // maps to an empty NUL terminated string.
        if name.is_empty() {
            break Ok(strs)
        }

        let (dir_idx, _bytes) = data
            .read_u128_leb128()
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "Invalid directory index"))?;

        let (mod_tm, _bytes) = data
            .read_u128_leb128()
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "Invalid last modified time"))?;

        let (size, _bytes) = data
            .read_u128_leb128()
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "Invalid file size"))?;

        let () = strs.push(DebugLineFileInfo {
            name: name.to_string(),
            dir_idx: dir_idx as u32,
            _mod_tm: mod_tm as u64,
            _size: size as usize,
        });
    }
}

fn parse_debug_line_cu(data: &mut &[u8], addresses: &[Addr]) -> Result<DebugLineCU, Error> {
    let prologue_v2_size: usize = mem::size_of::<DebugLinePrologueV2>();
    let prologue_v4_size: usize = mem::size_of::<DebugLinePrologue>();

    let mut head = *data;
    let v2 = data
        .read_pod::<DebugLinePrologueV2>()
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "failed to read debug line prologue"))?;

    if v2.version != 2 && v2.version != 4 {
        let version = v2.version;
        return Err(Error::new(
            ErrorKind::Unsupported,
            format!("encountered unsupported DWARF version: {version}"),
        ))
    }

    let (prologue, prologue_size) = if v2.version == 4 {
        // Upgrade to V4.
        // V4 has more fields to read.
        let prologue_v4 = head.read_pod::<DebugLinePrologue>().ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidData,
                "failed to read debug line v4 prologue",
            )
        })?;
        (*data) = head;
        (prologue_v4, prologue_v4_size)
    } else {
        // Convert V2 to V4
        let prologue_v4 = DebugLinePrologue {
            total_length: v2.total_length,
            version: v2.version,
            prologue_length: v2.prologue_length,
            minimum_instruction_length: v2.minimum_instruction_length,
            maximum_ops_per_instruction: 0,
            default_is_stmt: v2.default_is_stmt,
            line_base: v2.line_base,
            line_range: v2.line_range,
            opcode_base: v2.opcode_base,
        };
        (prologue_v4, prologue_v2_size)
    };

    let to_read = prologue.total_length as usize + 4 - prologue_size;
    let () = data.ensure(to_read).ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidData,
            "encountered insufficient debug line information data",
        )
    })?;

    let std_op_num = (prologue.opcode_base - 1) as usize;
    let std_op_lengths = data
        .read_slice(std_op_num)
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "failed to read std op lengths"))?;
    let inc_dirs = parse_debug_line_dirs(data)?;
    let files = parse_debug_line_files(data)?;
    let matrix = run_debug_line_stmts(data, &prologue, addresses)?;

    #[cfg(debug_assertions)]
    for i in 1..matrix.len() {
        if matrix[i].address < matrix[i - 1].address && !matrix[i - 1].end_sequence {
            panic!(
                "Not in ascending order @ [{}] {:?} [{}] {:?}",
                i - 1,
                matrix[i - 1],
                i,
                matrix[i]
            );
        }
    }

    Ok(DebugLineCU {
        prologue,
        _standard_opcode_lengths: std_op_lengths.to_vec(),
        include_directories: inc_dirs,
        files,
        matrix,
    })
}

#[derive(Clone, Debug)]
pub(crate) struct DebugLineStates {
    pub address: Addr,
    file: usize,
    line: usize,
    column: usize,
    discriminator: u64,
    is_stmt: bool,
    basic_block: bool,
    end_sequence: bool,
    prologue_end: bool,
    should_reset: bool,
}

impl DebugLineStates {
    fn new(prologue: &DebugLinePrologue) -> DebugLineStates {
        DebugLineStates {
            address: 0,
            file: 1,
            line: 1,
            column: 0,
            discriminator: 0,
            is_stmt: prologue.default_is_stmt != 0,
            basic_block: false,
            end_sequence: false,
            prologue_end: false,
            should_reset: false,
        }
    }

    fn reset(&mut self, prologue: &DebugLinePrologue) {
        self.address = 0;
        self.file = 1;
        self.line = 1;
        self.column = 0;
        self.discriminator = 0;
        self.is_stmt = prologue.default_is_stmt != 0;
        self.basic_block = false;
        self.end_sequence = false;
        self.prologue_end = false;
        self.should_reset = false;
    }
}

/// Return `Ok((insn_bytes, emit))` if success.  `insn_bytes1 is the
/// size of the instruction at the position given by ip.  `emit` is
/// true if this instruction emit a new row to describe line
/// information of an address.  Not every instructions emit rows.
/// Some instructions create only intermediate states for the next row
/// going to emit.
fn run_debug_line_stmt(
    stmts: &[u8],
    prologue: &DebugLinePrologue,
    ip: usize,
    states: &mut DebugLineStates,
) -> Result<(usize, bool), Error> {
    // Standard opcodes
    const DW_LNS_EXT: u8 = 0;
    const DW_LNS_COPY: u8 = 1;
    const DW_LNS_ADVANCE_PC: u8 = 2;
    const DW_LNS_ADVANCE_LINE: u8 = 3;
    const DW_LNS_SET_FILE: u8 = 4;
    const DW_LNS_SET_COLUMN: u8 = 5;
    const DW_LNS_NEGATE_STMT: u8 = 6;
    const DW_LNS_SET_BASIC_BLOCK: u8 = 7;
    const DW_LNS_CONST_ADD_PC: u8 = 8;
    const DW_LNS_FIXED_ADVANCE_PC: u8 = 9;
    const DW_LNS_SET_PROLOGUE_END: u8 = 10;

    // Extended opcodes
    const DW_LINE_END_SEQUENCE: u8 = 1;
    const DW_LINE_SET_ADDRESS: u8 = 2;
    const DW_LINE_DEFINE_FILE: u8 = 3;
    const DW_LINE_SET_DISCRIMINATOR: u8 = 4;

    let opcode_base = prologue.opcode_base;
    let opcode = stmts[ip];

    match opcode {
        DW_LNS_EXT => {
            // Extended opcodes
            if let Some((insn_size, bytes)) = decode_leb128(&stmts[(ip + 1)..]) {
                if insn_size < 1 {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        format!("invalid extended opcode (ip=0x{ip:x}, insn_size=0x{insn_size:x}"),
                    ))
                }
                let ext_opcode = stmts[ip + 1 + bytes as usize];
                match ext_opcode {
                    DW_LINE_END_SEQUENCE => {
                        states.end_sequence = true;
                        states.should_reset = true;
                        Ok((1 + bytes as usize + insn_size as usize, true))
                    }
                    DW_LINE_SET_ADDRESS => match insn_size - 1 {
                        4 => {
                            let address = decode_uword(&stmts[(ip + 1 + bytes as usize + 1)..]);
                            states.address = address as Addr;
                            Ok((1 + bytes as usize + insn_size as usize, false))
                        }
                        8 => {
                            let address = decode_udword(&stmts[(ip + 1 + bytes as usize + 1)..]);
                            states.address = address as Addr;
                            Ok((1 + bytes as usize + insn_size as usize, false))
                        }
                        _ => Err(Error::new(
                            ErrorKind::Unsupported,
                            format!("unsupported address size ({insn_size})"),
                        )),
                    },
                    DW_LINE_DEFINE_FILE => Err(Error::new(
                        ErrorKind::Unsupported,
                        "DW_LINE_define_file is not supported yet",
                    )),
                    DW_LINE_SET_DISCRIMINATOR => {
                        if let Some((discriminator, discr_bytes)) =
                            decode_leb128(&stmts[(ip + 1 + bytes as usize + 1)..])
                        {
                            if discr_bytes as u64 + 1 == insn_size {
                                states.discriminator = discriminator;
                                Ok((1 + bytes as usize + insn_size as usize, false))
                            } else {
                                Err(Error::new(
                                    ErrorKind::InvalidData,
                                    "unmatched instruction size for DW_LINE_set_discriminator",
                                ))
                            }
                        } else {
                            Err(Error::new(
                                ErrorKind::InvalidData,
                                "discriminator is broken",
                            ))
                        }
                    }
                    _ => Err(Error::new(
                        ErrorKind::Unsupported,
                        format!(
                            "invalid extended opcode (ip=0x{ip:x}, ext_opcode=0x{ext_opcode:x})"
                        ),
                    )),
                }
            } else {
                Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("invalid extended opcode (ip=0x{ip:x})"),
                ))
            }
        }
        DW_LNS_COPY => Ok((1, true)),
        DW_LNS_ADVANCE_PC => {
            if let Some((adv, bytes)) = decode_leb128(&stmts[(ip + 1)..]) {
                states.address += (adv * u64::from(prologue.minimum_instruction_length)) as Addr;
                Ok((1 + bytes as usize, false))
            } else {
                Err(Error::new(
                    ErrorKind::InvalidData,
                    "the operand of advance_pc is broken",
                ))
            }
        }
        DW_LNS_ADVANCE_LINE => {
            if let Some((adv, bytes)) = decode_leb128_s(&stmts[(ip + 1)..]) {
                states.line = (states.line as i64 + adv) as usize;
                Ok((1 + bytes as usize, false))
            } else {
                Err(Error::new(
                    ErrorKind::InvalidData,
                    "the operand of advance_line is broken",
                ))
            }
        }
        DW_LNS_SET_FILE => {
            if let Some((file_idx, bytes)) = decode_leb128(&stmts[(ip + 1)..]) {
                states.file = file_idx as usize;
                Ok((1 + bytes as usize, false))
            } else {
                Err(Error::new(
                    ErrorKind::InvalidData,
                    "the operand of set_file is broken",
                ))
            }
        }
        DW_LNS_SET_COLUMN => {
            if let Some((column, bytes)) = decode_leb128(&stmts[(ip + 1)..]) {
                states.column = column as usize;
                Ok((1 + bytes as usize, false))
            } else {
                Err(Error::new(
                    ErrorKind::InvalidData,
                    "the operand of set_column is broken",
                ))
            }
        }
        DW_LNS_NEGATE_STMT => {
            states.is_stmt = !states.is_stmt;
            Ok((1, false))
        }
        DW_LNS_SET_BASIC_BLOCK => {
            states.basic_block = true;
            Ok((1, false))
        }
        DW_LNS_CONST_ADD_PC => {
            let addr_adv = (255 - opcode_base) / prologue.line_range;
            states.address += Addr::from(addr_adv * prologue.minimum_instruction_length);
            Ok((1, false))
        }
        DW_LNS_FIXED_ADVANCE_PC => {
            if (ip + 3) < stmts.len() {
                let addr_adv = decode_uhalf(&stmts[(ip + 1)..]);
                states.address +=
                    Addr::from(addr_adv * u16::from(prologue.minimum_instruction_length));
                Ok((1, false))
            } else {
                Err(Error::new(
                    ErrorKind::InvalidData,
                    "the operand of fixed_advance_pc is broken",
                ))
            }
        }
        DW_LNS_SET_PROLOGUE_END => {
            states.prologue_end = true;
            Ok((1, false))
        }
        _ => {
            // Special opcodes
            let desired_line_incr = (opcode - opcode_base) % prologue.line_range;
            let addr_adv = (opcode - opcode_base) / prologue.line_range;
            states.address += Addr::from(addr_adv * prologue.minimum_instruction_length);
            states.line = (states.line as i64
                + (desired_line_incr as i16 + prologue.line_base as i16) as i64
                    * prologue.minimum_instruction_length as i64)
                as usize;
            Ok((1, true))
        }
    }
}

fn run_debug_line_stmts(
    stmts: &[u8],
    prologue: &DebugLinePrologue,
    addresses: &[Addr],
) -> Result<Vec<DebugLineStates>, Error> {
    let mut ip = 0;
    let mut matrix = Vec::<DebugLineStates>::new();
    let mut should_sort = false;
    let mut states_cur = DebugLineStates::new(prologue);
    let mut states_last = states_cur.clone();
    let mut last_ip_pushed = false;
    let mut force_no_emit = false;

    while ip < stmts.len() {
        match run_debug_line_stmt(stmts, prologue, ip, &mut states_cur) {
            Ok((sz, emit)) => {
                ip += sz;
                if emit {
                    if states_cur.address == 0 {
                        // This is a special case. Somehow, rust
                        // compiler generate debug_line for some
                        // builtin code starting from 0.  And, it
                        // causes incorrect behavior.
                        force_no_emit = true;
                    }
                    if !force_no_emit {
                        if !addresses.is_empty() {
                            let mut pushed = false;
                            for addr in addresses {
                                if *addr == states_cur.address
                                    || (states_last.address != 0
                                        && !states_last.end_sequence
                                        && *addr < states_cur.address
                                        && *addr > states_last.address)
                                {
                                    if !last_ip_pushed && *addr != states_cur.address {
                                        // The address falls between current and last emitted row.
                                        matrix.push(states_last.clone());
                                    }
                                    matrix.push(states_cur.clone());
                                    pushed = true;
                                    break
                                }
                            }
                            last_ip_pushed = pushed;
                            states_last = states_cur.clone();
                        } else {
                            matrix.push(states_cur.clone());
                        }
                        if states_last.address > states_cur.address {
                            should_sort = true;
                        }
                    }
                }
                if states_cur.should_reset {
                    states_cur.reset(prologue);
                    force_no_emit = false;
                }
            }
            Err(e) => return Err(e),
        }
    }

    if should_sort {
        matrix.sort_by_key(|x| x.address);
    }

    Ok(matrix)
}

/// If addresses is empty, it returns a full version of debug_line matrix.
/// If addresses is not empty, return only data needed to resolve given addresses .
pub(crate) fn parse_debug_line_elf_parser(
    parser: &ElfParser,
    addresses: &[Addr],
) -> Result<Vec<DebugLineCU>, Error> {
    let debug_line_idx = parser.find_section(".debug_line")?;
    let debug_line_sz = parser.get_section_size(debug_line_idx)?;
    let mut remain_sz = debug_line_sz;
    let prologue_size: usize = mem::size_of::<DebugLinePrologueV2>();
    let mut not_found = Vec::from(addresses);

    let data = &mut parser.section_data(debug_line_idx)?;

    let mut all_cus = Vec::<DebugLineCU>::new();
    while remain_sz > prologue_size {
        let debug_line_cu = parse_debug_line_cu(data, &not_found)?;
        let prologue = &debug_line_cu.prologue;
        remain_sz -= prologue.total_length as usize + 4;

        if debug_line_cu.matrix.is_empty() {
            continue
        }

        if !addresses.is_empty() {
            let mut last_row = &debug_line_cu.matrix[0];
            for row in debug_line_cu.matrix.as_slice() {
                let mut i = 0;
                // Remove addresses found in this CU from not_found.
                while i < not_found.len() {
                    let addr = addresses[i];
                    if addr == row.address || (addr < row.address && addr > last_row.address) {
                        not_found.remove(i);
                    } else {
                        i += 1;
                    }
                }
                last_row = row;
            }

            all_cus.push(debug_line_cu);

            if not_found.is_empty() {
                return Ok(all_cus)
            }
        } else {
            all_cus.push(debug_line_cu);
        }
    }

    if remain_sz != 0 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "encountered remaining garbage data at the end",
        ))
    }

    Ok(all_cus)
}


/// The symbol information extracted out of DWARF.
#[derive(Clone, Debug)]
pub(crate) struct DWSymInfo<'a> {
    pub name: &'a str,
    pub address: Addr,
    pub size: usize,
    pub sym_type: SymbolType, // A function or a variable.
}

fn find_die_sibling(die: &mut debug_info::DIE<'_>) -> Option<usize> {
    for (name, _form, _opt, value) in die {
        if name == constants::DW_AT_sibling {
            if let debug_info::AttrValue::Unsigned(off) = value {
                return Some(off as usize)
            }
            return None
        }
    }
    None
}

/// Parse a DIE that declares a subprogram. (a function)
///
/// We already know the given DIE is a declaration of a subprogram.
/// This function trys to extract the address of the subprogram and
/// other information from the DIE.
///
/// # Arguments
///
/// * `die` - is a DIE.
/// * `str_data` - is the content of the `.debug_str` section.
///
/// Return a [`DWSymInfo`] if it finds the address of the subprogram.
fn parse_die_subprogram<'a>(
    die: &mut debug_info::DIE<'a>,
    str_data: &'a [u8],
) -> Result<Option<DWSymInfo<'a>>, Error> {
    let mut addr: Option<Addr> = None;
    let mut name_str: Option<&str> = None;
    let mut size = 0;

    for (name, _form, _opt, value) in die {
        match name {
            constants::DW_AT_linkage_name | constants::DW_AT_name => {
                if name_str.is_some() {
                    continue
                }
                name_str = Some(match value {
                    debug_info::AttrValue::Unsigned(str_off) => unsafe {
                        CStr::from_ptr(str_data[str_off as usize..].as_ptr().cast())
                            .to_str()
                            .map_err(|_e| {
                                Error::new(
                                    ErrorKind::InvalidData,
                                    "fail to extract the name of a subprogram",
                                )
                            })?
                    },
                    debug_info::AttrValue::String(s) => s,
                    _ => {
                        return Err(Error::new(
                            ErrorKind::InvalidData,
                            "fail to parse DW_AT_linkage_name {}",
                        ))
                    }
                });
            }
            constants::DW_AT_lo_pc => match value {
                debug_info::AttrValue::Unsigned(pc) => {
                    addr = Some(pc as Addr);
                }
                _ => {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "fail to parse DW_AT_lo_pc",
                    ))
                }
            },
            constants::DW_AT_hi_pc => match value {
                debug_info::AttrValue::Unsigned(sz) => {
                    size = sz;
                }
                _ => {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "fail to parse DW_AT_lo_pc",
                    ))
                }
            },
            _ => {}
        }
    }

    match (addr, name_str) {
        (Some(address), Some(name)) => Ok(Some(DWSymInfo {
            name,
            address,
            size: size as usize,
            sym_type: SymbolType::Function,
        })),
        _ => Ok(None),
    }
}

/// Walk through all DIEs of a compile unit to extract symbols.
///
/// # Arguments
///
/// * `dieiter` - is an iterator returned by the iterator that is
///               returned by an [`UnitIter`].  [`UnitIter`] returns
///               an [`UnitHeader`] and an [`DIEIter`].
/// * `str_data` - is the content of the `.debug_str` section.
/// * `found_syms` - the Vec to append the found symbols.
fn debug_info_parse_symbols_cu<'a>(
    mut dieiter: debug_info::DIEIter<'a>,
    str_data: &'a [u8],
    found_syms: &mut Vec<DWSymInfo<'a>>,
) {
    while let Some(mut die) = dieiter.next() {
        if die.tag == 0 || die.tag == constants::DW_TAG_namespace {
            continue
        }

        assert!(die.abbrev.is_some());
        if die.tag != constants::DW_TAG_subprogram {
            if die.abbrev.unwrap().has_children {
                if let Some(sibling_off) = find_die_sibling(&mut die) {
                    dieiter.seek_to_sibling(sibling_off);
                    continue
                }
                // Skip this DIE quickly, or the iterator will
                // recalculate the size of the DIE.
                die.exhaust().unwrap();
            }
            continue
        }

        if let Ok(Some(syminfo)) = parse_die_subprogram(&mut die, str_data) {
            found_syms.push(syminfo);
        }
    }
}

/// Parse the addresses of symbols from the `.debug_info` section.
///
/// # Arguments
///
/// * `parser` - is an ELF parser.
/// * `cond` - is a function to check if we have found the information
///            we need.  The function will stop earlier if the
///            condition is met.
pub(crate) fn debug_info_parse_symbols<'a>(
    parser: &'a ElfParser,
    cond: Option<&(dyn Fn(&DWSymInfo<'a>) -> bool + Send + Sync)>,
) -> Result<Vec<DWSymInfo<'a>>, Error> {
    let info_sect_idx = parser.find_section(".debug_info")?;
    let info_data = parser.section_data(info_sect_idx)?;
    let abbrev_sect_idx = parser.find_section(".debug_abbrev")?;
    let abbrev_data = parser.section_data(abbrev_sect_idx)?;
    let units = debug_info::UnitIter::new(info_data, abbrev_data);
    let str_sect_idx = parser.find_section(".debug_str")?;
    let str_data = parser.section_data(str_sect_idx)?;

    let mut syms = Vec::<DWSymInfo>::new();

    if let Some(cond) = cond {
        'outer: for (uhdr, dieiter) in units {
            if let debug_info::UnitHeader::CompileV4(_) = uhdr {
                let saved_sz = syms.len();
                debug_info_parse_symbols_cu(dieiter, str_data, &mut syms);
                for sym in &syms[saved_sz..] {
                    if !cond(sym) {
                        break 'outer
                    }
                }
            }
        }
    } else {
        for (uhdr, dieiter) in units {
            if let debug_info::UnitHeader::CompileV4(_) = uhdr {
                debug_info_parse_symbols_cu(dieiter, str_data, &mut syms);
            }
        }
    }
    Ok(syms)
}

#[cfg(test)]
mod tests {
    use super::*;

    use test_log::test;

    #[cfg(feature = "nightly")]
    use test::Bencher;


    #[allow(unused)]
    struct ArangesCU {
        debug_line_off: usize,
        aranges: Vec<(u64, u64)>,
    }

    fn parse_aranges_cu(data: &[u8]) -> Result<(ArangesCU, usize), Error> {
        if data.len() < 12 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "invalid arange header (too small)",
            ))
        }
        let len = decode_uword(data);
        let version = decode_uhalf(&data[4..]);
        let offset = decode_uword(&data[6..]);
        let addr_sz = data[10];
        let _seg_sz = data[11];

        if data.len() < (len + 4) as usize {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "data is broken (too small)",
            ))
        }

        // Size of the header
        let mut pos = 12;

        // Padding to align with the size of addresses on the target system.
        pos += addr_sz as usize - 1;
        pos -= pos % addr_sz as usize;

        let mut aranges = Vec::<(u64, u64)>::new();
        match addr_sz {
            4 => {
                while pos < (len + 4 - 8) as usize {
                    let start = decode_uword(&data[pos..]);
                    pos += 4;
                    let size = decode_uword(&data[pos..]);
                    pos += 4;

                    if start == 0 && size == 0 {
                        break
                    }
                    aranges.push((start as u64, size as u64));
                }
            }
            8 => {
                while pos < (len + 4 - 16) as usize {
                    let start = decode_udword(&data[pos..]);
                    pos += 8;
                    let size = decode_udword(&data[pos..]);
                    pos += 8;

                    if start == 0 && size == 0 {
                        break
                    }
                    aranges.push((start, size));
                }
            }
            _ => {
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    format!("unsupported address size {addr_sz} ver {version} off 0x{offset:x}"),
                ))
            }
        }

        Ok((
            ArangesCU {
                debug_line_off: offset as usize,
                aranges,
            },
            len as usize + 4,
        ))
    }

    fn parse_aranges_elf_parser(parser: &ElfParser) -> Result<Vec<ArangesCU>, Error> {
        let debug_aranges_idx = parser.find_section(".debug_aranges")?;

        let raw_data = parser.read_section_raw(debug_aranges_idx)?;

        let mut pos = 0;
        let mut acus = Vec::<ArangesCU>::new();
        while pos < raw_data.len() {
            let (acu, bytes) = parse_aranges_cu(&raw_data[pos..])?;
            acus.push(acu);
            pos += bytes;
        }

        Ok(acus)
    }

    fn parse_aranges_elf(filename: &Path) -> Result<Vec<ArangesCU>, Error> {
        let parser = ElfParser::open(filename)?;
        parse_aranges_elf_parser(&parser)
    }

    #[test]
    fn test_parse_debug_line_elf() {
        let bin_name = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-dwarf-v4.bin");

        let parser = ElfParser::open(bin_name.as_ref()).unwrap();
        let _line = parse_debug_line_elf_parser(&parser, &[]).unwrap();
    }

    #[test]
    fn test_run_debug_line_stmts_1() {
        let stmts = [
            0x00, 0x09, 0x02, 0x30, 0x8b, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xa0, 0x04,
            0x01, 0x05, 0x06, 0x0a, 0x08, 0x30, 0x02, 0x05, 0x00, 0x01, 0x01,
        ];
        let prologue = DebugLinePrologue {
            total_length: 0,
            version: 4,
            prologue_length: 0,
            minimum_instruction_length: 1,
            maximum_ops_per_instruction: 1,
            default_is_stmt: 1,
            line_base: -5,
            line_range: 14,
            opcode_base: 13,
        };

        let result = run_debug_line_stmts(&stmts, &prologue, &[]);
        if result.is_err() {
            let e = result.as_ref().err().unwrap();
            println!("result {e:?}");
        }
        assert!(result.is_ok());
        let matrix = result.unwrap();
        assert_eq!(matrix.len(), 3);
        assert_eq!(matrix[0].line, 545);
        assert_eq!(matrix[0].address, 0x18b30);
        assert_eq!(matrix[1].line, 547);
        assert_eq!(matrix[1].address, 0x18b43);
        assert_eq!(matrix[2].line, 547);
        assert_eq!(matrix[2].address, 0x18b48);
    }

    #[test]
    fn test_run_debug_line_stmts_2() {
        //	File name                            Line number    Starting address    View    Stmt
        //	    methods.rs                                   789             0x18c70               x
        //	    methods.rs                                   791             0x18c7c               x
        //	    methods.rs                                   791             0x18c81
        //	    methods.rs                                   790             0x18c86               x
        //	    methods.rs                                     0             0x18c88
        //	    methods.rs                                   791             0x18c8c               x
        //	    methods.rs                                     0             0x18c95
        //	    methods.rs                                   792             0x18c99               x
        //	    methods.rs                                   792             0x18c9d
        //	    methods.rs                                     0             0x18ca4
        //	    methods.rs                                   791             0x18ca8               x
        //	    methods.rs                                   792             0x18caf               x
        //	    methods.rs                                     0             0x18cb6
        //	    methods.rs                                   792             0x18cba
        //	    methods.rs                                     0             0x18cc4
        //	    methods.rs                                   792             0x18cc8
        //	    methods.rs                                   790             0x18cce               x
        //	    methods.rs                                   794             0x18cd0               x
        //	    methods.rs                                   794             0x18cde               x
        let stmts = [
            0x00, 0x09, 0x02, 0x70, 0x8c, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x94, 0x06,
            0x01, 0x05, 0x0d, 0x0a, 0xbc, 0x05, 0x26, 0x06, 0x58, 0x05, 0x09, 0x06, 0x57, 0x06,
            0x03, 0xea, 0x79, 0x2e, 0x05, 0x13, 0x06, 0x03, 0x97, 0x06, 0x4a, 0x06, 0x03, 0xe9,
            0x79, 0x90, 0x05, 0x0d, 0x06, 0x03, 0x98, 0x06, 0x4a, 0x05, 0x12, 0x06, 0x4a, 0x03,
            0xe8, 0x79, 0x74, 0x05, 0x13, 0x06, 0x03, 0x97, 0x06, 0x4a, 0x05, 0x12, 0x75, 0x06,
            0x03, 0xe8, 0x79, 0x74, 0x05, 0x20, 0x03, 0x98, 0x06, 0x4a, 0x03, 0xe8, 0x79, 0x9e,
            0x05, 0x12, 0x03, 0x98, 0x06, 0x4a, 0x05, 0x09, 0x06, 0x64, 0x05, 0x06, 0x32, 0x02,
            0x0e, 0x00, 0x01, 0x01,
        ];
        let prologue = DebugLinePrologue {
            total_length: 0,
            version: 4,
            prologue_length: 0,
            minimum_instruction_length: 1,
            maximum_ops_per_instruction: 1,
            default_is_stmt: 1,
            line_base: -5,
            line_range: 14,
            opcode_base: 13,
        };

        let result = run_debug_line_stmts(&stmts, &prologue, &[]);
        if result.is_err() {
            let e = result.as_ref().err().unwrap();
            println!("result {e:?}");
        }
        assert!(result.is_ok());
        let matrix = result.unwrap();

        assert_eq!(matrix.len(), 19);
        assert_eq!(matrix[0].line, 789);
        assert_eq!(matrix[0].address, 0x18c70);
        assert!(matrix[0].is_stmt);

        assert_eq!(matrix[1].line, 791);
        assert_eq!(matrix[1].address, 0x18c7c);
        assert!(matrix[1].is_stmt);

        assert_eq!(matrix[2].line, 791);
        assert_eq!(matrix[2].address, 0x18c81);
        assert!(!matrix[2].is_stmt);

        assert_eq!(matrix[13].line, 792);
        assert_eq!(matrix[13].address, 0x18cba);
        assert!(!matrix[13].is_stmt);

        assert_eq!(matrix[14].line, 0);
        assert_eq!(matrix[14].address, 0x18cc4);
        assert!(!matrix[14].is_stmt);

        assert_eq!(matrix[18].line, 794);
        assert_eq!(matrix[18].address, 0x18cde);
        assert!(matrix[18].is_stmt);
    }

    #[test]
    fn test_parse_aranges_elf() {
        let bin_name = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-dwarf-v4.bin");

        let _aranges = parse_aranges_elf(bin_name.as_ref()).unwrap();
    }

    #[test]
    fn test_debug_info_parse_symbols() {
        let bin_name = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-dwarf-v4.bin");

        let parser = ElfParser::open(bin_name.as_ref()).unwrap();
        let syms = debug_info_parse_symbols(&parser, None).unwrap();
        assert!(syms.iter().any(|sym| sym.name == "fibonacci"))
    }

    /// Benchmark the [`debug_info_parse_symbols`] function.
    #[cfg(feature = "nightly")]
    #[bench]
    fn debug_info_parse_single_threaded(b: &mut Bencher) {
        let bin_name = env::args().next().unwrap();
        let parser = ElfParser::open(bin_name.as_ref()).unwrap();

        let () = b.iter(|| debug_info_parse_symbols(&parser, None).unwrap());
    }
}
