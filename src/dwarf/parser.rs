#[cfg(test)]
use std::env;
use std::ffi::OsStr;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::io::Error;
use std::io::ErrorKind;
use std::io::Result;
use std::mem;
use std::path::Path;

use gimli::constants;
use gimli::read::AttributeValue;
use gimli::read::DebugAbbrev;
use gimli::read::DebugInfo;
use gimli::read::DebugStr;
use gimli::read::EndianSlice;
use gimli::read::UnitHeader;
use gimli::Abbreviations;
use gimli::DebuggingInformationEntry;
use gimli::LittleEndian;
use gimli::Section as _;
use gimli::SectionId;
use gimli::UnitSectionOffset;

use crate::elf::ElfParser;
use crate::inspect::SymType;
use crate::log::warn;
use crate::util::decode_leb128;
use crate::util::decode_leb128_s;
use crate::util::decode_udword;
use crate::util::decode_uhalf;
use crate::util::decode_uword;
use crate::util::find_match_or_lower_bound_by_key;
use crate::util::Pod;
use crate::util::ReadRaw as _;
use crate::Addr;


/// The gimli reader type we currently use. Could be made generic if
/// need be, but we keep things simple while we can.
type R<'dat> = EndianSlice<'dat, LittleEndian>;


fn format_offset(offset: UnitSectionOffset<usize>) -> String {
    match offset {
        UnitSectionOffset::DebugInfoOffset(o) => {
            format!(".debug_info+0x{:08x}", o.0)
        }
        UnitSectionOffset::DebugTypesOffset(o) => {
            format!(".debug_types+0x{:08x}", o.0)
        }
    }
}


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
    pub(crate) fn find_line(&self, addr: Addr) -> Option<(&Path, &OsStr, usize)> {
        let idx = find_match_or_lower_bound_by_key(&self.matrix, addr, |dls| dls.addr)?;
        let states = &self.matrix[idx];
        if states.end_sequence {
            // This is the first byte after the last instruction
            return None
        }

        self.stringify_row(idx)
    }

    pub(crate) fn stringify_row(&self, idx: usize) -> Option<(&Path, &OsStr, usize)> {
        let states = &self.matrix[idx];
        let (dir, file) = {
            if states.file > 0 {
                let file = &self.files[states.file - 1];
                let dir = {
                    if file.dir_idx == 0 {
                        Path::new("")
                    } else {
                        Path::new(&self.include_directories[file.dir_idx as usize - 1])
                    }
                };
                (dir, OsStr::new(&file.name))
            } else {
                (Path::new(""), OsStr::new(""))
            }
        };

        Some((dir, file, states.line))
    }
}

/// Parse the list of directory paths for a CU.
fn parse_debug_line_dirs(data: &mut &[u8]) -> Result<Vec<String>> {
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
fn parse_debug_line_files(data: &mut &[u8]) -> Result<Vec<DebugLineFileInfo>> {
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

fn parse_debug_line_cu(data: &mut &[u8], addresses: &[Addr]) -> Result<DebugLineCU> {
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
        if matrix[i].addr < matrix[i - 1].addr && !matrix[i - 1].end_sequence {
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
    pub addr: Addr,
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
            addr: 0,
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
        self.addr = 0;
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
) -> Result<(usize, bool)> {
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
                            let addr = decode_uword(&stmts[(ip + 1 + bytes as usize + 1)..]);
                            states.addr = addr as Addr;
                            Ok((1 + bytes as usize + insn_size as usize, false))
                        }
                        8 => {
                            let addr = decode_udword(&stmts[(ip + 1 + bytes as usize + 1)..]);
                            states.addr = addr as Addr;
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
                states.addr += (adv * u64::from(prologue.minimum_instruction_length)) as Addr;
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
            states.addr += Addr::from(addr_adv * prologue.minimum_instruction_length);
            Ok((1, false))
        }
        DW_LNS_FIXED_ADVANCE_PC => {
            if (ip + 3) < stmts.len() {
                let addr_adv = decode_uhalf(&stmts[(ip + 1)..]);
                states.addr +=
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
            let opcode_offset = opcode.checked_sub(opcode_base).ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidData,
                    format!("DWARF based opcode offset is invalid (opcode: {opcode}, base: {opcode_base})"),
                )
            })?;
            let desired_line_incr = opcode_offset % prologue.line_range;
            let addr_adv = opcode_offset / prologue.line_range;
            states.addr += Addr::from(addr_adv * prologue.minimum_instruction_length);
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
) -> Result<Vec<DebugLineStates>> {
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
                    if states_cur.addr == 0 {
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
                                if *addr == states_cur.addr
                                    || (states_last.addr != 0
                                        && !states_last.end_sequence
                                        && *addr < states_cur.addr
                                        && *addr > states_last.addr)
                                {
                                    if !last_ip_pushed && *addr != states_cur.addr {
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
                        if states_last.addr > states_cur.addr {
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
        matrix.sort_by_key(|x| x.addr);
    }

    Ok(matrix)
}

/// If addresses is empty, it returns a full version of debug_line matrix.
/// If addresses is not empty, return only data needed to resolve given addresses.
pub(crate) fn parse_debug_line_elf_parser(
    parser: &ElfParser,
    addresses: &[Addr],
) -> Result<Vec<DebugLineCU>> {
    let debug_line_idx = parser.find_section(".debug_line")?.ok_or_else(|| {
        Error::new(
            ErrorKind::NotFound,
            "unable to find ELF section .debug_line",
        )
    })?;
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
                    if addr == row.addr || (addr < row.addr && addr > last_row.addr) {
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
    pub addr: Addr,
    pub size: usize,
    pub sym_type: SymType, // A function or a variable.
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
// TODO: Having a single function for a single subprogram may not be
//       sufficient to get all relevant symbol information. See
//       https://stackoverflow.com/a/59674438
// TODO: We likely need to handle DW_AT_ranges; see
//       https://reviews.llvm.org/D78489
fn parse_die_subprogram<'dat>(
    entry: &DebuggingInformationEntry<R<'dat>>,
    debug_str: &DebugStr<R<'dat>>,
) -> Result<Option<DWSymInfo<'dat>>> {
    let mut addr = None;
    let mut name = None;
    let mut size = None;
    let mut high_pc = None;
    let mut linkage_name = None;

    let mut attrs = entry.attrs();
    while let Some(attr) = attrs.next().map_err(|err| {
        Error::new(
            ErrorKind::InvalidData,
            format!("failed to read next DIE attribute: {err}"),
        )
    })? {
        match attr.name() {
            constants::DW_AT_linkage_name | constants::DW_AT_name => {
                let attr_name = || {
                    attr.name()
                        .static_string()
                        .unwrap_or("DW_AT_name/DW_AT_linkage_name")
                };

                let name_slice = match attr.value() {
                    AttributeValue::String(string) => string,
                    AttributeValue::DebugStrRef(..) => {
                        let string = attr.string_value(debug_str).ok_or_else(|| {
                            Error::new(
                                ErrorKind::InvalidData,
                                format!(
                                    "encountered invalid string reference in {} attribute",
                                    attr_name()
                                ),
                            )
                        })?;
                        string
                    }
                    _ => {
                        warn!("encountered unexpected attribute value for {}", attr_name());
                        continue
                    }
                };

                let name_ = name_slice.to_string().map_err(|err| {
                    Error::new(
                        ErrorKind::InvalidData,
                        format!(
                            "{} attribute does not contain valid string: {err}",
                            attr_name()
                        ),
                    )
                })?;
                if attr.name() == constants::DW_AT_name {
                    name = Some(name_);
                } else {
                    linkage_name = Some(name_);
                }
            }
            constants::DW_AT_low_pc => match attr.value() {
                AttributeValue::Addr(addr_) => {
                    addr = Some(addr_);
                }
                _ => {
                    warn!(
                        "encountered unexpected attribute for {}",
                        attr.name().static_string().unwrap_or("DW_AT_low_pc")
                    );
                    continue
                }
            },
            constants::DW_AT_high_pc => match attr.value() {
                AttributeValue::Addr(addr) => {
                    high_pc = Some(addr);
                }
                AttributeValue::Data8(offset) => {
                    // It's an offset from "low_pc", i.e., the size.
                    size = Some(offset);
                }
                _ => {
                    warn!(
                        "encountered unexpected attribute for {}",
                        attr.name().static_string().unwrap_or("DW_AT_high_pc")
                    );
                    continue
                }
            },
            _ => (),
        }
    }

    name = name.or(linkage_name);
    size = match (size, addr, high_pc) {
        (None, Some(low_pc), Some(high_pc)) => high_pc.checked_sub(low_pc),
        _ => size,
    };

    match (addr, name) {
        (Some(addr), Some(name)) => Ok(Some(DWSymInfo {
            name,
            addr: addr as Addr,
            // TODO: `size` really should be an `Option` inside
            //       `DWSymInfo`.
            size: size.unwrap_or(0) as usize,
            sym_type: SymType::Function,
        })),
        _ => Ok(None),
    }
}

/// Walk through all DIEs of a compile unit to extract symbols.
fn debug_info_parse_symbols_cu<'dat>(
    unit: UnitHeader<R<'dat>>,
    abbrevs: &Abbreviations,
    debug_str: &DebugStr<R<'dat>>,
    found_syms: &mut Vec<DWSymInfo<'dat>>,
) -> Result<()> {
    let mut entries = unit.entries(abbrevs);
    while let Some((_, entry)) = entries.next_dfs().map_err(|err| {
        Error::new(
            ErrorKind::InvalidData,
            format!("failed to find next DIE: {err}"),
        )
    })? {
        if entry.tag() == constants::DW_TAG_subprogram {
            if let Some(sym) = parse_die_subprogram(entry, debug_str)? {
                let () = found_syms.push(sym);
            }
        }
    }
    Ok(())
}


fn load_section(parser: &ElfParser, id: SectionId) -> Result<R<'_>> {
    let result = parser.find_section(id.name());
    let data = match result {
        Ok(Some(idx)) => parser.section_data(idx)?,
        // Make sure to return empty data if a section does not exist.
        Ok(None) => &[],
        Err(err) => return Err(err),
    };
    let reader = EndianSlice::new(data, LittleEndian);
    Ok(reader)
}


/// Parse the addresses of symbols from the `.debug_info` section.
///
/// # Arguments
///
/// * `parser` - is an ELF parser.
pub(crate) fn debug_info_parse_symbols(parser: &ElfParser) -> Result<Vec<DWSymInfo<'_>>> {
    let debug_abbrev_data = load_section(parser, DebugAbbrev::<R>::id())?;
    let debug_info_data = load_section(parser, DebugInfo::<R>::id())?;
    let debug_str_data = load_section(parser, DebugStr::<R>::id())?;
    let debug_abbrev = DebugAbbrev::from(debug_abbrev_data);
    let debug_info = DebugInfo::from(debug_info_data);
    let debug_str = DebugStr::from(debug_str_data);
    let mut units = debug_info.units();
    let mut syms = Vec::new();

    while let Some(unit) = units.next().map_err(|err| {
        Error::new(
            ErrorKind::InvalidData,
            format!("failed to iterate DWARF units: {err}"),
        )
    })? {
        let abbrevs = unit.abbreviations(&debug_abbrev).map_err(|err| {
            Error::new(
                ErrorKind::InvalidData,
                format!(
                    "failed to retrieve abbreviations for unit header @ {}: {err}",
                    format_offset(unit.offset())
                ),
            )
        })?;

        let () = debug_info_parse_symbols_cu(unit, &abbrevs, &debug_str, &mut syms)?;
    }
    Ok(syms)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "nightly")]
    use std::hint::black_box;

    use test_log::test;

    #[cfg(feature = "nightly")]
    use test::Bencher;


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
        assert_eq!(matrix[0].addr, 0x18b30);
        assert_eq!(matrix[1].line, 547);
        assert_eq!(matrix[1].addr, 0x18b43);
        assert_eq!(matrix[2].line, 547);
        assert_eq!(matrix[2].addr, 0x18b48);
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
        assert_eq!(matrix[0].addr, 0x18c70);
        assert!(matrix[0].is_stmt);

        assert_eq!(matrix[1].line, 791);
        assert_eq!(matrix[1].addr, 0x18c7c);
        assert!(matrix[1].is_stmt);

        assert_eq!(matrix[2].line, 791);
        assert_eq!(matrix[2].addr, 0x18c81);
        assert!(!matrix[2].is_stmt);

        assert_eq!(matrix[13].line, 792);
        assert_eq!(matrix[13].addr, 0x18cba);
        assert!(!matrix[13].is_stmt);

        assert_eq!(matrix[14].line, 0);
        assert_eq!(matrix[14].addr, 0x18cc4);
        assert!(!matrix[14].is_stmt);

        assert_eq!(matrix[18].line, 794);
        assert_eq!(matrix[18].addr, 0x18cde);
        assert!(matrix[18].is_stmt);
    }

    #[test]
    fn test_debug_info_parse_symbols() {
        let binaries = [
            "test-dwarf-v2.bin",
            "test-dwarf-v3.bin",
            "test-dwarf-v4.bin",
            "test-dwarf-v5.bin",
        ];

        for binary in binaries {
            let bin_name = Path::new(&env!("CARGO_MANIFEST_DIR"))
                .join("data")
                .join(binary);

            let parser = ElfParser::open(bin_name.as_ref()).unwrap();
            let syms = debug_info_parse_symbols(&parser).unwrap();
            assert!(syms.iter().any(|sym| sym.name == "fibonacci"))
        }
    }

    /// Benchmark the [`debug_info_parse_symbols`] function.
    #[cfg(feature = "nightly")]
    #[bench]
    fn debug_info_parse_single_threaded(b: &mut Bencher) {
        let bin_name = env::args().next().unwrap();
        let parser = ElfParser::open(bin_name.as_ref()).unwrap();

        let () = b.iter(|| debug_info_parse_symbols(black_box(&parser)).unwrap());
    }
}
