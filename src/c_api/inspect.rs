use std::alloc::alloc;
use std::alloc::dealloc;
use std::alloc::Layout;
use std::ffi::CStr;
use std::ffi::OsStr;
use std::fmt::Debug;
use std::mem;
use std::os::raw::c_char;
use std::os::unix::ffi::OsStrExt as _;
use std::ptr;

use crate::c_api::blazesym;
use crate::c_api::blazesym_sym_src_cfg;
use crate::log::error;
use crate::util::slice_from_user_array;
use crate::Addr;
use crate::SymbolInfo;
use crate::SymbolSrcCfg;
use crate::SymbolType;


/// The type of a symbol.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub enum blaze_sym_type {
    /// That type could not be determined (possibly because the source does not
    /// contains information about the type).
    BLAZE_SYM_UNKNOWN,
    /// The symbol is a function.
    BLAZE_SYM_FUNC,
    /// The symbol is a variable.
    BLAZE_SYM_VAR,
}


/// Information about a looked up symbol.
#[repr(C)]
#[derive(Debug)]
pub struct blaze_sym_info {
    pub name: *const c_char,
    pub address: Addr,
    pub size: usize,
    pub file_offset: u64,
    pub obj_file_name: *const c_char,
    pub sym_type: blaze_sym_type,
}


/// Convert [`SymbolInfo`] objects as returned by
/// [`BlazeSymbolizer::find_addrs`] to a C array.
fn convert_syms_list_to_c(syms_list: Vec<Vec<SymbolInfo>>) -> *const *const blaze_sym_info {
    let mut sym_cnt = 0;
    let mut str_buf_sz = 0;

    for syms in &syms_list {
        sym_cnt += syms.len() + 1;
        for sym in syms {
            str_buf_sz += sym.name.len() + 1;
            if let Some(fname) = sym.obj_file_name.as_ref() {
                str_buf_sz += AsRef::<OsStr>::as_ref(fname).as_bytes().len() + 1;
            }
        }
    }

    let array_sz = ((mem::size_of::<*const u64>() * syms_list.len() + mem::size_of::<u64>() - 1)
        % mem::size_of::<u64>())
        * mem::size_of::<u64>();
    let sym_buf_sz = mem::size_of::<blaze_sym_info>() * sym_cnt;
    let buf_size = array_sz + sym_buf_sz + str_buf_sz;
    let raw_buf_with_sz =
        unsafe { alloc(Layout::from_size_align(buf_size + mem::size_of::<u64>(), 8).unwrap()) };

    unsafe { *(raw_buf_with_sz as *mut u64) = buf_size as u64 };

    let raw_buf = unsafe { raw_buf_with_sz.add(mem::size_of::<u64>()) };
    let mut syms_ptr = raw_buf as *mut *mut blaze_sym_info;
    let mut sym_ptr = unsafe { raw_buf.add(array_sz) } as *mut blaze_sym_info;
    let mut str_ptr = unsafe { raw_buf.add(array_sz + sym_buf_sz) } as *mut c_char;

    for syms in syms_list {
        unsafe { *syms_ptr = sym_ptr };
        for SymbolInfo {
            name,
            address,
            size,
            sym_type,
            file_offset,
            obj_file_name,
        } in syms
        {
            let name_ptr = str_ptr.cast();
            unsafe { ptr::copy_nonoverlapping(name.as_ptr().cast(), str_ptr, name.len()) };
            str_ptr = unsafe { str_ptr.add(name.len()) };
            unsafe { *str_ptr = 0 };
            str_ptr = unsafe { str_ptr.add(1) };
            let obj_file_name = if let Some(fname) = obj_file_name.as_ref() {
                let fname = AsRef::<OsStr>::as_ref(fname).as_bytes();
                let obj_fname_ptr = str_ptr;
                unsafe { ptr::copy_nonoverlapping(fname.as_ptr().cast(), str_ptr, fname.len()) };
                str_ptr = unsafe { str_ptr.add(fname.len()) };
                unsafe { *str_ptr = 0 };
                str_ptr = unsafe { str_ptr.add(1) };
                obj_fname_ptr
            } else {
                ptr::null()
            };

            unsafe {
                (*sym_ptr) = blaze_sym_info {
                    name: name_ptr,
                    address,
                    size,
                    sym_type: match sym_type {
                        SymbolType::Function => blaze_sym_type::BLAZE_SYM_FUNC,
                        SymbolType::Variable => blaze_sym_type::BLAZE_SYM_VAR,
                        SymbolType::Unknown => blaze_sym_type::BLAZE_SYM_UNKNOWN,
                    },
                    file_offset,
                    obj_file_name,
                }
            };
            sym_ptr = unsafe { sym_ptr.add(1) };
        }
        unsafe {
            (*sym_ptr) = blaze_sym_info {
                name: ptr::null(),
                address: 0,
                size: 0,
                sym_type: blaze_sym_type::BLAZE_SYM_UNKNOWN,
                file_offset: 0,
                obj_file_name: ptr::null(),
            }
        };
        sym_ptr = unsafe { sym_ptr.add(1) };

        syms_ptr = unsafe { syms_ptr.add(1) };
    }

    raw_buf as *const *const blaze_sym_info
}


/// Find the addresses of a list of symbols.
///
/// Return an array with the same size as the input names. The caller should
/// free the returned array by calling [`blaze_syms_free`].
///
/// Every name in the input name list may have more than one address.
/// The respective entry in the returned array is an array containing
/// all addresses and ended with a null (0x0).
///
/// # Safety
///
/// The returned pointer should be free by [`blaze_syms_free`].
#[no_mangle]
pub unsafe extern "C" fn blaze_find_addrs(
    symbolizer: *mut blazesym,
    cfg: *const blazesym_sym_src_cfg,
    names: *const *const c_char,
    name_cnt: usize,
) -> *const *const blaze_sym_info {
    // SAFETY: The caller ensures that the pointer is valid.
    let symbolizer = unsafe { &*symbolizer };
    // SAFETY: The caller ensures that the pointer is valid.
    let cfg = SymbolSrcCfg::from(unsafe { &*cfg });
    // SAFETY: The caller ensures that the pointer is valid and the count
    //         matches.
    let names = unsafe { slice_from_user_array(names, name_cnt) };
    let names = names
        .iter()
        .map(|&p| {
            // SAFETY: The caller ensures that the pointer is valid.
            unsafe { CStr::from_ptr(p) }.to_str().unwrap()
        })
        .collect::<Vec<_>>();
    let result = symbolizer.find_addrs(&cfg, &names);
    match result {
        Ok(syms) => convert_syms_list_to_c(syms),
        Err(err) => {
            error!("failed to find {name_cnt} symbols: {err}");
            ptr::null()
        }
    }
}


/// Free an array returned by [`blazesym_find_addrs`].
///
/// # Safety
///
/// The pointer must be returned by [`blazesym_find_addrs`].
///
#[no_mangle]
pub unsafe extern "C" fn blaze_syms_free(syms: *const *const blaze_sym_info) {
    if syms.is_null() {
        return
    }

    let raw_buf_with_sz = unsafe { (syms as *mut u8).offset(-(mem::size_of::<u64>() as isize)) };
    let sz = unsafe { *(raw_buf_with_sz as *mut u64) } as usize + mem::size_of::<u64>();
    unsafe { dealloc(raw_buf_with_sz, Layout::from_size_align(sz, 8).unwrap()) };
}
