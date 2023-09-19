use std::cmp::min;
use std::mem::size_of;
use std::mem::transmute;
use std::ptr;

use blazesym::symbolize::Process;
use blazesym::symbolize::Source;
use blazesym::symbolize::Sym;
use blazesym::symbolize::Symbolizer;
use blazesym::Addr;
use blazesym::Pid;


fn symbolize_current_bt() {
    assert_eq!(size_of::<*mut libc::c_void>(), size_of::<Addr>());
    // Retrieve up to 64 stack frames of the calling thread.
    const MAX_CNT: usize = 64;

    let mut bt_buf = [ptr::null_mut::<libc::c_void>(); MAX_CNT];
    let bt_cnt = unsafe { libc::backtrace(bt_buf.as_mut_ptr(), MAX_CNT as _) } as usize;
    let bt = &bt_buf[0..min(bt_cnt, MAX_CNT)];
    let bt = unsafe { transmute::<&[*mut libc::c_void], &[Addr]>(bt) };

    // Symbolize the addresses for the current process, as that's where
    // they were captured.
    let src = Source::Process(Process::new(Pid::Slf));
    let symbolizer = Symbolizer::new();

    let syms = symbolizer.symbolize(&src, bt).unwrap();
    let addrs = bt;
    let addr_width = 16;
    let mut prev_addr_idx = None;

    for (sym, addr_idx) in syms {
        if let Some(idx) = prev_addr_idx {
            // Print a line for all addresses that did not get symbolized.
            for input_addr in addrs.iter().take(addr_idx).skip(idx + 1) {
                println!("{input_addr:#0width$x}: <no-symbol>", width = addr_width)
            }
        }

        let Sym {
            name,
            addr,
            offset,
            code_info,
            ..
        } = &sym;

        let src_loc = if let Some(code_info) = code_info {
            let path = code_info.to_path();
            let path = path.display();

            match (code_info.line, code_info.column) {
                (Some(line), Some(col)) => format!(" {path}:{line}:{col}"),
                (Some(line), None) => format!(" {path}:{line}"),
                (None, _) => format!(" {path}"),
            }
        } else {
            String::new()
        };

        if prev_addr_idx != Some(addr_idx) {
            // If the address index changed we reached a new symbol.
            println!(
                "{input_addr:#0width$x}: {name} @ {addr:#x}+{offset:#x}{src_loc}",
                input_addr = addrs[addr_idx],
                width = addr_width
            );
        } else {
            // Otherwise we are dealing with an inlined call.
            println!(
                "{:width$}  {name} @ {addr:#x}+{offset:#x}{src_loc}",
                " ",
                width = addr_width
            );
        }

        prev_addr_idx = Some(addr_idx);
    }
}


#[inline(never)]
fn f() {
    g()
}

#[inline(never)]
fn g() {
    h()
}

#[inline(never)]
fn h() {
    symbolize_current_bt()
}

fn main() {
    f();
}
