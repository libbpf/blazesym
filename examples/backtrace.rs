use blazesym::symbolize::Process;
use blazesym::symbolize::Source;
use blazesym::symbolize::SymbolizedResult;
use blazesym::symbolize::Symbolizer;
use blazesym::Addr;
use blazesym::Pid;
use std::cmp::min;
use std::mem::size_of;
use std::mem::transmute;
use std::ptr;


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

    let bt_syms = symbolizer.symbolize(&src, bt).unwrap();
    for (addr, syms) in bt.iter().zip(bt_syms) {
        match &syms[..] {
            [] => println!("0x{addr:016x}: <no-symbols>"),
            [sym] => {
                let SymbolizedResult {
                    symbol,
                    addr,
                    path,
                    line,
                    ..
                } = sym;
                println!(
                    "0x{addr:016x} {symbol} @ 0x{addr:x} {}:{line}",
                    path.display()
                );
            }
            syms => {
                // One address may get several results.
                println!("0x{addr:016x} ({} entries)", syms.len());

                for sym in syms {
                    let SymbolizedResult {
                        symbol,
                        addr,
                        path,
                        line,
                        ..
                    } = sym;
                    println!("    {symbol} @ 0x{addr:016x} {}:{line}", path.display());
                }
            }
        }
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
