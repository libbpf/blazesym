#![no_std]
#![no_main]

use core::hint::black_box;


#[inline(never)]
fn uninlined_call() -> usize {
    let x = 1337;
    x + 42
}

#[inline(always)]
fn inlined_call() -> usize {
    uninlined_call()
}

#[inline(never)]
fn test_function() -> usize {
    let x = inlined_call();
    x
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let _x = black_box(test_function());
    loop {}
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
