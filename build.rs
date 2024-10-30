use std::env;


fn main() {
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    if target_os == "linux" || target_os == "android" {
        println!("cargo:rustc-cfg=linux");
    }
    println!("cargo:rustc-check-cfg=cfg(linux)");
}
