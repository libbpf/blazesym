use cfg_aliases::cfg_aliases;

fn main() {
    cfg_aliases! {
        linux: { any(target_os = "linux", target_os = "android") },
    }
}
