use cfg_aliases::cfg_aliases;

fn main() {
    cfg_aliases! {
        linux: { target_os = "linux" },
    }
}
