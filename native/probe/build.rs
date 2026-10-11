use std::process::Command;

fn main() {
    cc::Build::new().file("shim.c").compile("ocshim");
    println!("cargo:rerun-if-changed=shim.c");
    if !cfg!(windows) {
        // Linux/macOS: find the system libopenconnect through pkg-config.
        let out = Command::new("pkg-config")
            .args(["--libs-only-L", "openconnect"])
            .output()
            .expect("pkg-config");
        for tok in String::from_utf8_lossy(&out.stdout).split_whitespace() {
            if let Some(p) = tok.strip_prefix("-L") {
                println!("cargo:rustc-link-search=native={p}");
            }
        }
    }
}
