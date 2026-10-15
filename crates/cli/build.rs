//! Links the program so that Windows looks for the DLLs it imports only in
//! System32 (`/DEPENDENTLOADFLAG:0x800`, LOAD_LIBRARY_SEARCH_SYSTEM32). The
//! program's own folder, the working folder and PATH are never searched
//! for them. `tests/binary.rs` reads the flag back from the linked program.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        println!("cargo:rustc-link-arg-bins=/DEPENDENTLOADFLAG:0x800");
    }
}
