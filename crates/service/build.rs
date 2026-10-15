//! Links the program so that Windows looks for the DLLs it imports only in
//! the program's own folder and in System32 (`/DEPENDENTLOADFLAG:0xA00`:
//! LOAD_LIBRARY_SEARCH_APPLICATION_DIR, 0x200, and
//! LOAD_LIBRARY_SEARCH_SYSTEM32, 0x800). The working folder and PATH are
//! never searched for them.
//!
//! The program's folder is needed for the Visual C++ runtime the installer
//! puts beside it (packaging/windows/vcruntime.lock). That folder is the
//! install folder, which only administrators can change and which the
//! service checks before it starts. `tests/binary.rs` reads the flag back
//! from the linked program.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        println!("cargo:rustc-link-arg-bins=/DEPENDENTLOADFLAG:0xA00");
    }
}
