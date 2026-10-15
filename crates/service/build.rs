//! Links the program so that Windows looks for the DLLs it imports only in
//! the program's own folder and in System32 (`/DEPENDENTLOADFLAG:0xA00`:
//! LOAD_LIBRARY_SEARCH_APPLICATION_DIR, 0x200, and
//! LOAD_LIBRARY_SEARCH_SYSTEM32, 0x800). The working folder and PATH are
//! never searched for them.
//!
//! The program's folder is needed for the Visual C++ runtime the installer
//! puts beside it (packaging/windows/vcruntime.lock). Windows loads that DLL
//! as it starts the program, before any of our code runs, so no check of
//! ours can protect that load, the service's folder check included. What
//! protects it is the install folder's access list alone: only SYSTEM,
//! Administrators and TrustedInstaller can change the folder or anything in
//! it, which the setup program sets. `tests/binary.rs` reads the flag back
//! from the linked program.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        println!("cargo:rustc-link-arg-bins=/DEPENDENTLOADFLAG:0xA00");
    }
}
