//! The service's folder check: verdicts on access lists written in SDDL,
//! and the check run on real folders of this computer.

use windows_sys::Win32::Security::{
    GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, SECURITY_ATTRIBUTES,
};
use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;

use super::super::security::{Descriptor, wide};
use super::*;

/// `C:\` and `C:\Program Files` on Windows 11 24H2, as `Get-Acl` gives them.
const DRIVE_ROOT: &str = "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;;LC;;;AU)(A;OICIIO;SDGXGWGR;;;AU)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;;0x1000a1;;;S-1-15-3-65536-1888954469-739942743-1668119174-2468466756-4239452838-1296943325-355587736-700089176)";
const PROGRAM_FILES: &str = "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;OICIIO;GA;;;CO)(A;OICIIO;GA;;;SY)(A;;0x1301bf;;;SY)(A;OICIIO;GA;;;BA)(A;;0x1301bf;;;BA)(A;OICIIO;GXGR;;;BU)(A;;0x1200a9;;;BU)(A;CIIO;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x1200a9;;;AC)(A;OICIIO;GXGR;;;AC)(A;;0x1200a9;;;S-1-15-2-2)(A;OICIIO;GXGR;;;S-1-15-2-2)";
/// A folder made inside Program Files by an elevated administrator: what it
/// inherits, with the creator's entry given to Administrators.
const INSTALLED: &str = "O:BAD:AI(A;OICIID;GA;;;SY)(A;ID;0x1301bf;;;SY)(A;OICIIOID;GA;;;BA)(A;ID;0x1301bf;;;BA)(A;OICIIOID;GXGR;;;BU)(A;ID;0x1200a9;;;BU)(A;OICIIOID;GA;;;CO)";

/// The owner and access entries of a descriptor written in SDDL.
fn parsed(sddl: &str) -> (String, Option<Vec<Entry>>) {
    let descriptor = Descriptor::parse(sddl).unwrap();
    let (mut owner, mut defaulted) = (null_mut(), 0);
    let (mut present, mut dacl) = (0, null_mut());
    // SAFETY: the descriptor is valid and the out pointers are valid.
    unsafe {
        assert_ne!(
            GetSecurityDescriptorOwner(descriptor.as_ptr(), &mut owner, &mut defaulted),
            0
        );
        assert_ne!(
            GetSecurityDescriptorDacl(descriptor.as_ptr(), &mut present, &mut dacl, &mut defaulted),
            0
        );
    }
    let owner = sid_text(owner).unwrap();
    let dacl = (present != 0 && !dacl.is_null()).then(|| entries(dacl).unwrap());
    (owner, dacl)
}

fn verdict(sddl: &str, rights: u32) -> Option<String> {
    let (owner, dacl) = parsed(sddl);
    judge(&owner, dacl.as_deref(), rights)
}

// A stock drive root and Program Files pass as folders above the service,
// and a folder installed in Program Files passes as the service's own.
#[test]
fn a_normal_install_passes() {
    assert_eq!(verdict(DRIVE_ROOT, REPLACE), None, "the drive root");
    assert_eq!(verdict(PROGRAM_FILES, REPLACE), None, "Program Files");
    assert_eq!(verdict(PROGRAM_FILES, CHANGE), None, "Program Files");
    assert_eq!(verdict(INSTALLED, CHANGE), None, "the installed folder");
    // Owned by SYSTEM, Administrators or TrustedInstaller alike.
    assert_eq!(verdict("O:SYD:P(A;;FA;;;SY)", CHANGE), None);
}

// Security rule: the service does not run from a folder anyone else could
// change, or from under a folder in which anyone else could swap it.
#[test]
fn a_folder_others_could_change_is_refused() {
    // The drive root lets users add folders. Fine above the service, not as
    // the service's own folder.
    assert!(verdict(DRIVE_ROOT, CHANGE).is_some());
    let refused_anywhere = [
        // Owned by an ordinary user, as a folder /D= made would be.
        "O:S-1-5-21-1-2-3-1001D:P(A;OICI;FA;;;SY)",
        // Users have full control, or may change the access list, take
        // ownership, delete it, or delete what is in it (0x40).
        "O:BAD:P(A;;FA;;;BU)",
        "O:BAD:P(A;;WD;;;BU)",
        "O:BAD:P(A;;WO;;;AU)",
        "O:BAD:P(A;;SD;;;WD)",
        "O:BAD:P(A;;0x40;;;BU)",
        "O:BAD:P(A;;GA;;;AU)",
        // An inherit-only entry counts for nothing, but the same entry
        // without the flag does.
        "O:BAD:P(A;OICI;GA;;;CO)",
        // No access list at all: anyone may do anything.
        "O:BAD:NO_ACCESS_CONTROL",
        // Entry kinds the check does not read.
        "O:BAD:P(A;;FA;;;SY)(OA;;FA;;;BU)",
        "O:BAD:P(A;;FA;;;SY)(XA;;FA;;;BU;(Member_of {SID(BA)}))",
    ];
    for sddl in refused_anywhere {
        assert!(verdict(sddl, REPLACE).is_some(), "above: {sddl}");
        assert!(verdict(sddl, CHANGE).is_some(), "own: {sddl}");
    }
    // Adding files or folders, or writing, is refused in the service's own
    // folder only.
    for sddl in [
        "O:BAD:P(A;;0x2;;;BU)",
        "O:BAD:P(A;;0x4;;;BU)",
        "O:BAD:P(A;;GW;;;BU)",
    ] {
        assert!(verdict(sddl, CHANGE).is_some(), "own: {sddl}");
        assert_eq!(verdict(sddl, REPLACE), None, "above: {sddl}");
    }
}

#[test]
fn says_who_could_change_it() {
    let why = verdict("O:S-1-5-21-1-2-3-1001D:P(A;;FA;;;SY)", CHANGE).unwrap();
    assert!(why.contains("owned by S-1-5-21-1-2-3-1001"), "{why}");
    let why = verdict("O:BAD:P(A;;0x2;;;BU)", CHANGE).unwrap();
    assert!(why.contains("S-1-5-32-545 may change it"), "{why}");
}

// On this computer: everything above Program Files passes, and a folder
// every user may change is refused.
#[test]
fn checks_real_folders() {
    let program_files = std::env::var_os("ProgramFiles").expect("ProgramFiles is set");
    let inside = Path::new(&program_files)
        .join("nothing-here")
        .join("program.exe");
    // The folders above are checked first, and pass; then the missing one.
    match check(&inside) {
        Err(Error::NotFound) => {}
        other => panic!("{:?}", other.err()),
    }

    let open_to_all = std::env::temp_dir().join(format!("ubc-vpn-open-{}", std::process::id()));
    let descriptor =
        Descriptor::parse("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;BU)").unwrap();
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.as_ptr(),
        bInheritHandle: 0,
    };
    let name = wide(&open_to_all.to_string_lossy());
    // SAFETY: the name is NUL-terminated, and it and the attributes, with
    // the descriptor they point to, outlive the call.
    assert_ne!(unsafe { CreateDirectoryW(name.as_ptr(), &attributes) }, 0);
    let checked = check(&open_to_all.join("program.exe"));
    std::fs::remove_dir(&open_to_all).unwrap();
    let Err(Error::Failed(why)) = checked else {
        panic!("a folder every user may change passed");
    };
    assert!(why.contains("not safe"), "{why}");
}

#[test]
fn a_relative_path_is_refused() {
    assert!(check(Path::new("program.exe")).is_err());
}

/// Makes `path` with the access list `sddl`, or says why not.
fn make_folder(path: &Path, sddl: &str) -> std::result::Result<(), u32> {
    let descriptor = Descriptor::parse(sddl).unwrap();
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.as_ptr(),
        bInheritHandle: 0,
    };
    let name = wide(&path.to_string_lossy());
    // SAFETY: the name is NUL-terminated, and it and the attributes, with the
    // descriptor they point to, outlive the call.
    match unsafe { CreateDirectoryW(name.as_ptr(), &attributes) } {
        0 => Err(last_error()),
        _ => Ok(()),
    }
}

// Security rule: a folder only administrators may change is still refused
// when a folder above it lets others swap it. Making a folder owned by the
// Administrators group needs an elevated process; CI has one.
#[test]
fn a_safe_folder_inside_an_open_one_is_refused() {
    let open = std::env::temp_dir().join(format!("ubc-vpn-open-above-{}", std::process::id()));
    make_folder(&open, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;BU)").unwrap();
    let safe = open.join("safe");
    let made = make_folder(&safe, "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
    let checked = made.map(|()| check(&safe.join("program.exe")));
    let _ = std::fs::remove_dir(&safe);
    std::fs::remove_dir(&open).unwrap();
    let checked = match checked {
        Ok(checked) => checked,
        // ERROR_INVALID_OWNER: this process may not make Administrators the owner.
        Err(1307) => {
            let required = std::env::var_os("UBC_VPN_REQUIRE_ELEVATED").is_some();
            assert!(
                !required,
                "making a folder Administrators own needs an elevated process, and this run requires it"
            );
            println!("SKIPPED: making a folder Administrators own needs an elevated process");
            return;
        }
        Err(code) => panic!("making the folder: Windows error {code}"),
    };
    let Err(Error::Failed(why)) = checked else {
        panic!("a folder under one every user may change passed");
    };
    assert!(why.contains(&*open.to_string_lossy()), "{why}");
    println!("RAN: program folder");
}

/// A new folder under ProgramData that only SYSTEM and the administrators
/// may change, or nothing, with a message, when this process may not make
/// one: making Administrators the owner needs an elevated process.
fn safe_folder(tag: &str) -> Option<std::path::PathBuf> {
    let program_data = std::env::var_os("ProgramData").expect("ProgramData is set");
    let folder =
        Path::new(&program_data).join(format!("ubc-vpn-test-{tag}-{}", std::process::id()));
    match make_folder(
        &folder,
        "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)",
    ) {
        Ok(()) => Some(folder),
        // ERROR_INVALID_OWNER: this process may not make Administrators the owner.
        Err(1307) => {
            let required = std::env::var_os("UBC_VPN_REQUIRE_ELEVATED").is_some();
            assert!(
                !required,
                "a folder Administrators own needs an elevated process, and this run requires it"
            );
            println!("SKIPPED: a folder Administrators own needs an elevated process");
            None
        }
        Err(code) => panic!("making the folder: Windows error {code}"),
    }
}

// Security rule: every file in the service's folder is checked. One that
// Users may write is refused, though the folder itself is safe.
#[test]
fn a_file_others_could_change_is_refused() {
    let Some(folder) = safe_folder("open-file") else {
        return;
    };
    let file = folder.join("libsomething.dll");
    std::fs::write(&file, b"not a library").unwrap();
    // Before Users may write it, the folder passes.
    let before = check(&folder.join("program.exe")).map(drop);
    let granted = std::process::Command::new("icacls")
        .arg(&file)
        .args(["/grant", "*S-1-5-32-545:M", "/Q"])
        .status()
        .unwrap();
    let after = check(&folder.join("program.exe")).map(drop);
    std::fs::remove_dir_all(&folder).unwrap();
    assert!(granted.success());
    before.expect("the folder before the file was opened to Users");
    let Err(Error::Failed(why)) = after else {
        panic!("a file Users may change passed");
    };
    assert!(
        why.contains("libsomething.dll") && why.contains("S-1-5-32-545"),
        "{why}"
    );
    println!("RAN: program file");
}

// Security rule: a link in the path is refused, even one an administrator
// made that points to a safe folder.
#[test]
fn a_link_in_the_path_is_refused() {
    let Some(folder) = safe_folder("link") else {
        return;
    };
    let real = folder.join("real");
    std::fs::create_dir(&real).unwrap();
    let link = folder.join("link");
    let made = std::process::Command::new("cmd")
        .args(["/c", "mklink", "/J"])
        .arg(&link)
        .arg(&real)
        .stdout(std::process::Stdio::null())
        .status()
        .unwrap();
    let through_real = check(&real.join("program.exe")).map(drop);
    let through_link = check(&link.join("program.exe")).map(drop);
    let _ = std::fs::remove_dir(&link);
    std::fs::remove_dir_all(&folder).unwrap();
    assert!(made.success());
    through_real.expect("the folder the link points to");
    let Err(Error::Failed(why)) = through_link else {
        panic!("a path through a link passed");
    };
    assert!(why.contains("is a link"), "{why}");
    println!("RAN: program link");
}
