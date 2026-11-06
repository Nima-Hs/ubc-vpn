//! The store over Credential Manager. The tests named `real_`, and the phases
//! `real_across_new_logons` runs, use the real one, under a throwaway service
//! name with made-up passwords, only on CI and only when the workflow asks:
//! never on anyone's own machine, where the real saved passwords are. The
//! others call nothing in the OS.

use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED;
use windows_sys::Win32::Security::Credentials::{
    CRED_PERSIST_ENTERPRISE, CRED_PRESERVE_CREDENTIAL_BLOB, CredEnumerateW,
};
use windows_sys::Win32::UI::Shell::FOLDERID_RoamingAppData;

use super::super::{INDEX, Kept, SERVICE, Saved, Secrets};
use super::*;

const PROFILE: &str = "11111111111111111111111111111111";
const OTHER: &str = "22222222222222222222222222222222";
/// As it would be stored: the form, a made-up username and password.
const VALUE: &str = "ubc-vpn 1\nuser.dept@app\nmade-up-pass-é€𝄞";
const PASSWORD: &str = "made-up-pass-é€𝄞";
const NEWER: &str = "ubc-vpn 1\nuser.dept@app\nmade-up-pass-0002";

thread_local! {
    /// How many credentials this thread has wiped and given back.
    static WIPED: Cell<usize> = const { Cell::new(0) };
    /// How many more writes and deletes will work: after that, as after a
    /// crash, none does.
    static STEPS_LEFT: Cell<u32> = const { Cell::new(0) };
    /// Which write from now, counting from 1, does what it is told not to.
    static NTH_WRITE: Cell<u32> = const { Cell::new(0) };
}

/// Called as a [`Found`] goes, after its value is wiped.
pub(super) fn wiped(blob: &[u8]) {
    assert!(blob.iter().all(|byte| *byte == 0));
    WIPED.with(|wiped| wiped.set(wiped.get() + 1));
}

/// Whether a workflow has asked for the real Credential Manager. Quietly
/// otherwise, without the word the workflow looks for.
fn asked() -> bool {
    std::env::var_os("CI").is_some() && std::env::var_os("UBC_VPN_REAL_KEYRING").is_some()
}

/// A service name for one test, or `None` when the real Credential Manager is
/// not to be touched.
fn throwaway(test: &str) -> Option<String> {
    asked().then(|| format!("{SERVICE}.test-{}-{test}", std::process::id()))
}

fn target_of(service: &str, account: &str) -> Vec<u16> {
    wide(&format!("{account}.{service}"))
}

fn spare_of(service: &str, account: &str) -> Vec<u16> {
    wide(&format!("{account}.{service}.moving"))
}

/// Writes an entry under `target` as the `keyring` crate 3.6.3 did, at the
/// given type. Its source writes these same fields, with this comment.
fn plant_at(target: &[u16], account: &str, blob: &[u8], persist: u32) {
    let (mut target, mut username) = (target.to_vec(), wide(account));
    let mut comment = wide("keyring v3.6.3");
    let mut alias = wide("");
    let mut blob = blob.to_vec();
    let credential = CREDENTIALW {
        Flags: 0,
        Type: CRED_TYPE_GENERIC,
        TargetName: target.as_mut_ptr(),
        Comment: comment.as_mut_ptr(),
        LastWritten: FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        },
        CredentialBlobSize: blob.len() as u32,
        CredentialBlob: blob.as_mut_ptr(),
        Persist: persist,
        AttributeCount: 0,
        Attributes: null_mut(),
        TargetAlias: alias.as_mut_ptr(),
        UserName: username.as_mut_ptr(),
    };
    write_credential(&credential).unwrap();
}

/// An entry the old code left.
fn plant_old(service: &str, account: &str, value: &str) {
    let target = target_of(service, account);
    plant_at(&target, account, &blob_of(value), CRED_PERSIST_ENTERPRISE);
}

/// A spare, as a move that stopped leaves it.
fn plant_spare(service: &str, account: &str, value: &str) {
    let target = spare_of(service, account);
    let persist = CRED_PERSIST_LOCAL_MACHINE;
    plant_at(&target, account, &blob_of(value), persist);
}

/// What `target` really holds: its type, value and username.
fn stored_at(target: &[u16]) -> Option<(u32, Vec<u8>, String)> {
    let found = Found::read(target).unwrap()?;
    let username = found.credential().UserName;
    // SAFETY: the OS ended this string in a nul, and this stops there.
    let length = (0..)
        .take_while(|n| unsafe { *username.add(*n) } != 0)
        .count();
    // SAFETY: as above, `length` units on.
    let username = unsafe { std::slice::from_raw_parts(username, length) };
    Some((
        found.persist(),
        found.blob().to_vec(),
        String::from_utf16(username).unwrap(),
    ))
}

fn stored(service: &str, account: &str) -> Option<(u32, Vec<u8>, String)> {
    stored_at(&target_of(service, account))
}

/// That `account` holds `value` on this computer, or nothing, with no spare.
#[track_caller]
fn assert_kept(service: &str, account: &str, value: Option<&str>) {
    let held = stored(service, account).map(|(persist, blob, _)| (persist, blob));
    let expected = value.map(|value| (CRED_PERSIST_LOCAL_MACHINE, blob_of(value).to_vec()));
    assert_eq!(held, expected, "{account}");
    assert_eq!(
        stored_at(&spare_of(service, account)),
        None,
        "{account}'s spare"
    );
}

/// How many credentials Windows lists under this target. One entry at any
/// type is one: a move must not leave a second copy behind.
fn copies(service: &str, account: &str) -> u32 {
    let target = target_of(service, account);
    let (mut count, mut list) = (0, null_mut());
    // SAFETY: the name ends in a nul, and the others are places to write to.
    if unsafe { CredEnumerateW(target.as_ptr(), 0, &mut count, &mut list) } == 0 {
        return 0;
    }
    // SAFETY: the call gave this pointer, and nothing uses it after.
    unsafe { CredFree(list.cast()) };
    count
}

fn with_write(service: &str, write: fn(&CREDENTIALW) -> Os<()>) -> Credentials {
    Credentials {
        write,
        ..Credentials::new(service)
    }
}

fn with_limit(service: &str, limit: fn() -> Os<u32>) -> Credentials {
    Credentials {
        limit,
        ..Credentials::new(service)
    }
}

fn step_taken() -> Os<()> {
    let left = STEPS_LEFT.get();
    if left == 0 {
        return Err(ERROR_ACCESS_DENIED);
    }
    STEPS_LEFT.set(left - 1);
    Ok(())
}

fn write_until_crash(credential: &CREDENTIALW) -> Os<()> {
    step_taken()?;
    write_credential(credential)
}

fn delete_until_crash(target: &[u16]) -> Os<()> {
    step_taken()?;
    delete_credential(target)
}

/// A store in a process that stops after `steps` writes and deletes.
fn crashing_after(service: &str, steps: u32) -> Credentials {
    STEPS_LEFT.set(steps);
    Credentials {
        write: write_until_crash,
        delete: delete_until_crash,
        ..Credentials::new(service)
    }
}

fn saved(password: &str) -> Saved {
    Saved {
        username: "user.dept@app".to_string(),
        password: Secret::new(password),
        in_doubt: false,
    }
}

fn secrets(service: &str) -> Arc<dyn Secrets> {
    Arc::new(Kept::new(Credentials::new(service)))
}

// A new save stays on this computer: the entry and the index, in the form the
// old code wrote, so an older copy of the program could still read it.
#[test]
fn real_a_new_save_stays_on_this_computer() {
    let Some(service) = throwaway("new") else {
        return;
    };
    let secrets = secrets(&service);
    secrets.save(PROFILE, &saved(PASSWORD)).unwrap();
    let (persist, blob, username) = stored(&service, PROFILE).unwrap();
    assert_eq!(persist, CRED_PERSIST_LOCAL_MACHINE);
    assert_eq!(username, PROFILE);
    let units: Vec<u8> = VALUE.encode_utf16().flat_map(u16::to_le_bytes).collect();
    assert_eq!(blob, units);
    assert_kept(&service, INDEX, Some(PROFILE));
    let read = secrets.load(PROFILE).unwrap().unwrap();
    assert_eq!(read.password.expose(), PASSWORD);
    ubc_vpn_test_lines::whole_line!("RAN: credential a new save");
}

// An entry and an index the old code left are moved on the first use, even
// one that asks for something else, with what they hold unchanged.
#[test]
fn real_an_old_entry_moves_with_its_value_unchanged() {
    let Some(service) = throwaway("move") else {
        return;
    };
    plant_old(&service, INDEX, &format!("{PROFILE}\n{OTHER}"));
    plant_old(&service, PROFILE, VALUE);
    plant_old(&service, OTHER, VALUE);
    let before = [INDEX, PROFILE, OTHER].map(|account| stored(&service, account).unwrap());
    assert!(
        before
            .iter()
            .all(|(persist, ..)| *persist == CRED_PERSIST_ENTERPRISE)
    );

    let secrets = secrets(&service);
    let read = secrets.load(PROFILE).unwrap().unwrap();
    assert_eq!(read.password.expose(), PASSWORD);

    for (account, (_, blob, username)) in [INDEX, PROFILE, OTHER].into_iter().zip(before) {
        let (persist, after, name) = stored(&service, account).unwrap();
        assert_eq!(persist, CRED_PERSIST_LOCAL_MACHINE, "{account}");
        assert_eq!(after, blob, "{account}");
        assert_eq!(name, username, "{account}");
        assert_eq!(copies(&service, account), 1, "{account}");
        assert_eq!(stored_at(&spare_of(&service, account)), None, "{account}");
    }
    assert_eq!(secrets.saved().unwrap(), [PROFILE, OTHER]);
    ubc_vpn_test_lines::whole_line!("RAN: credential an old entry moves");
}

fn refuses(_: &CREDENTIALW) -> Os<()> {
    Err(ERROR_ACCESS_DENIED)
}

// Forgetting works on an entry of either type and on its spare. This store's
// writes all fail here, so what is deleted is still of the old type.
#[test]
fn real_forgetting_works_on_both_types() {
    let Some(service) = throwaway("forget") else {
        return;
    };
    let store = Credentials::new(&service);
    plant_old(&service, PROFILE, VALUE);
    store.delete(PROFILE).unwrap();
    assert_kept(&service, PROFILE, None);
    store.set(PROFILE, VALUE).unwrap();
    assert_kept(&service, PROFILE, Some(VALUE));
    store.delete(PROFILE).unwrap();
    assert_kept(&service, PROFILE, None);
    // None there is fine.
    store.delete(PROFILE).unwrap();

    // Every form at once, and a spare by itself.
    plant_old(&service, PROFILE, VALUE);
    plant_spare(&service, PROFILE, VALUE);
    store.delete(PROFILE).unwrap();
    assert_kept(&service, PROFILE, None);
    plant_spare(&service, PROFILE, VALUE);
    store.delete(PROFILE).unwrap();
    assert_kept(&service, PROFILE, None);

    plant_old(&service, INDEX, PROFILE);
    plant_old(&service, PROFILE, VALUE);
    let stuck = Kept::new(with_write(&service, refuses));
    stuck.forget(PROFILE).unwrap();
    assert_kept(&service, PROFILE, None);
    assert_kept(&service, INDEX, None);

    plant_old(&service, INDEX, OTHER);
    plant_old(&service, OTHER, VALUE);
    plant_spare(&service, OTHER, VALUE);
    let stuck = Kept::new(with_write(&service, refuses));
    stuck.forget_all().unwrap();
    assert_kept(&service, OTHER, None);
    assert_kept(&service, INDEX, None);
    ubc_vpn_test_lines::whole_line!("RAN: credential forgetting");
}

// Security rule: a failed move loses nothing and blocks nothing. The old entry
// stays as it was and still logs in, and the next run moves it.
#[test]
fn real_a_failed_write_keeps_the_old_entry() {
    let Some(service) = throwaway("failed") else {
        return;
    };
    plant_old(&service, INDEX, PROFILE);
    plant_old(&service, PROFILE, VALUE);
    let before = stored(&service, PROFILE).unwrap();

    let stuck = with_write(&service, refuses);
    assert!(matches!(stuck.migrate(PROFILE), Err(Error::Failed(_))));
    assert_eq!(stored(&service, PROFILE).unwrap(), before);

    let stuck: Arc<dyn Secrets> = Arc::new(Kept::new(stuck));
    let read = stuck.load(PROFILE).unwrap().unwrap();
    assert_eq!(read.password.expose(), PASSWORD);
    assert_eq!(stuck.saved().unwrap(), [PROFILE]);
    assert_eq!(stored(&service, PROFILE).unwrap(), before);

    let read = secrets(&service).load(PROFILE).unwrap().unwrap();
    assert_eq!(read.password.expose(), PASSWORD);
    assert_kept(&service, PROFILE, Some(VALUE));
    ubc_vpn_test_lines::whole_line!("RAN: credential a failed write");
}

/// What each write and delete a move makes leaves behind: the entry's type if
/// it is there, and whether a spare is.
const MOVE: [(Option<u32>, bool); 5] = [
    (Some(CRED_PERSIST_ENTERPRISE), false),
    (Some(CRED_PERSIST_ENTERPRISE), true),
    (None, true),
    (Some(CRED_PERSIST_LOCAL_MACHINE), true),
    (Some(CRED_PERSIST_LOCAL_MACHINE), false),
];

// Security rule: the move's four steps come in this order, so a crash after any
// of them leaves a copy that can be read at once, and the next run finishes.
#[test]
fn real_a_crash_after_each_step_keeps_the_password() {
    let Some(service) = throwaway("crash") else {
        return;
    };
    for (steps, (entry, spare)) in MOVE.into_iter().enumerate() {
        let account = format!("step{steps}");
        plant_old(&service, &account, VALUE);
        let crashing = crashing_after(&service, steps as u32);
        let result = crashing.migrate(&account);
        assert_eq!(result.is_ok(), steps == 4, "{account}");
        let held = stored(&service, &account).map(|(persist, ..)| persist);
        assert_eq!(held, entry, "{account}");
        let spare_there = stored_at(&spare_of(&service, &account)).is_some();
        assert_eq!(spare_there, spare, "{account}");

        let store = Credentials::new(&service);
        assert_eq!(store.get(&account).unwrap().unwrap().expose(), VALUE);
        store.migrate(&account).unwrap();
        assert_kept(&service, &account, Some(VALUE));
    }
    ubc_vpn_test_lines::whole_line!("RAN: credential a crash after each step");
}

/// The value a write that is told to go wrong puts there instead.
fn nth_garbled(credential: &CREDENTIALW) -> Os<()> {
    let nth = NTH_WRITE.get();
    NTH_WRITE.set(nth.saturating_sub(1));
    if nth != 1 {
        return write_credential(credential);
    }
    let mut blob = blob_of(NEWER);
    let other = CREDENTIALW {
        CredentialBlob: blob.as_mut_ptr(),
        CredentialBlobSize: blob.len() as u32,
        ..*credential
    };
    write_credential(&other)
}

fn nth_does_nothing(credential: &CREDENTIALW) -> Os<()> {
    let nth = NTH_WRITE.get();
    NTH_WRITE.set(nth.saturating_sub(1));
    match nth {
        1 => Ok(()),
        _ => write_credential(credential),
    }
}

fn nth_at_old_type(credential: &CREDENTIALW) -> Os<()> {
    let nth = NTH_WRITE.get();
    NTH_WRITE.set(nth.saturating_sub(1));
    write_credential(&CREDENTIALW {
        Persist: match nth {
            1 => CRED_PERSIST_ENTERPRISE,
            _ => credential.Persist,
        },
        ..*credential
    })
}

// Security rule: "the write worked" is not taken on trust. If the spare does
// not read back as the same value on this computer the old entry is not
// deleted; if the entry does not, the spare is kept.
#[test]
fn real_each_write_of_a_move_is_read_back() {
    let Some(service) = throwaway("confirm") else {
        return;
    };
    for write in [nth_garbled, nth_does_nothing, nth_at_old_type] {
        plant_old(&service, PROFILE, VALUE);
        NTH_WRITE.set(1);
        let store = with_write(&service, write);
        assert!(store.migrate(PROFILE).is_err());
        let (persist, blob, _) = stored(&service, PROFILE).unwrap();
        assert_eq!(persist, CRED_PERSIST_ENTERPRISE);
        assert_eq!(blob, blob_of(VALUE).to_vec());
        Credentials::new(&service).migrate(PROFILE).unwrap();
        assert_kept(&service, PROFILE, Some(VALUE));
        Credentials::new(&service).delete(PROFILE).unwrap();

        plant_old(&service, PROFILE, VALUE);
        NTH_WRITE.set(2);
        assert!(store.migrate(PROFILE).is_err());
        let (_, blob, _) = stored_at(&spare_of(&service, PROFILE)).unwrap();
        assert_eq!(blob, blob_of(VALUE).to_vec());
        Credentials::new(&service).delete(PROFILE).unwrap();
    }
    ubc_vpn_test_lines::whole_line!("RAN: credential each write is read back");
}

// What a crash leaves, whichever came last. An entry on this computer wins over
// a spare. Otherwise a spare with no entry becomes it, and an entry of the old
// type is what the user last had.
#[test]
fn real_a_leftover_spare_is_settled() {
    let Some(service) = throwaway("leftover") else {
        return;
    };
    let store = Credentials::new(&service);

    store.set("wins", VALUE).unwrap();
    plant_spare(&service, "wins", NEWER);
    assert_eq!(store.get("wins").unwrap().unwrap().expose(), VALUE);
    store.migrate("wins").unwrap();
    assert_kept(&service, "wins", Some(VALUE));

    plant_spare(&service, "alone", NEWER);
    assert_eq!(store.get("alone").unwrap().unwrap().expose(), NEWER);
    store.migrate("alone").unwrap();
    assert_kept(&service, "alone", Some(NEWER));

    plant_old(&service, "old", VALUE);
    plant_spare(&service, "old", NEWER);
    assert_eq!(store.get("old").unwrap().unwrap().expose(), VALUE);
    store.migrate("old").unwrap();
    assert_kept(&service, "old", Some(VALUE));

    // A new password takes a leftover spare with it.
    plant_spare(&service, "saved", VALUE);
    store.set("saved", NEWER).unwrap();
    assert_kept(&service, "saved", Some(NEWER));

    // Nothing there and nothing to do are not failures, and write nothing.
    let stuck = with_write(&service, refuses);
    stuck.migrate("nothing").unwrap();
    assert_kept(&service, "nothing", None);
    stuck.migrate("wins").unwrap();
    ubc_vpn_test_lines::whole_line!("RAN: credential a leftover spare");
}

// Security rule: a spare is no account. It is not in the index, and an account
// that really ends in the spare's word has an entry and a spare of its own.
#[test]
fn real_a_spare_is_never_an_account() {
    let Some(service) = throwaway("names") else {
        return;
    };
    const NAMED: &str = "abc.moving";
    let secrets = secrets(&service);
    secrets.save("abc", &saved("made-up-pass-0003")).unwrap();
    plant_spare(&service, "abc", VALUE);
    assert_eq!(secrets.saved().unwrap(), ["abc"]);
    assert!(secrets.load(NAMED).unwrap().is_none());

    secrets.save(NAMED, &saved(PASSWORD)).unwrap();
    assert_eq!(secrets.saved().unwrap(), ["abc", NAMED]);
    let read = secrets.load(NAMED).unwrap().unwrap();
    assert_eq!(read.password.expose(), PASSWORD);
    let read = secrets.load("abc").unwrap().unwrap();
    assert_eq!(read.password.expose(), "made-up-pass-0003");
    // The account's own target name is not the other's spare's.
    assert_ne!(target_of(&service, NAMED), spare_of(&service, "abc"));

    secrets.forget("abc").unwrap();
    assert_kept(&service, "abc", None);
    assert_eq!(secrets.saved().unwrap(), [NAMED]);
    let read = secrets.load(NAMED).unwrap().unwrap();
    assert_eq!(read.password.expose(), PASSWORD);
    secrets.forget_all().unwrap();
    assert_kept(&service, NAMED, None);
    ubc_vpn_test_lines::whole_line!("RAN: credential a spare is no account");
}

fn no_session() -> Os<u32> {
    Err(ERROR_NO_SUCH_LOGON_SESSION)
}

fn keeps_nothing() -> Os<u32> {
    Ok(CRED_PERSIST_NONE)
}

fn session_only() -> Os<u32> {
    Ok(CRED_PERSIST_SESSION)
}

fn limit_fails() -> Os<u32> {
    Err(ERROR_ACCESS_DENIED)
}

// Security rule: a session that cannot keep credentials is a keyring that
// cannot be used, and nothing is read, written or deleted. One that keeps them
// only until sign-out is never given a password to save.
#[test]
fn real_a_session_that_keeps_nothing_is_no_keyring() {
    let Some(service) = throwaway("session") else {
        return;
    };
    plant_old(&service, PROFILE, VALUE);
    let before = stored(&service, PROFILE).unwrap();
    for limit in [no_session, keeps_nothing] {
        let store = with_limit(&service, limit);
        assert!(matches!(store.get(PROFILE), Err(Error::Unsupported)));
        assert!(matches!(store.set(PROFILE, "x"), Err(Error::Unsupported)));
        assert!(matches!(store.delete(PROFILE), Err(Error::Unsupported)));
        assert!(matches!(store.migrate(PROFILE), Err(Error::Unsupported)));
        assert_eq!(stored(&service, PROFILE).unwrap(), before);
    }
    let store = with_limit(&service, limit_fails);
    assert!(matches!(store.get(PROFILE), Err(Error::Failed(_))));

    let store = with_limit(&service, session_only);
    assert!(matches!(store.set(PROFILE, "x"), Err(Error::Unsupported)));
    assert!(matches!(store.migrate(PROFILE), Err(Error::Unsupported)));
    assert_eq!(stored(&service, PROFILE).unwrap(), before);
    assert_eq!(store.get(PROFILE).unwrap().unwrap().expose(), VALUE);
    store.delete(PROFILE).unwrap();
    assert_eq!(stored(&service, PROFILE), None);
    ubc_vpn_test_lines::whole_line!("RAN: credential a session keeping nothing");
}

// The runner's session may keep credentials on the computer, as a normal
// sign-in does; the rest of these tests rest on that.
#[test]
fn real_this_session_may_keep_credentials() {
    if !asked() {
        return;
    }
    let limit = session_limit().unwrap();
    assert!(limit >= CRED_PERSIST_LOCAL_MACHINE, "{limit}");
    assert!(limit <= CRED_PERSIST_ENTERPRISE, "{limit}");
    ubc_vpn_test_lines::whole_line!("RAN: credential the session's limit");
}

// Security rule: every credential read is wiped before it is given back.
// `wiped` above checks each one.
#[test]
fn real_what_is_read_is_wiped() {
    let Some(service) = throwaway("wiped") else {
        return;
    };
    let store = Credentials::new(&service);
    store.set(PROFILE, VALUE).unwrap();
    let before = WIPED.get();
    assert_eq!(store.get(PROFILE).unwrap().unwrap().expose(), VALUE);
    assert_eq!(WIPED.get(), before + 1);
    ubc_vpn_test_lines::whole_line!("RAN: credential what is read is wiped");
}

// What is not UTF-16 text is not one of this product's: no password, no error.
#[test]
fn real_what_is_not_text_is_no_entry() {
    let Some(service) = throwaway("text") else {
        return;
    };
    let persist = CRED_PERSIST_LOCAL_MACHINE;
    plant_at(&target_of(&service, PROFILE), PROFILE, &[0x61], persist);
    let store = Credentials::new(&service);
    assert!(store.get(PROFILE).unwrap().is_none());
    assert!(store.get(OTHER).unwrap().is_none());
    ubc_vpn_test_lines::whole_line!("RAN: credential what is not text");
}

/// What a new logon runs of this program.
const LOGON_PHASE: &str = "secrets::credentials::tests::logon_phase";

/// Starts this program again as the throwaway user, in a logon of its own. The
/// password stays in this process's environment and the script's memory, never
/// on a command line or in a file, and the phase is not given it.
const NEW_LOGON: &str = r"
$ErrorActionPreference = 'Stop'
$secure = ConvertTo-SecureString $env:UBC_VPN_TEST_PASSWORD -AsPlainText -Force
$credential = [pscredential]::new($env:UBC_VPN_TEST_USER, $secure)
Remove-Item Env:UBC_VPN_TEST_PASSWORD
$phase = Start-Process $env:LOGON_PROGRAM -Credential $credential -LoadUserProfile -Wait -PassThru `
  -WorkingDirectory $env:LOGON_DIR -ArgumentList '--exact', $env:LOGON_TEST, '--nocapture' `
  -RedirectStandardOutput $env:LOGON_OUT -RedirectStandardError $env:LOGON_ERR
exit $phase.ExitCode
";

// Security rule: what happens to an entry must still hold at the next logon,
// because that is when Windows reads its files again. Nothing in one logon can
// show this: an entry moved the obvious way reads as moved until then.
//
// Each phase runs in a new logon of a throwaway user, from a copy of this
// program it can read.
#[test]
fn real_across_new_logons() {
    let Some(service) = throwaway("logons") else {
        return;
    };
    assert!(
        std::env::var_os("UBC_VPN_TEST_USER").is_some()
            && std::env::var_os("UBC_VPN_TEST_PASSWORD").is_some(),
        "the workflow must name a throwaway user"
    );
    let dir = PathBuf::from(format!(
        r"C:\Users\Public\ubc-vpn-logons-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let grant = std::process::Command::new("icacls")
        .arg(&dir)
        .args(["/grant", "Users:(OI)(CI)M"])
        .output()
        .unwrap();
    assert!(grant.status.success());
    let program = dir.join("phases.exe");
    std::fs::copy(std::env::current_exe().unwrap(), &program).unwrap();
    for phase in 1..=3 {
        let (out, err) = (
            dir.join(format!("{phase}.out")),
            dir.join(format!("{phase}.err")),
        );
        let run = std::process::Command::new("pwsh")
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                NEW_LOGON,
            ])
            .env("LOGON_PROGRAM", &program)
            .env("LOGON_DIR", &dir)
            .env("LOGON_TEST", LOGON_PHASE)
            .env("LOGON_OUT", &out)
            .env("LOGON_ERR", &err)
            .env("LOGON_PHASE", phase.to_string())
            .env("LOGON_SERVICE", &service)
            .output()
            .unwrap();
        let said = std::fs::read_to_string(&out).unwrap_or_default();
        let complaint = std::fs::read_to_string(&err).unwrap_or_default();
        let finished = format!("PHASE {phase} HELD");
        assert!(
            run.status.success() && said.lines().any(|line| line == finished),
            "phase {phase}: {run:?}\n{said}\n{complaint}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
    ubc_vpn_test_lines::whole_line!("RAN: credential across new logons");
}

/// What ends up where, for the entries a phase checks.
struct Expected {
    account: &'static str,
    value: Option<&'static str>,
}

const fn holds(account: &'static str, value: &'static str) -> Expected {
    Expected {
        account,
        value: Some(value),
    }
}

const fn gone(account: &'static str) -> Expected {
    Expected {
        account,
        value: None,
    }
}

/// Everything the first logon did, as every later logon must find it.
const SETTLED: [Expected; 11] = [
    holds("moved", VALUE),
    gone("moved-forgotten"),
    gone("moved-forgotten-twice"),
    holds("moved-replaced", NEWER),
    holds("replaced", NEWER),
    holds("deleted-replaced", NEWER),
    gone("old-forgotten"),
    holds("new", VALUE),
    gone("new-forgotten"),
    gone("replaced-forgotten"),
    gone("spare-forgotten"),
];

/// A crash after each write and delete of a save over an old entry, and what
/// is read afterwards: the new password only once the old one has gone, since
/// until then the entry is what the user last had.
const CRASHED_SAVE: [&str; 5] = [VALUE, VALUE, NEWER, NEWER, NEWER];

/// The account of a crash after `steps` in a move.
fn crashed_move(steps: u32) -> String {
    format!("crashed-move-{steps}")
}

fn crashed_save(steps: u32) -> String {
    format!("crashed-save-{steps}")
}

fn crashed_forget(steps: u32) -> String {
    format!("crashed-forget-{steps}")
}

/// What Windows keeps files of, for the throwaway user: its own roaming folder.
fn roaming_files() -> Vec<std::ffi::OsString> {
    let folder = crate::os::known_folder(&FOLDERID_RoamingAppData, false).unwrap();
    let files = std::fs::read_dir(folder.join(r"Microsoft\Credentials"));
    let mut names: Vec<_> = files
        .map(|files| files.flatten().map(|file| file.file_name()).collect())
        .unwrap_or_default();
    names.sort();
    names
}

fn roaming_snapshot(dir: &Path) -> PathBuf {
    dir.join("roaming.txt")
}

fn roaming_text() -> String {
    let names = roaming_files();
    let names = names.iter().map(|name| name.to_string_lossy().into_owned());
    names.collect::<Vec<_>>().join("\n")
}

/// Moves an entry the obvious way, in place, as Windows lets it be done: what
/// the rest of this store must not do. Not used for any entry but the checks
/// that a new logon really is one.
fn move_in_place(service: &str, account: &str) {
    let target = target_of(service, account);
    let old = Found::read(&target).unwrap().unwrap();
    let keeping = CREDENTIALW {
        Persist: CRED_PERSIST_LOCAL_MACHINE,
        CredentialBlob: null_mut(),
        CredentialBlobSize: 0,
        ..*old.credential()
    };
    // SAFETY: as in `write_credential`.
    let written = unsafe { CredWriteW(&keeping, CRED_PRESERVE_CREDENTIAL_BLOB) };
    assert_ne!(written, 0);
}

/// The ways of writing an entry in place that a new logon undoes, each of which
/// this store must avoid. Each comes back as the old entry. If these stop
/// holding, either Windows changed, and this store could be simpler, or these
/// phases are no longer new logons, and they prove nothing.
fn plant_undone_by_a_new_logon(service: &str) {
    let plant = |account| plant_old(service, account, VALUE);
    plant("in-place");
    move_in_place(service, "in-place");
    plant("in-place-deleted");
    move_in_place(service, "in-place-deleted");
    delete_credential(&target_of(service, "in-place-deleted")).unwrap();
    plant("in-place-deleted-twice");
    move_in_place(service, "in-place-deleted-twice");
    delete_credential(&target_of(service, "in-place-deleted-twice")).unwrap();
    let _ = delete_credential(&target_of(service, "in-place-deleted-twice"));
    plant("in-place-deleted-rewritten");
    let target = target_of(service, "in-place-deleted-rewritten");
    move_in_place(service, "in-place-deleted-rewritten");
    delete_credential(&target).unwrap();
    let persist = CRED_PERSIST_LOCAL_MACHINE;
    plant_at(
        &target,
        "in-place-deleted-rewritten",
        &blob_of(VALUE),
        persist,
    );
    plant("in-place-replaced");
    move_in_place(service, "in-place-replaced");
    let target = target_of(service, "in-place-replaced");
    plant_at(&target, "in-place-replaced", &blob_of(NEWER), persist);
    plant("written-over");
    let target = target_of(service, "written-over");
    plant_at(&target, "written-over", &blob_of(NEWER), persist);
}

const UNDONE: [&str; 6] = [
    "in-place",
    "in-place-deleted",
    "in-place-deleted-twice",
    "in-place-deleted-rewritten",
    "in-place-replaced",
    "written-over",
];

/// One logon of [`real_across_new_logons`]. Quietly nothing unless it started
/// this, so that a run of the whole suite does not touch anything.
#[test]
fn logon_phase() {
    let (Some(phase), Some(service)) = (
        std::env::var("LOGON_PHASE").ok(),
        std::env::var("LOGON_SERVICE").ok(),
    ) else {
        return;
    };
    assert!(asked(), "only a workflow may run this");
    let service = &service[..];
    let dir = std::env::current_exe().unwrap();
    let snapshot = roaming_snapshot(dir.parent().unwrap());
    match &phase[..] {
        "1" => first_logon(service, &snapshot),
        "2" => second_logon(service, &snapshot),
        "3" => third_logon(service),
        other => panic!("{other}"),
    }
    println!("PHASE {phase} HELD");
}

fn index_service(service: &str) -> String {
    format!("{service}.index")
}

fn names_service(service: &str) -> String {
    format!("{service}.names")
}

fn first_logon(service: &str, snapshot: &Path) {
    std::fs::write(snapshot, roaming_text()).unwrap();
    let store = Credentials::new(service);
    let plant = |account| plant_old(service, account, VALUE);

    plant("moved");
    store.migrate("moved").unwrap();

    plant("moved-forgotten");
    store.migrate("moved-forgotten").unwrap();
    store.delete("moved-forgotten").unwrap();

    plant("moved-forgotten-twice");
    store.migrate("moved-forgotten-twice").unwrap();
    store.delete("moved-forgotten-twice").unwrap();
    store.delete("moved-forgotten-twice").unwrap();

    plant("moved-replaced");
    store.migrate("moved-replaced").unwrap();
    store.set("moved-replaced", NEWER).unwrap();

    plant("replaced");
    store.set("replaced", NEWER).unwrap();

    plant("deleted-replaced");
    store.delete("deleted-replaced").unwrap();
    store.set("deleted-replaced", NEWER).unwrap();

    plant("old-forgotten");
    store.delete("old-forgotten").unwrap();

    store.set("new", VALUE).unwrap();

    store.set("new-forgotten", VALUE).unwrap();
    store.delete("new-forgotten").unwrap();

    plant("replaced-forgotten");
    store.set("replaced-forgotten", NEWER).unwrap();
    store.delete("replaced-forgotten").unwrap();

    plant("spare-forgotten");
    plant_spare(service, "spare-forgotten", VALUE);
    store.delete("spare-forgotten").unwrap();

    // A crash after each step, of a move, of a new password over an old entry
    // and of forgetting.
    for steps in 0..5 {
        let account = crashed_move(steps);
        plant_old(service, &account, VALUE);
        let _ = crashing_after(service, steps).migrate(&account);
        let account = crashed_save(steps);
        plant_old(service, &account, VALUE);
        let _ = crashing_after(service, steps).set(&account, NEWER);
    }
    for steps in 0..3 {
        let account = crashed_forget(steps);
        store.set(&account, VALUE).unwrap();
        plant_spare(service, &account, VALUE);
        let _ = crashing_after(service, steps).delete(&account);
    }

    // A leftover spare, whichever came last.
    store.set("real-wins", VALUE).unwrap();
    plant_spare(service, "real-wins", NEWER);
    plant_spare(service, "spare-alone", NEWER);
    plant("old-over-spare");
    plant_spare(service, "old-over-spare", NEWER);

    // The index itself, stopped half way through its move.
    let index = &index_service(service);
    plant_old(index, INDEX, "abc\ndef");
    plant_old(index, "abc", VALUE);
    plant_old(index, "def", VALUE);
    let _ = crashing_after(index, 2).migrate(INDEX);

    // An account that really ends in the spare's word, beside a leftover spare.
    let names = &names_service(service);
    let secrets = self::secrets(names);
    secrets.save("abc", &saved(PASSWORD)).unwrap();
    secrets
        .save("abc.moving", &saved("made-up-pass-0002"))
        .unwrap();
    plant_spare(names, "abc", NEWER);
}

fn check_settled(service: &str) {
    for Expected { account, value } in SETTLED {
        assert_kept(service, account, value);
    }
}

fn second_logon(service: &str, snapshot: &Path) {
    let store = Credentials::new(service);
    check_settled(service);

    // Each crash left something that can be read at once, and this run finishes.
    for steps in 0..5 {
        let account = crashed_move(steps);
        assert_eq!(store.get(&account).unwrap().unwrap().expose(), VALUE);
        store.migrate(&account).unwrap();
        assert_kept(service, &account, Some(VALUE));

        let account = crashed_save(steps);
        let expected = CRASHED_SAVE[steps as usize];
        assert_eq!(store.get(&account).unwrap().unwrap().expose(), expected);
        store.migrate(&account).unwrap();
        assert_kept(service, &account, Some(expected));
    }

    // Stopped with the entry still there, forgetting has not happened, and can
    // be said again. Stopped with it gone, it has. No spare brings it back.
    for steps in 0..3 {
        let account = crashed_forget(steps);
        let expected = (steps < 2).then_some(VALUE);
        let spare = stored_at(&spare_of(service, &account));
        assert_eq!(spare.is_some(), steps == 0, "{account}");
        let read = store.get(&account).unwrap();
        assert_eq!(read.as_ref().map(Secret::expose), expected, "{account}");
        store.migrate(&account).unwrap();
        assert_kept(service, &account, expected);
    }

    assert_eq!(store.get("real-wins").unwrap().unwrap().expose(), VALUE);
    store.migrate("real-wins").unwrap();
    assert_kept(service, "real-wins", Some(VALUE));
    assert_eq!(store.get("spare-alone").unwrap().unwrap().expose(), NEWER);
    store.migrate("spare-alone").unwrap();
    assert_kept(service, "spare-alone", Some(NEWER));
    assert_eq!(
        store.get("old-over-spare").unwrap().unwrap().expose(),
        VALUE
    );
    store.migrate("old-over-spare").unwrap();
    assert_kept(service, "old-over-spare", Some(VALUE));

    // With the index found through its spare and moved, so is what it names.
    let index = &index_service(service);
    let secrets = self::secrets(index);
    assert_eq!(secrets.saved().unwrap(), ["abc", "def"]);
    assert_kept(index, INDEX, Some("abc\ndef"));
    assert_kept(index, "abc", Some(VALUE));
    assert_kept(index, "def", Some(VALUE));

    let names = &names_service(service);
    let secrets = self::secrets(names);
    assert_eq!(secrets.saved().unwrap(), ["abc", "abc.moving"]);
    let read = secrets.load("abc").unwrap().unwrap();
    assert_eq!(read.password.expose(), PASSWORD);
    assert_kept(names, "abc", Some(VALUE));
    let read = secrets.load("abc.moving").unwrap().unwrap();
    assert_eq!(read.password.expose(), "made-up-pass-0002");

    // Every old entry this run made has gone from the folder that roams. The
    // folder may hold files of an earlier run's, which Windows can tidy away
    // at a logon, so only what is new counts.
    let before = std::fs::read_to_string(snapshot).unwrap();
    let before: Vec<&str> = before.lines().collect();
    let now = roaming_text();
    let new: Vec<&str> = now.lines().filter(|name| !before.contains(name)).collect();
    assert!(new.is_empty(), "left in the roaming folder: {new:?}");

    plant_undone_by_a_new_logon(service);
}

fn third_logon(service: &str) {
    check_settled(service);
    for steps in 0..5 {
        assert_kept(service, &crashed_move(steps), Some(VALUE));
        let expected = CRASHED_SAVE[steps as usize];
        assert_kept(service, &crashed_save(steps), Some(expected));
    }
    assert_kept(service, "real-wins", Some(VALUE));
    assert_kept(service, "spare-alone", Some(NEWER));
    assert_kept(service, "old-over-spare", Some(VALUE));
    let index = &index_service(service);
    assert_kept(index, INDEX, Some("abc\ndef"));
    assert_kept(index, "abc", Some(VALUE));

    // These phases really are new logons: what a new logon undoes, it undid.
    for account in UNDONE {
        let (persist, blob, _) = stored(service, account).unwrap();
        assert_eq!(persist, CRED_PERSIST_ENTERPRISE, "{account}");
        assert_eq!(blob, blob_of(VALUE).to_vec(), "{account}");
    }
}

#[test]
fn a_value_is_stored_as_little_endian_utf16_with_no_terminator() {
    assert_eq!(blob_of("").to_vec(), [0u8; 0]);
    assert_eq!(blob_of("a€").to_vec(), [0x61, 0, 0xAC, 0x20]);
    // Outside the first plane, a surrogate pair.
    assert_eq!(blob_of("𝄞").to_vec(), [0x34, 0xD8, 0x1E, 0xDD]);
    // The buffer it was made in is the one it stays in: no copy left behind.
    let long = "é€𝄞a".repeat(100);
    let blob = blob_of(&long);
    assert_eq!(blob.capacity(), long.len() * 2);
}

#[test]
fn a_stored_value_reads_back_as_text() {
    let read = |blob: &[u8]| text_of(blob).map(|text| text.expose().to_string());
    assert_eq!(read(&[]).unwrap(), "");
    assert_eq!(read(&blob_of(VALUE)).unwrap(), VALUE);
    assert_eq!(read(&[0x61, 0, 0xAC, 0x20]).unwrap(), "a€");
    // An odd number of bytes, and half a surrogate pair.
    assert_eq!(read(&[0x61]), None);
    assert_eq!(read(&[0x61, 0, 0]), None);
    assert_eq!(read(&[0x00, 0xD8, 0x61, 0]), None);
}

#[test]
fn the_names_are_the_old_codes() {
    let store = Credentials::new("made.up.service");
    let names = store.names("abc").unwrap();
    assert_eq!(names.target, wide("abc.made.up.service"));
    assert_eq!(names.target.last(), Some(&0));
    assert_eq!(names.username, wide("abc"));
    // A nul would end the name early, at some other entry's.
    assert!(store.names("abc\0def").is_err());
}

// Security rule: no account's target name is any account's spare, whatever the
// accounts are called, so a spare can never be read as an entry.
#[test]
fn a_spare_has_a_name_no_account_has() {
    let store = Credentials::new("made.up.service");
    let names = store.names("abc").unwrap();
    assert_eq!(names.spare, wide("abc.made.up.service.moving"));
    for account in [
        "abc",
        "abc.moving",
        "abc.made.up.service",
        "abc.made.up.service.moving",
    ] {
        assert_ne!(
            store.names(account).unwrap().target,
            names.spare,
            "{account}"
        );
    }
}

// Security rule: no OS code or message in what comes out, whatever the OS says.
#[test]
fn an_os_failure_is_fixed_text() {
    assert!(matches!(
        os_error(ERROR_NO_SUCH_LOGON_SESSION),
        Error::Unsupported
    ));
    for code in [ERROR_ACCESS_DENIED, ERROR_NOT_FOUND, 1234] {
        let error = os_error(code);
        match &error {
            Error::Failed(text) => assert_eq!(text, "the OS keyring could not be used"),
            other => panic!("{other:?}"),
        }
        assert!(!format!("{error} {error:?}").contains(&code.to_string()));
    }
}

#[test]
fn what_a_session_allows() {
    for (limit, needed, ok) in [
        (CRED_PERSIST_NONE, CRED_PERSIST_SESSION, false),
        (CRED_PERSIST_SESSION, CRED_PERSIST_SESSION, true),
        (CRED_PERSIST_SESSION, CRED_PERSIST_LOCAL_MACHINE, false),
        (CRED_PERSIST_LOCAL_MACHINE, CRED_PERSIST_LOCAL_MACHINE, true),
        (CRED_PERSIST_ENTERPRISE, CRED_PERSIST_LOCAL_MACHINE, true),
    ] {
        match allowed(Ok(limit), needed) {
            Ok(()) => assert!(ok, "{limit} {needed}"),
            Err(error) => {
                assert!(!ok, "{limit} {needed}");
                assert!(matches!(error, Error::Unsupported));
            }
        }
    }
    let no_session = allowed(Err(ERROR_NO_SUCH_LOGON_SESSION), CRED_PERSIST_SESSION);
    assert!(matches!(no_session, Err(Error::Unsupported)));
    let refused = allowed(Err(ERROR_ACCESS_DENIED), CRED_PERSIST_SESSION);
    assert!(matches!(refused, Err(Error::Failed(_))));
}
