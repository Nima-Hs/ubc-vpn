//! The store over Credential Manager. The tests named `real_` use the real
//! one, under a throwaway service name with made-up passwords, only on CI and
//! only when the workflow asks: never on anyone's own machine, where the real
//! saved passwords are. The others call nothing in the OS.

use std::cell::Cell;
use std::sync::Arc;

use windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED;
use windows_sys::Win32::Security::Credentials::{CRED_PERSIST_ENTERPRISE, CredEnumerateW};

use super::super::{INDEX, Kept, SERVICE, Saved, Secrets};
use super::*;

const PROFILE: &str = "11111111111111111111111111111111";
const OTHER: &str = "22222222222222222222222222222222";
/// As it would be stored: the form, a made-up username and password.
const VALUE: &str = "ubc-vpn 1\nuser.dept@app\nmade-up-pass-é€𝄞";
const PASSWORD: &str = "made-up-pass-é€𝄞";

thread_local! {
    /// How many credentials this thread has wiped and given back.
    static WIPED: Cell<usize> = const { Cell::new(0) };
}

/// Called as a [`Found`] goes, after its value is wiped.
pub(super) fn wiped(blob: &[u8]) {
    assert!(blob.iter().all(|byte| *byte == 0));
    WIPED.with(|wiped| wiped.set(wiped.get() + 1));
}

/// A service name for one test, or `None` when the real Credential Manager is
/// not to be touched. Quietly, without the word the workflow looks for.
fn throwaway(test: &str) -> Option<String> {
    let asked =
        std::env::var_os("CI").is_some() && std::env::var_os("UBC_VPN_REAL_KEYRING").is_some();
    asked.then(|| format!("{SERVICE}.test-{}-{test}", std::process::id()))
}

fn target_of(service: &str, account: &str) -> Vec<u16> {
    wide(&format!("{account}.{service}"))
}

/// Writes an entry as the `keyring` crate 3.6.3 did, at the given type. Its
/// source writes these same fields, with this comment.
fn plant(service: &str, account: &str, blob: &[u8], persist: u32) {
    let (mut target, mut username) = (target_of(service, account), wide(account));
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
    write_credential(&credential, 0).unwrap();
}

/// An entry the old code left.
fn plant_old(service: &str, account: &str, value: &str) {
    plant(service, account, &blob_of(value), CRED_PERSIST_ENTERPRISE);
}

/// What is really stored: its type, value and username.
fn stored(service: &str, account: &str) -> Option<(u32, Vec<u8>, String)> {
    let found = Found::read(&target_of(service, account)).unwrap()?;
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

fn persist_of(service: &str, account: &str) -> Option<u32> {
    stored(service, account).map(|(persist, ..)| persist)
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

fn with_write(service: &str, write: fn(&CREDENTIALW, u32) -> Os<()>) -> Credentials {
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

fn saved(password: &str) -> Saved {
    Saved {
        username: "user.dept@app".to_string(),
        password: Secret::new(password),
        in_doubt: false,
    }
}

// A new save stays on this computer: the entry and the index, in the form the
// old code wrote, so an older copy of the program could still read it.
#[test]
fn real_a_new_save_stays_on_this_computer() {
    let Some(service) = throwaway("new") else {
        return;
    };
    let secrets: Arc<dyn Secrets> = Arc::new(Kept::new(Credentials::new(&service)));
    secrets.save(PROFILE, &saved(PASSWORD)).unwrap();
    let (persist, blob, username) = stored(&service, PROFILE).unwrap();
    assert_eq!(persist, CRED_PERSIST_LOCAL_MACHINE);
    assert_eq!(username, PROFILE);
    let units: Vec<u8> = VALUE.encode_utf16().flat_map(u16::to_le_bytes).collect();
    assert_eq!(blob, units);
    assert_eq!(
        persist_of(&service, INDEX),
        Some(CRED_PERSIST_LOCAL_MACHINE)
    );
    assert_eq!(
        secrets.load(PROFILE).unwrap().unwrap().password.expose(),
        PASSWORD
    );
    // A new password over an old entry brings it here too, with no second copy.
    plant_old(&service, OTHER, VALUE);
    Credentials::new(&service).set(OTHER, VALUE).unwrap();
    assert_eq!(
        persist_of(&service, OTHER),
        Some(CRED_PERSIST_LOCAL_MACHINE)
    );
    assert_eq!(copies(&service, OTHER), 1);
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

    let secrets: Arc<dyn Secrets> = Arc::new(Kept::new(Credentials::new(&service)));
    let read = secrets.load(PROFILE).unwrap().unwrap();
    assert_eq!(read.password.expose(), PASSWORD);

    for (account, (_, blob, username)) in [INDEX, PROFILE, OTHER].into_iter().zip(before) {
        let (persist, after, name) = stored(&service, account).unwrap();
        assert_eq!(persist, CRED_PERSIST_LOCAL_MACHINE, "{account}");
        assert_eq!(after, blob, "{account}");
        assert_eq!(name, username, "{account}");
        assert_eq!(copies(&service, account), 1, "{account}");
    }
    assert_eq!(secrets.saved().unwrap(), [PROFILE, OTHER]);
    ubc_vpn_test_lines::whole_line!("RAN: credential an old entry moves");
}

// Forgetting works on an entry of either type, with nothing moved first: this
// store's writes all fail here, so what is deleted is still of the old type.
#[test]
fn real_forgetting_works_on_both_types() {
    let Some(service) = throwaway("forget") else {
        return;
    };
    let store = Credentials::new(&service);
    plant_old(&service, PROFILE, VALUE);
    store.delete(PROFILE).unwrap();
    assert_eq!(stored(&service, PROFILE), None);
    store.set(PROFILE, VALUE).unwrap();
    assert_eq!(
        persist_of(&service, PROFILE),
        Some(CRED_PERSIST_LOCAL_MACHINE)
    );
    store.delete(PROFILE).unwrap();
    assert_eq!(stored(&service, PROFILE), None);
    // None there is fine.
    store.delete(PROFILE).unwrap();

    plant_old(&service, INDEX, PROFILE);
    plant_old(&service, PROFILE, VALUE);
    let stuck = Kept::new(with_write(&service, refuses));
    stuck.forget(PROFILE).unwrap();
    assert_eq!(stored(&service, PROFILE), None);
    assert_eq!(stored(&service, INDEX), None);

    plant_old(&service, INDEX, OTHER);
    plant_old(&service, OTHER, VALUE);
    let stuck = Kept::new(with_write(&service, refuses));
    stuck.forget_all().unwrap();
    assert_eq!(stored(&service, OTHER), None);
    assert_eq!(stored(&service, INDEX), None);
    ubc_vpn_test_lines::whole_line!("RAN: credential forgetting");
}

fn refuses(_: &CREDENTIALW, _: u32) -> Os<()> {
    Err(ERROR_ACCESS_DENIED)
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

    let secrets: Arc<dyn Secrets> = Arc::new(Kept::new(stuck));
    let read = secrets.load(PROFILE).unwrap().unwrap();
    assert_eq!(read.password.expose(), PASSWORD);
    assert_eq!(secrets.saved().unwrap(), [PROFILE]);
    assert_eq!(stored(&service, PROFILE).unwrap(), before);

    let next_run: Arc<dyn Secrets> = Arc::new(Kept::new(Credentials::new(&service)));
    let read = next_run.load(PROFILE).unwrap().unwrap();
    assert_eq!(read.password.expose(), PASSWORD);
    assert_eq!(
        persist_of(&service, PROFILE),
        Some(CRED_PERSIST_LOCAL_MACHINE)
    );
    ubc_vpn_test_lines::whole_line!("RAN: credential a failed write");
}

fn refuses_flag(credential: &CREDENTIALW, flags: u32) -> Os<()> {
    match flags {
        0 => write_credential(credential, 0),
        _ => Err(ERROR_INVALID_FLAGS),
    }
}

fn refuses_parameter(credential: &CREDENTIALW, flags: u32) -> Os<()> {
    match flags {
        0 => write_credential(credential, 0),
        _ => Err(ERROR_INVALID_PARAMETER),
    }
}

fn only_with_the_flag(credential: &CREDENTIALW, flags: u32) -> Os<()> {
    assert_eq!(flags, CRED_PRESERVE_CREDENTIAL_BLOB);
    assert_eq!(credential.CredentialBlobSize, 0);
    write_credential(credential, flags)
}

// The real write takes the flag, so the value is not written back from memory.
// Where it is refused, the value is written too.
#[test]
fn real_a_refused_flag_falls_back_to_writing_the_value() {
    let Some(service) = throwaway("flag") else {
        return;
    };
    plant_old(&service, PROFILE, VALUE);
    let before = stored(&service, PROFILE).unwrap();
    with_write(&service, only_with_the_flag)
        .migrate(PROFILE)
        .unwrap();
    let (persist, blob, username) = stored(&service, PROFILE).unwrap();
    assert_eq!(persist, CRED_PERSIST_LOCAL_MACHINE);
    assert_eq!((blob, username), (before.1, before.2));

    for write in [refuses_flag, refuses_parameter] {
        plant_old(&service, PROFILE, VALUE);
        let before = stored(&service, PROFILE).unwrap();
        with_write(&service, write).migrate(PROFILE).unwrap();
        let (persist, blob, username) = stored(&service, PROFILE).unwrap();
        assert_eq!(persist, CRED_PERSIST_LOCAL_MACHINE);
        assert_eq!((blob, username), (before.1, before.2));
    }
    ubc_vpn_test_lines::whole_line!("RAN: credential a refused flag");
}

/// Keeps the entry, at the new type, with no value at all.
fn loses_value(credential: &CREDENTIALW, flags: u32) -> Os<()> {
    write_credential(credential, flags & !CRED_PRESERVE_CREDENTIAL_BLOB)
}

/// Says yes and changes nothing.
fn does_nothing(_: &CREDENTIALW, _: u32) -> Os<()> {
    Ok(())
}

/// Has another process save another password in the meantime.
fn other_saved(credential: &CREDENTIALW, _: u32) -> Os<()> {
    let mut blob = blob_of("ubc-vpn 1\nuser.dept@app\nmade-up-pass-0002");
    let other = CREDENTIALW {
        CredentialBlob: blob.as_mut_ptr(),
        CredentialBlobSize: blob.len() as u32,
        ..*credential
    };
    write_credential(&other, 0)
}

/// Has another process forget the entry in the meantime.
fn other_forgot(credential: &CREDENTIALW, _: u32) -> Os<()> {
    // SAFETY: the name ends in a nul and outlives the call.
    match unsafe { CredDeleteW(credential.TargetName, CRED_TYPE_GENERIC, 0) } {
        0 => Err(last_error()),
        _ => Ok(()),
    }
}

// Security rule: "the write worked" is not taken on trust. What is read back
// must be the same value at the new type. A value the OS lost is put back; one
// another process changed, or forgot, stays as that process left it.
#[test]
fn real_a_move_is_confirmed_by_reading_it_back() {
    let Some(service) = throwaway("confirm") else {
        return;
    };
    plant_old(&service, PROFILE, VALUE);
    let (_, value, _) = stored(&service, PROFILE).unwrap();
    assert!(with_write(&service, does_nothing).migrate(PROFILE).is_err());
    assert_eq!(persist_of(&service, PROFILE), Some(CRED_PERSIST_ENTERPRISE));

    assert!(with_write(&service, loses_value).migrate(PROFILE).is_err());
    let (persist, blob, _) = stored(&service, PROFILE).unwrap();
    assert_eq!(persist, CRED_PERSIST_LOCAL_MACHINE);
    assert_eq!(blob, value);

    plant_old(&service, PROFILE, VALUE);
    assert!(with_write(&service, other_saved).migrate(PROFILE).is_err());
    let (_, blob, _) = stored(&service, PROFILE).unwrap();
    assert_eq!(
        blob,
        blob_of("ubc-vpn 1\nuser.dept@app\nmade-up-pass-0002").to_vec()
    );

    plant_old(&service, PROFILE, VALUE);
    assert!(with_write(&service, other_forgot).migrate(PROFILE).is_err());
    assert_eq!(stored(&service, PROFILE), None);

    // Nothing there and nothing to do are not failures.
    Credentials::new(&service).migrate(PROFILE).unwrap();
    assert_eq!(stored(&service, PROFILE), None);
    Credentials::new(&service).set(PROFILE, VALUE).unwrap();
    with_write(&service, refuses).migrate(PROFILE).unwrap();
    ubc_vpn_test_lines::whole_line!("RAN: credential a move is confirmed");
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
    if throwaway("limit").is_none() {
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
    let before = WIPED.with(Cell::get);
    assert_eq!(store.get(PROFILE).unwrap().unwrap().expose(), VALUE);
    assert_eq!(WIPED.with(Cell::get), before + 1);
    ubc_vpn_test_lines::whole_line!("RAN: credential what is read is wiped");
}

// What is not UTF-16 text is not one of this product's: no password, no error.
#[test]
fn real_what_is_not_text_is_no_entry() {
    let Some(service) = throwaway("text") else {
        return;
    };
    plant(&service, PROFILE, &[0x61], CRED_PERSIST_LOCAL_MACHINE);
    let store = Credentials::new(&service);
    assert!(store.get(PROFILE).unwrap().is_none());
    assert!(store.get(OTHER).unwrap().is_none());
    ubc_vpn_test_lines::whole_line!("RAN: credential what is not text");
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
    let (target, username) = store.names("abc").unwrap();
    assert_eq!(target, wide("abc.made.up.service"));
    assert_eq!(target.last(), Some(&0));
    assert_eq!(username, wide("abc"));
    // A nul would end the name early, at some other entry's.
    assert!(store.names("abc\0def").is_err());
}

// Security rule: no OS code or message in what comes out, whatever the OS says.
#[test]
fn an_os_failure_is_fixed_text() {
    assert!(matches!(
        os_error(ERROR_NO_SUCH_LOGON_SESSION),
        Error::Unsupported
    ));
    for code in [
        ERROR_ACCESS_DENIED,
        ERROR_NOT_FOUND,
        ERROR_INVALID_FLAGS,
        1234,
    ] {
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
