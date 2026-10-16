//! Which keyring this program keeps saved passwords in.
//!
//! - **Its own unit tests:** always an in-memory fake, one to a thread. No
//!   unit test can reach the user's keyring, however it is written.
//! - **A debug build with `UBC_VPN_TEST_KEYRING` set:** a keyring kept as
//!   files in the folder it names, so that the tests that run this program
//!   as a program, several processes at once, share one. A release build
//!   never reads that variable.
//! - **Otherwise:** the user's OS keyring.
//!
//! Every change to a saved password is made while the settings lock is
//! held (see `settings_lock`), so two processes of this program never
//! change the keyring's index at once.

use std::sync::Arc;

use ubc_vpn_platform::secrets::Secrets;

/// The variable that points a debug build at a keyring in a folder.
#[cfg(all(debug_assertions, not(test)))]
const TEST_KEYRING: &str = "UBC_VPN_TEST_KEYRING";

/// The variable that makes that keyring slow to read its index.
#[cfg(all(debug_assertions, not(test)))]
const SLOW_KEYRING: &str = "UBC_VPN_TEST_KEYRING_SLOW";

/// Whether this run is in dev mode, whose saved passwords are kept apart
/// from the installed product's.
static DEV: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Says this run is in dev mode. Its passwords are then kept under a
/// service name of their own, so dev mode can never read or forget those
/// of the installed product.
#[cfg_attr(not(feature = "dev-mode"), allow(dead_code))]
pub(crate) fn dev_mode() {
    DEV.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// The service name dev mode keeps its passwords under.
pub(crate) const DEV_SERVICE: &str = "io.github.nima-hs.ubc-vpn.dev";

/// The service name in the OS keyring that saved passwords are kept under:
/// the installed product's, or in dev mode one of its own.
fn service(dev: bool) -> &'static str {
    match dev {
        true => DEV_SERVICE,
        false => ubc_vpn_platform::secrets::SERVICE,
    }
}

/// The service name this run keeps saved passwords under, as dev mode has
/// been said or not. [`keyring`] opens the OS keyring under this and no
/// other name. Unit tests never open it; one asks for this name.
#[cfg_attr(all(test, not(feature = "dev-mode")), allow(dead_code))]
pub(crate) fn chosen_service() -> &'static str {
    service(DEV.load(std::sync::atomic::Ordering::SeqCst))
}

/// The keyring this program keeps saved passwords in.
pub(crate) fn keyring() -> Arc<dyn Secrets> {
    #[cfg(test)]
    {
        test::FAKE.with(|fake| fake.secrets())
    }
    #[cfg(not(test))]
    {
        use ubc_vpn_platform::secrets;
        #[cfg(debug_assertions)]
        if let Some(dir) = std::env::var_os(TEST_KEYRING) {
            // With it, the keyring is slow to read its index, so that two
            // processes changing it overlap unless the settings lock keeps
            // them apart.
            let slow = std::env::var_os(SLOW_KEYRING).is_some();
            return secrets::file_backed(std::path::Path::new(&dir), slow);
        }
        secrets::under(chosen_service())
    }
}

#[cfg(test)]
pub(crate) mod test {
    use ubc_vpn_platform::secrets::FakeSecrets;

    thread_local! {
        /// The keyring of this thread's test.
        pub(crate) static FAKE: FakeSecrets = FakeSecrets::new();
    }

    /// The keyring this thread's test sees, to plant entries in and look at.
    pub(crate) fn fake() -> FakeSecrets {
        FAKE.with(Clone::clone)
    }

    // Security rule: dev mode keeps its passwords apart from the installed
    // product's, so it can never read or forget theirs.
    #[test]
    fn dev_mode_has_a_keyring_service_of_its_own() {
        use ubc_vpn_platform::secrets::SERVICE;
        assert_eq!(super::service(false), SERVICE);
        assert_eq!(super::service(true), "io.github.nima-hs.ubc-vpn.dev");
        assert_ne!(super::service(true), SERVICE);
    }

    // Security rule: `--dev` alone is enough for this run's passwords to be
    // kept under dev mode's name, so `ubc-vpn --dev settings reset --force`
    // can never forget the installed product's. No OS keyring is opened:
    // only the name the keyring would be opened under is asked for.
    //
    // `DEV` is one for the whole process, so this leaves it set for the
    // other tests in this binary. That changes nothing for them: under
    // `cfg(test)` `keyring()` is always the fake.
    #[cfg(feature = "dev-mode")]
    #[test]
    fn the_dev_flag_puts_saved_passwords_under_dev_modes_name() {
        let (dev, rest) = crate::dev_flag(&["--dev", "version"]);
        assert_eq!((dev, rest), (true, &["version"][..]));
        assert_eq!(super::chosen_service(), super::DEV_SERVICE);
    }
}
