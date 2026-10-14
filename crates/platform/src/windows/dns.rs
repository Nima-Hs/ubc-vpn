//! Split DNS on Windows: name resolution policy (NRPT) rules in the DNS
//! client's own registry key, under identifiers that are this product's.
//!
//! - **Ours** are the keys named in [`RULES`], and no others. Setting writes
//!   them and deletes the ones not needed; clearing deletes them all. A rule
//!   holds at most [`PER_RULE`] domains, so a long list takes several.
//! - **Refused** when rules from group policy exist: Windows then ignores the
//!   local ones, so setting ours would look applied and do nothing.
//! - **Read back** exactly, together with a check that no group-policy table
//!   and no rule of anyone else's names our domains. Windows offers no
//!   documented way to see which rules its resolver took in, so a match
//!   answers [`Verified::Unknown`], as the contract asks; the CI test with a
//!   DNS server of its own shows the effect.
//! - **Survives** a crash and a restart of the machine, being in the
//!   registry; the service's start-up clear removes it.

use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_ITEMS};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_ALL_ACCESS, KEY_READ, REG_DWORD, REG_MULTI_SZ,
    REG_OPTION_NON_VOLATILE, REG_SZ, RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegEnumKeyExW,
    RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
};

use super::security::{os_error, wide};
use crate::{Dns, Error, Result, SplitDns, Verified};

/// Where the DNS client reads local rules.
const LOCAL: &str = r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig";
/// Where group policy puts rules, which replace local ones.
const POLICY: &str = r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig";
/// This product's rules. Never change them: a later version must find an
/// earlier one's rules to remove them.
pub(super) const RULES: [&str; 6] = [
    "{6F3B1C2A-7E4D-4B19-9C55-0D1E2F3A4B01}",
    "{6F3B1C2A-7E4D-4B19-9C55-0D1E2F3A4B02}",
    "{6F3B1C2A-7E4D-4B19-9C55-0D1E2F3A4B03}",
    "{6F3B1C2A-7E4D-4B19-9C55-0D1E2F3A4B04}",
    "{6F3B1C2A-7E4D-4B19-9C55-0D1E2F3A4B05}",
    "{6F3B1C2A-7E4D-4B19-9C55-0D1E2F3A4B06}",
];
/// The most domains one rule holds.
pub(super) const PER_RULE: usize = 50;
/// "Use the given DNS servers for these names."
const OVERRIDE_SERVERS: u32 = 0x8;

/// An open registry key. Dropping it closes it.
struct Key(HKEY);

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: the key is open and owned by this value alone.
        unsafe { RegCloseKey(self.0) };
    }
}

fn checked(code: u32) -> Result<()> {
    match code {
        0 => Ok(()),
        ERROR_FILE_NOT_FOUND => Err(Error::NotFound),
        code => Err(os_error(code)),
    }
}

fn open(path: &str, access: u32) -> Result<Option<Key>> {
    let name = wide(path);
    let mut key = null_mut();
    // SAFETY: the name is NUL-terminated and the out pointer valid.
    match checked(unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, name.as_ptr(), 0, access, &mut key) })
    {
        Ok(()) => Ok(Some(Key(key))),
        Err(Error::NotFound) => Ok(None),
        Err(error) => Err(error),
    }
}

/// The names of the subkeys of `key`.
fn subkeys(key: &Key) -> Result<Vec<String>> {
    let mut names = Vec::new();
    for index in 0.. {
        let mut name = [0u16; 256];
        let mut len = name.len() as u32;
        // SAFETY: the key is open, the buffer is writable for `len` units,
        // and the optional out pointers are null.
        let code = unsafe {
            RegEnumKeyExW(
                key.0,
                index,
                name.as_mut_ptr(),
                &mut len,
                null(),
                null_mut(),
                null_mut(),
                null_mut(),
            )
        };
        if code == ERROR_NO_MORE_ITEMS {
            break;
        }
        checked(code)?;
        names.push(String::from_utf16_lossy(&name[..len as usize]));
    }
    Ok(names)
}

/// A value's raw bytes, or `None` when it is missing.
fn value(key: &Key, name: &str) -> Result<Option<(u32, Vec<u8>)>> {
    let name = wide(name);
    let (mut kind, mut size) = (0, 0);
    // SAFETY: the key is open and the name NUL-terminated; a null buffer
    // asks only for the size.
    let code = unsafe {
        RegQueryValueExW(
            key.0,
            name.as_ptr(),
            null_mut(),
            &mut kind,
            null_mut(),
            &mut size,
        )
    };
    match checked(code) {
        Err(Error::NotFound) => return Ok(None),
        other => other?,
    }
    let mut data = vec![0u8; size as usize];
    // SAFETY: the buffer is writable for `size` bytes, which the call is told.
    let code = unsafe {
        RegQueryValueExW(
            key.0,
            name.as_ptr(),
            null_mut(),
            &mut kind,
            data.as_mut_ptr(),
            &mut size,
        )
    };
    checked(code)?;
    data.truncate(size as usize);
    Ok(Some((kind, data)))
}

fn units(bytes: &[u8]) -> Vec<u16> {
    let (pairs, _) = bytes.as_chunks::<2>();
    pairs.iter().map(|pair| u16::from_le_bytes(*pair)).collect()
}

/// The strings of a REG_MULTI_SZ or REG_SZ value.
fn strings(bytes: &[u8]) -> Vec<String> {
    let units = units(bytes);
    let parts = units
        .split(|unit| *unit == 0)
        .filter(|part| !part.is_empty());
    parts.map(String::from_utf16_lossy).collect()
}

/// One rule as the registry holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Rule {
    /// Each with a leading dot, as the DNS client expects.
    pub(super) names: Vec<String>,
    pub(super) servers: String,
}

/// The rules `dns` takes: its domains in groups of [`PER_RULE`], each
/// pointing at all the resolvers.
pub(super) fn rules(dns: &SplitDns) -> Result<Vec<Rule>> {
    if dns.domains.is_empty() || dns.resolvers.is_empty() {
        return Err(Error::InvalidInput);
    }
    if dns.domains.len() > RULES.len() * PER_RULE {
        return Err(Error::InvalidInput);
    }
    let servers = dns
        .resolvers
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(";");
    let chunks = dns.domains.chunks(PER_RULE);
    let rules = chunks.map(|chunk| Rule {
        names: chunk.iter().map(|domain| format!(".{domain}")).collect(),
        servers: servers.clone(),
    });
    Ok(rules.collect())
}

fn set_value(key: &Key, name: &str, kind: u32, data: &[u8]) -> Result<()> {
    let name = wide(name);
    let len = u32::try_from(data.len()).map_err(|_| Error::InvalidInput)?;
    // SAFETY: the key is open, the name NUL-terminated, and the data
    // readable for `len` bytes.
    checked(unsafe { RegSetValueExW(key.0, name.as_ptr(), 0, kind, data.as_ptr(), len) })
}

fn utf16_bytes(units: impl IntoIterator<Item = u16>) -> Vec<u8> {
    units.into_iter().flat_map(u16::to_le_bytes).collect()
}

fn write_rule(id: &str, rule: &Rule) -> Result<()> {
    let path = wide(&format!(r"{LOCAL}\{id}"));
    let mut key = null_mut();
    // SAFETY: the path is NUL-terminated; the class, security attributes and
    // disposition may be null; the out pointer is valid.
    let code = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            path.as_ptr(),
            0,
            null_mut(),
            REG_OPTION_NON_VOLATILE,
            KEY_ALL_ACCESS,
            null_mut(),
            &mut key,
            null_mut(),
        )
    };
    checked(code)?;
    let key = Key(key);
    let names = rule
        .names
        .iter()
        .flat_map(|name| name.encode_utf16().chain([0]))
        .chain([0]);
    set_value(&key, "Version", REG_DWORD, &1u32.to_le_bytes())?;
    set_value(
        &key,
        "ConfigOptions",
        REG_DWORD,
        &OVERRIDE_SERVERS.to_le_bytes(),
    )?;
    set_value(&key, "Name", REG_MULTI_SZ, &utf16_bytes(names))?;
    let servers = rule.servers.encode_utf16().chain([0]);
    set_value(&key, "GenericDNSServers", REG_SZ, &utf16_bytes(servers))
}

fn read_rule(id: &str) -> Result<Option<Rule>> {
    let Some(key) = open(&format!(r"{LOCAL}\{id}"), KEY_READ)? else {
        return Ok(None);
    };
    let dword = |name| -> Result<Option<u32>> {
        Ok(match value(&key, name)? {
            Some((REG_DWORD, data)) if data.len() == 4 => {
                Some(u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
            }
            _ => None,
        })
    };
    let names = match value(&key, "Name")? {
        Some((REG_MULTI_SZ, data)) => strings(&data),
        _ => return Ok(None),
    };
    let servers = match value(&key, "GenericDNSServers")? {
        Some((REG_SZ, data)) => strings(&data).concat(),
        _ => return Ok(None),
    };
    // A rule of ours that says anything else is not the rule we wrote.
    if dword("Version")? != Some(1) || dword("ConfigOptions")? != Some(OVERRIDE_SERVERS) {
        return Ok(None);
    }
    Ok(Some(Rule { names, servers }))
}

fn delete_rule(id: &str) -> Result<()> {
    let path = wide(&format!(r"{LOCAL}\{id}"));
    // SAFETY: the path is NUL-terminated.
    match checked(unsafe { RegDeleteTreeW(HKEY_LOCAL_MACHINE, path.as_ptr()) }) {
        Ok(()) | Err(Error::NotFound) => Ok(()),
        Err(error) => Err(error),
    }
}

/// Whether group policy has name resolution rules, which replace local ones.
fn policy_rules_exist() -> Result<bool> {
    match open(POLICY, KEY_READ)? {
        Some(key) => Ok(!subkeys(&key)?.is_empty()),
        None => Ok(false),
    }
}

pub(crate) struct WinDns;

impl Dns for WinDns {
    fn set_split_dns(&self, _tunnel: &str, dns: &SplitDns) -> Result<()> {
        let rules = rules(dns)?;
        if policy_rules_exist()? {
            return Err(Error::Unsupported);
        }
        for (id, rule) in RULES.iter().zip(&rules) {
            write_rule(id, rule)?;
        }
        for id in &RULES[rules.len()..] {
            delete_rule(id)?;
        }
        Ok(())
    }

    fn clear_split_dns(&self) -> Result<()> {
        let mut failed = None;
        for id in RULES {
            if let Err(error) = delete_rule(id) {
                failed = Some(error);
            }
        }
        failed.map_or(Ok(()), Err)
    }

    fn split_dns_matches(&self, dns: &SplitDns) -> Verified {
        let check = || -> Result<Verified> {
            let Ok(expected) = rules(dns) else {
                return Ok(Verified::No);
            };
            let mut found = Vec::new();
            for id in RULES {
                found.push(read_rule(id)?);
            }
            let wanted = expected.iter().cloned().map(Some);
            let wanted: Vec<_> = wanted
                .chain(std::iter::repeat_n(None, RULES.len() - expected.len()))
                .collect();
            if found != wanted || policy_rules_exist()? {
                return Ok(Verified::No);
            }
            // Nobody else's rule may name one of our domains.
            let ours: Vec<&String> = expected.iter().flat_map(|rule| &rule.names).collect();
            let all = open(LOCAL, KEY_READ)?
                .map(|key| subkeys(&key))
                .transpose()?;
            for id in all.unwrap_or_default() {
                if RULES.contains(&id.as_str()) {
                    continue;
                }
                let key = open(&format!(r"{LOCAL}\{id}"), KEY_READ)?;
                let names = match key.map(|key| value(&key, "Name")).transpose()?.flatten() {
                    Some((_, data)) => strings(&data),
                    None => continue,
                };
                if names
                    .iter()
                    .any(|name| ours.contains(&&name.to_ascii_lowercase()))
                {
                    return Ok(Verified::No);
                }
            }
            // Written as asked; whether the resolver took it in, Windows
            // does not say.
            Ok(Verified::Unknown)
        };
        check().unwrap_or(Verified::Unknown)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn dns(domains: usize) -> SplitDns {
        SplitDns {
            resolvers: vec![Ipv4Addr::new(192, 0, 2, 53), Ipv4Addr::new(192, 0, 2, 54)],
            domains: (0..domains).map(|n| format!("d{n}.example")).collect(),
        }
    }

    #[test]
    fn splits_domains_into_rules_of_fifty_with_every_server() {
        let split = rules(&dns(120)).unwrap();
        assert_eq!(
            split
                .iter()
                .map(|rule| rule.names.len())
                .collect::<Vec<_>>(),
            [50, 50, 20]
        );
        assert_eq!(split[0].names[0], ".d0.example");
        assert!(
            split
                .iter()
                .all(|rule| rule.servers == "192.0.2.53;192.0.2.54")
        );
        assert_eq!(
            rules(&dns(RULES.len() * PER_RULE)).unwrap().len(),
            RULES.len()
        );
        assert_eq!(
            rules(&dns(RULES.len() * PER_RULE + 1)),
            Err(Error::InvalidInput)
        );
        assert_eq!(rules(&dns(0)), Err(Error::InvalidInput));
    }

    #[test]
    fn reads_multi_strings_back() {
        let bytes = utf16_bytes(".a.example\0.b.example\0\0".encode_utf16());
        assert_eq!(strings(&bytes), [".a.example", ".b.example"]);
    }

    // The identifiers are how a later version finds these rules: they never
    // change, and none repeats.
    #[test]
    fn the_rule_identifiers_never_change() {
        assert_eq!(RULES[0], "{6F3B1C2A-7E4D-4B19-9C55-0D1E2F3A4B01}");
        let mut unique = RULES.to_vec();
        unique.dedup();
        assert_eq!(unique.len(), RULES.len());
    }
}
