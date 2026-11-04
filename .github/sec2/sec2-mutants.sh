#!/usr/bin/env bash
# Scratch only: each mutation must make the secrets tests fail.
set -uo pipefail
C=crates/platform/src/windows/credentials.rs
S=crates/platform/src/secrets.rs
out=$GITHUB_STEP_SUMMARY
bad=0
echo "| mutation | result | failing tests |" >> "$out"
echo "|---|---|---|" >> "$out"
m() {
  local name=$1 file=$2 expr=$3
  perl -0pi -e "$expr" "$file"
  if git diff --quiet -- "$file"; then
    echo "$name: NOT APPLIED"; echo "| $name | NOT APPLIED | |" >> "$out"; bad=1; return
  fi
  local log=sec2-$name.log result
  if cargo test --locked -p ubc-vpn-platform --features secrets --lib -- secrets:: > "$log" 2>&1; then
    result=MISSED; bad=1
  elif grep -q 'could not compile' "$log"; then
    result=UNVIABLE; bad=1; grep -m5 -A6 '^error' "$log"
  else
    result=caught
  fi
  local tests
  tests=$(grep -E '^test .* FAILED$' "$log" | sed -E 's/^test secrets::(credentials::)?(tests::)?//; s/ \.\.\. FAILED$//' | tr '\n' ' ')
  if [ "$result" = caught ] && [ -z "$tests" ]; then tests="(process aborted)"; fi
  echo "$name: $result: $tests"
  echo "| $name | $result | $tests |" >> "$out"
  git checkout -q -- "$file"
}
P='CRED_PERSIST_LOCAL_MACHINE'
E=windows_sys::Win32::Security::Credentials::CRED_PERSIST_ENTERPRISE
UNC='let s = CREDENTIALW { TargetName: names.TT.as_ptr().cast_mut(), Persist: CRED_PERSIST_LOCAL_MACHINE, ..*credential }; let _ = (self.write)(&s);'
# Each step of the move.
m step1-no-spare "$C" 's/self\.write_confirmed\(credential, &names\.spare\)\?;//'
m step1-unconfirmed "$C" "s/self\.write_confirmed\(credential, &names\.spare\)\?;/${UNC//TT/spare}/"
m step2-no-delete "$C" 's/self\.write_confirmed\(credential, &names\.spare\)\?;\s+self\.gone\(&names\.target\)\?;/self.write_confirmed(credential, &names.spare)?;/'
m step2-before-step1 "$C" 's/self\.write_confirmed\(credential, &names\.spare\)\?;\s+self\.gone\(&names\.target\)\?;/self.gone(&names.target)?;\n        self.write_confirmed(credential, &names.spare)?;/'
m step3-no-write "$C" 's/self\.write_confirmed\(credential, &names\.target\)\n/Ok(())\n/; s/self\.write_confirmed\(credential, &names\.target\)\r\n/Ok(())\r\n/'
m step3-unconfirmed "$C" "s/self\.write_confirmed\(credential, &names\.target\)(\r?\n)/${UNC//TT/target} Ok(())\$1/"
m step4-no-delete-in-move "$C" 's/\}(\s+)self\.gone\(&names\.spare\)(\s+\}\s+\}\s+impl Store)/}$1Ok(())$2/'
m step4-no-delete-in-save "$C" 's/let _ = self\.gone\(&names\.spare\);//'
# Reading back.
m read-back-nothing "$C" 's/match back\.persist\(\) == CRED_PERSIST_LOCAL_MACHINE && same/let _ = same; match true/'
m read-back-type-only "$C" 's/match back\.persist\(\) == CRED_PERSIST_LOCAL_MACHINE && same/let _ = same; match back.persist() == CRED_PERSIST_LOCAL_MACHINE/'
m read-back-value-only "$C" 's/match back\.persist\(\) == CRED_PERSIST_LOCAL_MACHINE && same/match same/'
m writes-roaming "$C" "s/(TargetName: target\.as_ptr\(\)\.cast_mut\(\),\s+Persist: )$P/\$1$E/"
# The designs that a new logon undoes.
m moved-in-place "$C" 's/Some\(old\) => self\.place\(&names, old\.credential\(\)\)\?,/Some(old) => self.write_confirmed(old.credential(), &names.target)?,/'
m save-in-place-over-old "$C" 's/match old_type \{/let _ = old_type; match false {/'
# A leftover spare.
m spare-beats-new-entry "$C" 's/Some\(found\) if found\.persist\(\) == CRED_PERSIST_LOCAL_MACHINE => \{\}/Some(found) if found.persist() == CRED_PERSIST_LOCAL_MACHINE \&\& false => {}/'
m spare-beats-old-entry "$C" 's/Some\(old\) => self\.place\(&names, old\.credential\(\)\)\?,/Some(old) => { let old = Found::read(\&names.spare)?.unwrap_or(old); self.place(\&names, old.credential())? }/'
m spare-not-recovered "$C" 's/Some\(spare\) => self\.write_confirmed\(spare\.credential\(\), &names\.target\)\?,/Some(_) => return Ok(()),/'
m spare-not-read "$C" 's/None => Found::read\(&names\.spare\)\?,/None => None,/'
m spare-read-first "$C" 's/let found = match Found::read\(&names\.target\)\? \{(\s+)Some\(found\) => Some\(found\),/let found = match Found::read(\&names.spare)? {$1Some(found) => Some(found),/; s/None => Found::read\(&names\.spare\)\?,/None => Found::read(\&names.target)?,/'
m spare-name-collides "$C" 's/format!\("\{target\}\{SPARE\}"\)/format!("{account}{SPARE}.{}", self.service)/'
# Forgetting.
m forget-keeps-spare "$C" 's/(fn delete\(&self, account: &str\).*?)self\.gone\(&names\.spare\)\?;/$1/s'
m forget-entry-first "$C" 's/self\.gone\(&names\.spare\)\?;(\s+)self\.gone\(&names\.target\)(\s+\}\s+fn settle)/self.gone(\&names.target)?;$1self.gone(\&names.spare)$2/'
m gone-none-fails "$C" 's/Ok\(\(\)\) \| Err\(ERROR_NOT_FOUND\) => Ok\(\(\)\),/Ok(()) => Ok(()),/'
# Settling.
m no-migration "$C" 's/let _ = self\.migrate\(super::INDEX\);//; s/let _ = self\.migrate\(&account\);/let _ = &account;/'
m migration-skips-index "$C" 's/let _ = self\.migrate\(super::INDEX\);//'
m migration-skips-accounts "$C" 's/let _ = self\.migrate\(&account\);/let _ = &account;/'
m failed-move-blocks-login "$C" 's/let _ = self\.migrate\(&account\);/self.migrate(&account).unwrap();/'
m failed-index-move-blocks-login "$C" 's/let _ = self\.migrate\(super::INDEX\);/self.migrate(super::INDEX).unwrap();/'
m settles-every-use "$S" 's/\*settled = true;//'
m load-does-not-settle "$S" 's/(fn load\(&self, account: &str\) -> Result<Option<Saved>> \{\s+)drop\(self\.changing\(\)\);/$1/'
m saved-does-not-settle "$S" 's/(fn saved\(&self\) -> Result<Vec<String>> \{\s+)drop\(self\.changing\(\)\);/$1/'
# Sessions, errors, wiping, form.
m ignores-session "$C" 's/allowed\(\(self\.limit\)\(\), needed\)/{ let _ = needed; Ok(()) }/'
m get-ignores-session "$C" 's/(fn get.*?)self\.allows\(CRED_PERSIST_SESSION\)\?;/$1/s'
m delete-ignores-session "$C" 's/(fn delete\(&self, account.*?)self\.allows\(CRED_PERSIST_SESSION\)\?;/$1/s'
m session-only-may-save "$C" 's/(fn set.*?self\.allows\()CRED_PERSIST_LOCAL_MACHINE/$1CRED_PERSIST_SESSION/s'
m session-only-may-move "$C" 's/(fn migrate.*?self\.allows\()CRED_PERSIST_LOCAL_MACHINE/$1CRED_PERSIST_SESSION/s'
m wrong-session-index "$C" 's/limits\[CRED_TYPE_GENERIC as usize\]/limits[0]/'
m no-wipe "$C" 's/(size as usize\) \})\.zeroize\(\);/$1;/'
m no-logon-is-failure "$C" 's/ERROR_NO_SUCH_LOGON_SESSION => Error::Unsupported/ERROR_NO_SUCH_LOGON_SESSION => failed()/'
m os-code-in-error "$C" 's/_ => failed\(\),(\s*\}\s*\}\s*fn last_error)/_ => Error::Failed(code.to_string()),$1/'
m target-swapped "$C" 's/format!\("\{account\}\.\{\}", self\.service\)/format!("{}.{account}", self.service)/'
m nul-allowed "$C" "s/match target\.contains\('\\\\0'\)/match false/"
m big-endian "$C" 's/unit\.to_le_bytes\(\)/unit.to_be_bytes()/'
m odd-blob-accepted "$C" 's/if !odd\.is_empty\(\)/if false/'
exit $bad
