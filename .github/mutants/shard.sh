#!/usr/bin/env bash
# Runs one shard of cargo-mutants over the lines a pull request changed.
# The working directory is a throwaway checkout of the pull request's head:
# cargo-mutants changes its files in place and puts each one back. Nothing
# is committed or pushed.
#
# Usage: shard.sh <diff> <shard> <shards> <out>
#
# MUTANTS_OS names the OS, linux or windows. Each mutant goes to the same
# shard on every OS. It is tested first with its own crate's tests and the
# features CI tests that crate with, and only if those miss it, with the
# whole workspace, then both again in release builds, and on Linux the
# platform crate's tests as root. A rule that exists in only one of those
# builds is still checked, and a mutant the first run catches costs no more.
#
# <out>/results.tsv gets a line for each run of each mutant: the outcome
# (caught, missed, timeout or unviable), a tab, and the mutant's name.
# <out>/cargo-mutants/ keeps each run's mutants.out.
set -euo pipefail

if [ "$#" -ne 4 ]; then
  echo "Usage: shard.sh <diff> <shard> <shards> <out>" >&2
  exit 2
fi
diff=$1 shard=$2 shards=$3 out=$4
os=${MUTANTS_OS:-}
# Every cargo goes through cargo.sh, for Windows (see token.ps1).
here=$(cd "$(dirname "$0")" && pwd)
case $os in
  linux | windows) ;;
  *) echo "MUTANTS_OS must be linux or windows." >&2; exit 2 ;;
esac
if ! [[ $shard =~ ^[0-9]+$ && $shards =~ ^[1-9][0-9]*$ ]] || [ "$shard" -ge "$shards" ]; then
  echo "The shard must be a number below the number of shards." >&2
  exit 2
fi

# Code built only for macOS. No job here runs on macOS, so its mutants would
# all look missed.
exclude=(--exclude 'crates/platform/src/macos/**')

# The features CI tests each crate with besides its defaults
# (.github/workflows/ci.yml, platform-*.yml).
own_features() {
  case $1 in
    ubc-vpn-engine) echo fake,debug-logs ;;
    ubc-vpn-platform | ubc-vpn-service | ubc-vpn-cli) echo dev-mode ;;
    *) echo "" ;;
  esac
}

# A list of mutant names as a cargo-mutants config that selects exactly
# those: each name as a regex matching only itself, in a TOML string.
to_config() {
  printf 'examine_re = [\n'
  sed -e 's/[][\\.+*?(){}|^$#&~-]/\\&/g' \
    -e 's/\\/\\\\/g' -e 's/"/\\"/g' \
    -e 's/^/  "^/' -e 's/$/$",/' "$1"
  printf ']\n'
}

mkdir -p "$out/lists" "$out/cargo-mutants"
: > "$out/results.tsv"
none=$out/lists/none.toml
: > "$none"

# Every mutant in the diff, crate by crate, then this shard's share.
: > "$out/lists/all.tsv"
for manifest in crates/*/Cargo.toml; do
  package=$(sed -n 's/^name = "\(.*\)"$/\1/p' "$manifest" | head -n 1)
  if [ -z "$package" ]; then
    echo "No package name in $manifest." >&2
    exit 1
  fi
  bash "$here/cargo.sh" mutants --list --colors=never --line-col=true --in-diff "$diff" \
    --config "$none" -p "$package" "${exclude[@]}" > "$out/lists/$package.txt"
  sed "s/^/$package\t/" "$out/lists/$package.txt" >> "$out/lists/all.tsv"
done
LC_ALL=C sort -t "$(printf '\t')" -k 2 "$out/lists/all.tsv" |
  awk -v k="$shard" -v n="$shards" '(NR - 1) % n == k' > "$out/lists/shard.tsv"
echo "$(wc -l < "$out/lists/all.tsv") mutants in the diff, $(wc -l < "$out/lists/shard.tsv") of them in shard $shard of $shards."

# Runs cargo-mutants once over the mutants of $package that no earlier run
# caught, then proves the same tests still pass without any mutation, so a
# mutant that left the machine broken cannot pass for caught.
#   run <name> <cargo-mutants arguments...> -- <cargo test arguments...>
prefix=()
run() {
  local name=$1
  shift
  local margs=() targs=()
  while [ "$1" != "--" ]; do margs+=("$1"); shift; done
  shift
  targs=("$@")
  local remaining=$out/lists/$package.remaining
  if ! [ -s "$remaining" ]; then
    return 0
  fi
  local dir=$out/cargo-mutants/$package/$name
  mkdir -p "$dir"
  to_config "$remaining" > "$dir.toml"
  local count status=0
  count=$(wc -l < "$remaining")
  echo "::group::$package, $name: $count mutants"
  "${prefix[@]}" bash "$here/cargo.sh" mutants --in-place --cap-lints=true --colors=never \
    --in-diff "$diff" --config "$dir.toml" -p "$package" "${exclude[@]}" \
    --output "$dir" "${margs[@]}" || status=$?
  echo "::endgroup::"
  # 2 is a missed mutant and 3 a timeout, which the summary reports.
  case $status in
    0 | 2 | 3) ;;
    *) echo "cargo-mutants stopped with status $status: $package, $name." >&2; exit 1 ;;
  esac
  local tested=0 outcome file
  for outcome in caught missed timeout unviable; do
    file=$dir/mutants.out/$outcome.txt
    if [ -f "$file" ]; then
      sed "s/^/$outcome\t/" "$file" >> "$out/results.tsv"
      tested=$((tested + $(wc -l < "$file")))
    fi
  done
  # Every mutant asked for must have been tested, or a name the config did
  # not match would pass unnoticed.
  if [ "$tested" -ne "$count" ]; then
    echo "cargo-mutants tested $tested of $count mutants: $package, $name." >&2
    exit 1
  fi
  cat "$dir/mutants.out/caught.txt" "$dir/mutants.out/timeout.txt" 2> /dev/null |
    grep -vxF -f - "$remaining" > "$remaining.next" || true
  mv "$remaining.next" "$remaining"
  echo "::group::$package, $name: the tests pass without a mutation"
  if ! "${prefix[@]}" bash "$here/cargo.sh" test --locked "${targs[@]}"; then
    echo "::endgroup::"
    echo "The tests fail without a mutation after $package, $name: its results cannot be trusted." >&2
    exit 1
  fi
  echo "::endgroup::"
}

while IFS= read -r package; do
  awk -F '\t' -v p="$package" '$1 == p { print $2 }' "$out/lists/shard.tsv" > "$out/lists/$package.remaining"
  features=$(own_features "$package")
  own=()
  if [ -n "$features" ]; then own=(--features "$features"); fi
  run own "${own[@]}" -- -p "$package" "${own[@]}"
  run workspace --test-workspace=true -- --workspace
  run own-release "${own[@]}" --profile=release -- -p "$package" "${own[@]}" --release
  run workspace-release --test-workspace=true --profile=release -- --workspace --release
  # The channel's rules that only root can test (platform-unix.yml).
  if [ "$os" = linux ] && [ "$package" = ubc-vpn-platform ]; then
    prefix=(sudo env "PATH=$PATH" "HOME=$HOME" UBC_VPN_REQUIRE_ROOT=1)
    run root --features dev-mode -- -p "$package" --features dev-mode
    prefix=()
    sudo chown -R "$(id -u):$(id -g)" . "$out" "$HOME/.cargo" "$HOME/.rustup"
  fi
done < <(cut -f 1 "$out/lists/shard.tsv" | sort -u)
