#!/usr/bin/env bash
# Records what the build output contains, so that the jobs which later fetch a
# copy of it from GitHub can check they have exactly that. Runs in Git Bash on
# Windows and in bash on Linux.
#
#   seal.sh record <list>
#       writes the SHA-256 of every file the output will hold when it is
#       uploaded for use
#   seal.sh verify <list> <sha256 of the list> [before-approval]
#       fails if the list is not the one with that checksum, or if a file of
#       the output differs from the list, is missing or was added.
#       "before-approval" leaves the manifest out, which approve.sh has yet to
#       change.
#   seal.sh self-test
#       shows that verify notices each of those
#
# The build job makes the list and gives out its checksum as a job output. See
# README.md for what this does and does not protect against.
set -euo pipefail

here=$(cd "$(dirname "$0")/.." && pwd)
out=$here/out

die() {
    echo "error: $*" >&2
    exit 1
}

# record_folder <folder> <list>: one "<sha256>  <path>" line per file.
record_folder() {
    (cd "$1" && find . -type f | LC_ALL=C sort | while read -r file; do
        echo "$(sha256sum "$file" | cut -d' ' -f1)  $file"
    done) >"$2"
}

# verify_folder <folder> <list> [before-approval]: succeeds only if the folder
# holds exactly the files in the list, each with the checksum listed.
verify_folder() {
    local dir
    dir=$(mktemp -d)
    record_folder "$1" "$dir/now"
    cp "$2" "$dir/then"
    if [ "${3:-}" = before-approval ]; then
        sed -i '/  \.\/manifest\.json$/d' "$dir/now" "$dir/then"
    fi
    if ! diff "$dir/then" "$dir/now"; then
        rm -rf "$dir"
        return 1
    fi
    rm -rf "$dir"
}

case ${1:-} in
record)
    list=$2
    mkdir -p "$(dirname "$list")"
    record_folder "$out" "$list"
    # The manifest is the one file that changes after this: approve.sh marks
    # the output shippable once every test has passed. Record it as it will be
    # then, by running approve.sh on a copy.
    copy=$(mktemp -d)
    cp "$out/manifest.json" "$copy/"
    "$here/tests/approve.sh" "$copy/manifest.json" >/dev/null
    approved=$(sha256sum "$copy/manifest.json" | cut -d' ' -f1)
    rm -rf "$copy"
    grep -q '  \./manifest\.json$' "$list" || die "the output has no manifest.json"
    sed -i "s|^[0-9a-f]*  \./manifest\.json\$|$approved  ./manifest.json|" "$list"
    echo "Recorded $(wc -l <"$list") files. SHA-256 of the list: $(sha256sum "$list" | cut -d' ' -f1)"
    ;;
verify)
    list=$2
    expected=$3
    [ -s "$list" ] || die "the list $list is missing or empty"
    [[ $expected =~ ^[0-9a-f]{64}$ ]] || die "no checksum for the list was given"
    actual=$(sha256sum "$list" | cut -d' ' -f1)
    [ "$actual" = "$expected" ] ||
        die "the list is not the one the build job made: its SHA-256 is $actual, the build job gave out $expected"
    [ -f "$out/manifest.json" ] || die "the output has no manifest.json"
    verify_folder "$out" "$list" "${4:-}" ||
        die "the output is not what the build job recorded: '<' is the record, '>' is the output now"
    echo "The list is the build job's, and the output matches it${4:+, the manifest aside}."
    ;;
self-test)
    dir=$(mktemp -d)
    mkdir -p "$dir/out/bin"
    echo "first" >"$dir/out/bin/a.dll"
    echo "second" >"$dir/out/manifest.json"
    record_folder "$dir/out" "$dir/list"
    verify_folder "$dir/out" "$dir/list" >/dev/null || die "self-test: an unchanged folder does not verify"
    echo "firsu" >"$dir/out/bin/a.dll"
    ! verify_folder "$dir/out" "$dir/list" >/dev/null || die "self-test: a changed byte went unnoticed"
    ! verify_folder "$dir/out" "$dir/list" before-approval >/dev/null ||
        die "self-test: a changed byte went unnoticed before approval"
    echo "first" >"$dir/out/bin/a.dll"
    echo "changed" >"$dir/out/manifest.json"
    ! verify_folder "$dir/out" "$dir/list" >/dev/null || die "self-test: a changed manifest went unnoticed"
    verify_folder "$dir/out" "$dir/list" before-approval >/dev/null ||
        die "self-test: before approval, the manifest is not left out"
    echo "second" >"$dir/out/manifest.json"
    echo "extra" >"$dir/out/bin/b.dll"
    ! verify_folder "$dir/out" "$dir/list" >/dev/null || die "self-test: an added file went unnoticed"
    rm "$dir/out/bin/b.dll" "$dir/out/bin/a.dll"
    ! verify_folder "$dir/out" "$dir/list" >/dev/null || die "self-test: a removed file went unnoticed"
    rm -rf "$dir"
    echo "Self-test: a changed byte, a changed manifest, an added file and a removed file each fail the check."
    ;;
*)
    die "usage: seal.sh record <list> | verify <list> <sha256 of the list> [before-approval] | self-test"
    ;;
esac
