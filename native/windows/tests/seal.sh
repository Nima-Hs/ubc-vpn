#!/usr/bin/env bash
# Records what the build output contains before Process Monitor, a program we
# cannot pin, is downloaded and run as administrator, and checks afterwards
# that the output is still exactly that. Run from Git Bash.
#
#   seal.sh record <list>   writes the SHA-256 of every file the output will
#                           hold when it is uploaded
#   seal.sh verify <list>   fails if a file differs, is missing or was added
#   seal.sh self-test       shows that verify notices each of those
#
# The workflow uploads the list as an artifact of its own before the trace
# runs, and verifies against a copy downloaded afresh, so a program on the
# build machine cannot change the output and the record of it together without
# also interfering with GitHub's artifact store.
#
# This catches a tool that alters the output by accident or in passing. It
# does not stop a program running as administrator that sets out to defeat it:
# such a program can change this check, or the files after the check and
# before the upload. See README.md.
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

# verify_folder <folder> <list>: succeeds only if the folder holds exactly the
# files in the list, each with the checksum listed.
verify_folder() {
    local now
    now=$(mktemp)
    record_folder "$1" "$now"
    if ! diff "$2" "$now"; then
        rm -f "$now"
        return 1
    fi
    rm -f "$now"
}

case ${1:-} in
record)
    list=$2
    mkdir -p "$(dirname "$list")"
    record_folder "$out" "$list"
    # The manifest is the one file that changes after this: approve.sh marks
    # the output shippable once the trace has passed. Record it as it will be
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
    [ -s "$list" ] || die "the list $list is missing or empty"
    verify_folder "$out" "$list" ||
        die "the output is not what was recorded before the trace: '<' is the record, '>' is the output now"
    echo "The output's $(wc -l <"$list") files match the record made before the trace."
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
    echo "first" >"$dir/out/bin/a.dll"
    echo "extra" >"$dir/out/bin/b.dll"
    ! verify_folder "$dir/out" "$dir/list" >/dev/null || die "self-test: an added file went unnoticed"
    rm "$dir/out/bin/b.dll" "$dir/out/manifest.json"
    ! verify_folder "$dir/out" "$dir/list" >/dev/null || die "self-test: a removed file went unnoticed"
    rm -rf "$dir"
    echo "Self-test: a changed byte, an added file and a removed file each fail the check."
    ;;
*)
    die "usage: seal.sh record <list> | verify <list> | self-test"
    ;;
esac
