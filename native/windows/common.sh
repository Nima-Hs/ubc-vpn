# Shared by the scripts in this folder. Source it; do not run it.

PREFIX=/ucrt64
MINGW_PACKAGES=https://repo.msys2.org/mingw/ucrt64
MSYS_PACKAGES=https://repo.msys2.org/msys/x86_64
SOURCES=https://repo.msys2.org/mingw/sources

# The GnuTLS release gnutls.sh builds. Its SHA-256 is in sources.lock.
GNUTLS_VERSION=3.8.13
GNUTLS_TARBALL=gnutls-$GNUTLS_VERSION.tar.xz
GNUTLS_URL=https://www.gnupg.org/ftp/gcrypt/gnutls/v3.8/$GNUTLS_TARBALL

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
work=$here/work
out=$here/out
gnutls=$here/cache/gnutls

die() {
    echo "error: $*" >&2
    exit 1
}

sha256() {
    sha256sum "$1" | cut -d' ' -f1
}

# Prints the SHA-256 a lock file gives for a file name, or stops.
locked_sha() {
    local sha
    sha=$(awk -v f="$2" '$2 == f { print $1 }' "$here/$1")
    [ -n "$sha" ] || die "$2 is not in $1"
    echo "$sha"
}

require_ucrt64() {
    [ "${MSYSTEM:-}" = UCRT64 ] || die "run this in an MSYS2 UCRT64 shell"
}

# collect_dlls <folder> <dll> <search dir>...
# Copies into <folder> every DLL that <folder>/<dll> needs, directly or not,
# taking each from the first search dir that has it. A DLL found in none of
# them must be part of Windows. Prints "<dll> <dir it came from>" per copy.
collect_dlls() {
    local dest=$1 system32 i name dir found
    local todo=("$2")
    shift 2
    system32=$(cygpath -u "$SYSTEMROOT")/System32
    for ((i = 0; i < ${#todo[@]}; i++)); do
        for name in $(objdump -p "$dest/${todo[i]}" | sed -n 's/^\s*DLL Name: //p'); do
            [ ! -e "$dest/$name" ] || continue
            found=""
            for dir in "$@"; do
                if [ -e "$dir/$name" ]; then
                    cp "$dir/$name" "$dest/"
                    todo+=("$name")
                    echo "$name $dir"
                    found=1
                    break
                fi
            done
            [ -n "$found" ] || [ -e "$system32/$name" ] || [[ ${name,,} == api-ms-win-* ]] ||
                die "$name, needed by ${todo[i]}, is neither in $* nor in $system32"
        done
    done
}
