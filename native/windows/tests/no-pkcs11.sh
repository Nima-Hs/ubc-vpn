#!/usr/bin/env bash
# Checks that the output cannot load a PKCS#11 module, which is code named by a
# configuration file. Run in an MSYS2 UCRT64 shell, after build.sh.
#
# build.sh has already checked that GnuTLS and OpenConnect were both configured
# without PKCS#11. This looks at what was actually built.
set -euo pipefail
. "$(dirname "$0")/../common.sh"
require_ucrt64

# No p11-kit, the library that finds and loads PKCS#11 modules.
! ls "$out/bin" | grep -i 'p11' || die "a p11-kit DLL is in the output"
for dll in "$out"/bin/*.dll; do
    ! objdump -p "$dll" | grep -i 'DLL Name: .*p11' || die "${dll##*/} imports p11-kit"
    ! { strings -a "$dll" && strings -a -e l "$dll"; } | grep -E 'p11_kit|p11-kit|C_GetFunctionList' ||
        die "${dll##*/} refers to p11-kit or to a PKCS#11 module's entry point"
done

# GnuTLS can load a library by name at run time. The only names it may hold are
# those of the two Windows libraries it loads that way for the system
# certificate and key stores.
gnutls_dll=$out/bin/libgnutls-30.dll
linked=$(objdump -p "$gnutls_dll" | sed -n 's/^\s*DLL Name: //p' | tr 'A-Z' 'a-z' | sort -u)
named=$({ strings -a "$gnutls_dll" && strings -a -e l "$gnutls_dll"; } |
    grep -i -E '^[A-Za-z0-9_.+-]+\.dll$' | tr 'A-Z' 'a-z' | sort -u)
by_name=$(comm -23 <(echo "$named") <(printf '%s\n' "$linked" libgnutls-30.dll | sort -u))
echo "libgnutls-30.dll is linked to: $(echo $linked)"
echo "libgnutls-30.dll names for loading at run time: $(echo $by_name)"
other=$(comm -23 <(echo "$by_name") <(printf 'crypt32.dll\nncrypt.dll\n'))
[ -z "$other" ] || die "libgnutls-30.dll may only name crypt32.dll and ncrypt.dll for loading at run time, not: $other"
