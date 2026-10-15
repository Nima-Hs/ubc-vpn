#!/usr/bin/env bash
# Copies the pinned Visual C++ runtime DLL from the build machine's Visual
# Studio into a folder, for the installer to put beside our programs.
#
#   packaging/windows/vcruntime.sh <out-dir>
#
# It stops, and says what it found, unless the Visual Studio edition, its
# version line, the redistributable's version and every file's SHA-256 are
# exactly those in vcruntime.lock. Run it in Git Bash on Windows.

set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
lock="$here/vcruntime.lock"
out=${1:?usage: vcruntime.sh <out-dir>}

value() { sed -n "s/^$1=//p" "$lock"; }
product=$(value VC_PRODUCT)
line=$(value VC_PRODUCT_LINE_VERSION)
version=$(value VC_REDIST_VERSION)
folder=$(value VC_CRT_FOLDER)

# vswhere is installed at this fixed place by the Visual Studio installer.
vswhere="/c/Program Files (x86)/Microsoft Visual Studio/Installer/vswhere.exe"
property() {
  "$vswhere" -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 \
    -property "$1" | tr -d '\r'
}
install=$(property installationPath)
found_product=$(property productId)
found_line=$(property catalog_productLineVersion)
echo "Visual Studio: $found_product $found_line ($(property catalog_productDisplayVersion)) at $install"

failed=0
if [ "$found_product" != "$product" ] || [ "$found_line" != "$line" ]; then
  echo "error: the lock is for $product $line, and its licence terms are what ships"
  failed=1
fi
redist="$(cygpath -u "$install")/VC/Redist/MSVC"
echo "Redistributable versions here: $(ls "$redist" | tr '\n' ' ')"
source="$redist/$version/x64/$folder"
mkdir -p "$out"
while read -r sum name; do
  file="$source/$name"
  if [ ! -f "$file" ]; then
    echo "error: $file is missing"
    failed=1
    continue
  fi
  actual=$(sha256sum "$file" | cut -d' ' -f1)
  if [ "$actual" != "$sum" ]; then
    echo "error: $name is $actual, not $sum"
    failed=1
    continue
  fi
  cp "$file" "$out/$name"
  echo "$name $version $actual"
done < <(grep -E '^[0-9a-f]{64}  ' "$lock")

if [ "$failed" != 0 ]; then
  for name in $(grep -E '^[0-9a-f]{64}  ' "$lock" | awk '{print $2}'); do
    for candidate in "$redist"/*/x64/Microsoft.VC*.CRT/"$name"; do
      [ -f "$candidate" ] && echo "found: $(sha256sum "$candidate" | cut -d' ' -f1)  $candidate"
    done
  done
  exit 1
fi
