#!/bin/bash
# What the Linux packages run once their files are in place: the .deb's
# postinst and the .rpm's %post. electron-builder fills in this file
# (app/electron-builder.linux.yml) as it does its own script, so every
# dollar sign followed by a brace is one of its names: our own shell
# variables are written without braces.
#
# The arguments say why it runs:
#   .deb  `configure` with the version it replaces, empty on a first
#         install; `abort-upgrade`, `abort-remove` or `abort-deconfigure`
#         when dpkg puts back a version after a failed step.
#   .rpm  the number of versions installed once this one is: 1 on a first
#         install, 2 on an upgrade.
#
# It is safe to run again: electron-builder's part sets the same things
# again, and `install` brings an installed service up to date.

# electron-builder's own script for its packages, as it supplies it
# (app-builder-lib/templates/linux/after-install.tpl), unchanged: the
# /usr/bin link to the app, the sandbox helper, and the AppArmor profile
# the sandbox needs on Ubuntu 24.04. `check:package:linux` fails unless the
# package's script holds it as the pinned electron-builder has it.
electron_builder_after_install() {

if type update-alternatives >/dev/null 2>&1; then
    # Remove previous link if it doesn't use update-alternatives
    if [ -L '/usr/bin/${executable}' -a -e '/usr/bin/${executable}' -a "`readlink '/usr/bin/${executable}'`" != '/etc/alternatives/${executable}' ]; then
        rm -f '/usr/bin/${executable}'
    fi
    update-alternatives --install '/usr/bin/${executable}' '${executable}' '/opt/${sanitizedProductName}/${executable}' 100 || ln -sf '/opt/${sanitizedProductName}/${executable}' '/usr/bin/${executable}'
else
    ln -sf '/opt/${sanitizedProductName}/${executable}' '/usr/bin/${executable}'
fi

# Check if user namespaces are supported by the kernel and working with a quick test:
if ! { [[ -L /proc/self/ns/user ]] && unshare --user true; }; then
    # Use SUID chrome-sandbox only on systems without user namespaces:
    chmod 4755 '/opt/${sanitizedProductName}/chrome-sandbox' || true
else
    chmod 0755 '/opt/${sanitizedProductName}/chrome-sandbox' || true
fi

if hash update-mime-database 2>/dev/null; then
    update-mime-database /usr/share/mime || true
fi

if hash update-desktop-database 2>/dev/null; then
    update-desktop-database /usr/share/applications || true
fi

# Install apparmor profile. (Ubuntu 24+)
# First check if the version of AppArmor running on the device supports our profile.
# This is in order to keep backwards compatibility with Ubuntu 22.04 which does not support abi/4.0.
# In that case, we just skip installing the profile since the app runs fine without it on 22.04.
#
# Those apparmor_parser flags are akin to performing a dry run of loading a profile.
# https://wiki.debian.org/AppArmor/HowToUse#Dumping_profiles
#
# Unfortunately, at the moment AppArmor doesn't have a good story for backwards compatibility.
# https://askubuntu.com/questions/1517272/writing-a-backwards-compatible-apparmor-profile
if apparmor_status --enabled > /dev/null 2>&1; then
  APPARMOR_PROFILE_SOURCE='/opt/${sanitizedProductName}/resources/apparmor-profile'
  APPARMOR_PROFILE_TARGET='/etc/apparmor.d/${executable}'
  if apparmor_parser --skip-kernel-load --debug "$APPARMOR_PROFILE_SOURCE" > /dev/null 2>&1; then
    cp -f "$APPARMOR_PROFILE_SOURCE" "$APPARMOR_PROFILE_TARGET"

    # Updating the current AppArmor profile is not possible and probably not meaningful in a chroot'ed environment.
    # Use cases are for example environments where images for clients are maintained.
    # There, AppArmor might correctly be installed, but live updating makes no sense.
    if ! { [ -x '/usr/bin/ischroot' ] && /usr/bin/ischroot; } && hash apparmor_parser 2>/dev/null; then
      # Extra flags taken from dh_apparmor:
      # > By using '-W -T' we ensure that any abstraction updates are also pulled in.
      # https://wiki.debian.org/AppArmor/Contribute/FirstTimeProfileImport
      apparmor_parser --replace --write-cache --skip-read-cache "$APPARMOR_PROFILE_TARGET"
    fi
  else
    echo "Skipping the installation of the AppArmor profile as this version of AppArmor does not seem to support the bundled profile"
  fi
fi
}

# Run first, as electron-builder runs it: without stopping at a failing
# command, and failing as its script would, with the last one's status.
electron_builder_after_install || exit $?

set -e
SERVICE="/opt/UBC VPN/resources/bin/ubc-vpn-service"
POLICY="/opt/UBC VPN/resources/policy.json"

# A first install empties a policy or state folder anyone may have made
# before it, unless it holds an owner the service would accept (see
# `install --fresh`). Anything else is an update, which keeps state.json,
# and with it the owner.
fresh=
case "$1" in
    configure) [ -n "$2" ] || fresh=--fresh ;;
    1) fresh=--fresh ;;
esac

# The service is a systemd unit, and `install` starts it. Where systemd is
# not running, as in a container, the app is installed without it.
if [ ! -d /run/systemd/system ]; then
    echo "systemd is not running, so the UBC VPN service was not installed." >&2
    echo "Once it runs, install the service as root with:" >&2
    echo "  \"$SERVICE\" install --policy \"$POLICY\"" >&2
    exit 0
fi

# Copies the policy to /etc/ubc-vpn/policy.json, where the service reads it
# (so it is never one of dpkg's conffiles), registers the unit and starts
# it. It checks the service's folder first, and stops if anyone but root
# could change it. Nothing of this script's environment reaches it.
env -i "$SERVICE" install --policy "$POLICY" $fresh
