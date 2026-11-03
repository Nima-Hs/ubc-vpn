#!/bin/bash
# What the Linux packages run once their files are removed: the .deb's
# postrm and the .rpm's %postun. electron-builder fills in this file
# (app/electron-builder.linux.yml) as it does its own script, so every
# dollar sign followed by a brace is one of its names: our own shell
# variables are written without braces.
#
# The arguments say why it runs:
#   .deb  `remove`, then `purge` when the package is purged; `upgrade` when
#         a new version replaces this one; `abort-install` or
#         `abort-upgrade` when dpkg undoes a failed step.
#   .rpm  the number of versions left installed: 0 on a removal, 1 on an
#         upgrade. An .rpm has no purge, so a removal is one.
#
# On an upgrade it does nothing: state.json, and with it the owner, stays,
# and the new version's script has already run on an .rpm. It is safe to
# run again.

# electron-builder's own script for its packages, as it supplies it
# (app-builder-lib/templates/linux/after-remove.tpl), unchanged: it
# removes the /usr/bin link to the app and the AppArmor profile.
# `check:package:linux` fails unless the package's script holds it as the
# pinned electron-builder has it. Run on a removal only: on an .rpm upgrade
# this runs after the new version's install script, and would remove what
# that set up.
electron_builder_after_remove() {

# Delete the link to the binary
# update-alternatives --remove <name> <path>: 'path' must be the registered alternative binary,
# not the generic symlink — see https://man7.org/linux/man-pages/man1/update-alternatives.1.html
if type update-alternatives >/dev/null 2>&1; then
    update-alternatives --remove '${executable}' '/opt/${sanitizedProductName}/${executable}'
else
    rm -f '/usr/bin/${executable}'
fi

APPARMOR_PROFILE_DEST='/etc/apparmor.d/${executable}'

# Remove and unload apparmor profile.
if [ -f "$APPARMOR_PROFILE_DEST" ]; then
  # Unload the profile from the running kernel before deleting the file so the
  # policy is not left enforced until the next reboot.  Mirror the chroot guard
  # used in the after-install script — live AppArmor operations are not
  # meaningful inside a chroot.
  # https://wiki.debian.org/AppArmor/HowToUse
  if apparmor_status --enabled > /dev/null 2>&1; then
    if ! { [ -x '/usr/bin/ischroot' ] && /usr/bin/ischroot; } && hash apparmor_parser 2>/dev/null; then
      apparmor_parser --remove "$APPARMOR_PROFILE_DEST" || true
    fi
  fi
  rm -f "$APPARMOR_PROFILE_DEST"
fi
}

case "$1" in
    remove | purge | abort-install | 0)
        # As electron-builder runs it: without stopping at a failing
        # command, and failing as its script would.
        electron_builder_after_remove || exit $?
        ;;
esac

set -e
# Purging removes the service's data: the policy and state folders, which
# `uninstall` already removed if systemd ran at the removal, and the unit
# and its link if it did not. Nothing else in them is anyone's but the
# service's.
remove_data() {
    rm -rf /etc/ubc-vpn /var/lib/ubc-vpn
    rm -f /etc/systemd/system/ubc-vpn.service /etc/systemd/system/multi-user.target.wants/ubc-vpn.service
}
case "$1" in
    purge) remove_data ;;
    0)
        remove_data
        # rpm leaves the app's own folders behind, empty.
        rm -rf "/opt/UBC VPN"
        ;;
esac
