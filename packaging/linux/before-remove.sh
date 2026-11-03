#!/bin/sh
# What the Linux packages run before their files are removed: the .deb's
# prerm and the .rpm's %preun. fpm takes it as it is (electron-builder
# supplies no script for this step).
#
# The arguments say why it runs:
#   .deb  `remove`; `upgrade` when a new version replaces this one;
#         `deconfigure` or `failed-upgrade` in dpkg's other paths.
#   .rpm  the number of versions left installed: 0 on a removal, 1 on an
#         upgrade.
#
# Only a removal removes the service. An upgrade leaves it, and its
# state.json with the owner, as they are: the new version's install script
# stops it, brings the unit up to date and starts it again. It is safe to
# run again: `uninstall` with nothing installed does nothing.
set -e
SERVICE="/opt/UBC VPN/resources/bin/ubc-vpn-service"

case "$1" in
    remove | 0) ;;
    *) exit 0 ;;
esac

# Without systemd, as in a container, no service was installed.
if [ ! -d /run/systemd/system ]; then
    exit 0
fi

# Stops the service, which removes its routes and DNS first, removes the
# unit, and removes /etc/ubc-vpn and /var/lib/ubc-vpn, as the Windows
# uninstaller does. The user's own settings stay. Nothing of this script's
# environment reaches it.
/usr/bin/env -i "$SERVICE" uninstall
