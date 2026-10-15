# When UBC VPN cannot reach its service

The app and the `ubc-vpn` command control a small service that runs in the background with administrator rights. When they cannot reach it, `ubc-vpn` says which of these it is, and exits with the status shown.

## "UBC VPN is not installed on this computer" (status 3)

There is no UBC VPN service on this computer. Install UBC VPN, then try again.

## "The UBC VPN service is installed but not running" (status 3)

UBC VPN is installed, but its service is stopped. Restarting the computer starts it again. To start it without restarting:

- **Windows:** open a command prompt as an administrator and run `sc start ubc-vpn`. You can also start "UBC VPN Service" from the Services window.

If it stops again straight away, reinstall UBC VPN.

## "You are not the owner" (status 5)

Only one user of a computer can control UBC VPN: the first one to use it after it was installed. Ask that user to connect for you.

To make yourself the owner, an administrator deletes the file `state.json` from UBC VPN's state folder and restarts the service. The next user to run UBC VPN then becomes the owner.

| System | State folder |
| --- | --- |
| Windows | `%ProgramData%\UBC VPN\` |
| macOS | `/Library/Application Support/UBC VPN/` |
| Linux | `/var/lib/ubc-vpn/` |

## "Another program is answering in place of the UBC VPN service" (status 6)

Something other than UBC VPN is listening where the service should be, and UBC VPN sent it nothing. Restart the computer. If it happens again, reinstall UBC VPN.

# When connecting fails

## "The VPN server's certificate has changed" (status 1)

The VPN server answered with a certificate that this version of UBC VPN does not recognise, so UBC VPN sent it nothing: not your password, and not your session. Either UBC has replaced the server's certificate, or the network you are on is intercepting the connection, as some hotel and café networks do.

1. Update UBC VPN to the latest version, then connect again.
2. If UBC VPN is already up to date, try another network.
