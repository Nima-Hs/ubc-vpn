# Our additions to the setup program electron-builder makes (nsis.include in
# app/electron-builder.yml). Each macro is a hook electron-builder calls if it
# is defined. The rules are in docs/architecture.md, "What the installers
# must do".

# Runs in .onInit, after electron-builder has chosen the folder.
#
# The app installs for the whole machine into Program Files, where only
# administrators can change it, and the service will run from there.
# electron-builder lets /D=<folder> choose another folder; in the packaging
# trial that installed into a folder ordinary users could write to. So a
# setup program given /D= stops, says why, and installs nothing.
#
# electron-builder's .onInit starts with SetOutPath $INSTDIR, which has
# already created the /D= folder, empty, and made it the working folder by
# the time this runs. So this leaves that folder and removes it. RMDir
# removes it only if it is empty; folders above it that SetOutPath made stay.
!macro customInit
  !insertmacro GetDParameter $R0
  ${if} $R0 != ""
    SetOutPath $TEMP
    RMDir $R0
    MessageBox MB_OK|MB_ICONSTOP "UBC VPN always installs in Program Files. The /D option is not supported. Nothing was installed." /SD IDOK
    SetErrorLevel 2
    Quit
  ${endif}
  # Also when a folder was recorded by an earlier install.
  StrCpy $INSTDIR "$PROGRAMFILES64\${APP_FILENAME}"
!macroend

# Runs at the end of every install and update, after the files are in place
# and before the app first runs.
#
# Files the installer writes are owned by the account that ran it, and
# Program Files hands that owner full control through its CREATOR OWNER
# entry. Where UAC is off, that account's ordinary programs could then
# replace the app's files. So the folder's owner and access list are set
# here, by SID, on every install and update:
#
# - owner: Administrators, on the folder and everything in it;
# - no entry set on the folder itself survives;
# - the folder's access list is protected, so nothing is inherited from
#   Program Files and there is no CREATOR OWNER entry;
# - SYSTEM, Administrators and TrustedInstaller have full control, and
#   Users read and execute, passed on to everything inside;
# - everything inside is reset to inherit just that.
#
# Any failure stops the install with an error, after removing everything
# this install put in place (see ubcVpnUndoInstall): electron-builder has
# already written the files, the uninstall entry and the shortcut, and a
# half-done install would leave the files owned by whoever ran it.
#
# Anything that must not run in a folder others could change, such as
# registering the service, comes after these steps, never before.
!define UBC_VPN_ACL_SYSTEM "*S-1-5-18"
!define UBC_VPN_ACL_ADMINS "*S-1-5-32-544"
!define UBC_VPN_ACL_INSTALLER "*S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
!define UBC_VPN_ACL_USERS "*S-1-5-32-545"

# Removes what this install has put in place so far: the app's folder, the
# Start menu and desktop shortcuts, and the uninstall and install entries.
!macro ubcVpnUndoInstall
  SetOutPath $TEMP
  RMDir /r "$INSTDIR"
  Delete "$newStartMenuLink"
  Delete "$newDesktopLink"
  DeleteRegKey SHELL_CONTEXT "${UNINSTALL_REGISTRY_KEY}"
  DeleteRegKey SHELL_CONTEXT "${INSTALL_REGISTRY_KEY}"
!macroend

# Runs one step, and on failure undoes the install and stops with an error.
#
# A setup program built to test that (packaging/windows/tests/fail-step.nsh)
# defines UBC_VPN_TEST_FAIL_STEP as a step's label, and that step then
# fails without running. The define exists only in that build.
!macro ubcVpnRun LABEL COMMAND
  !ifdef UBC_VPN_TEST_FAIL_STEP
    !if "${LABEL}" == "${UBC_VPN_TEST_FAIL_STEP}"
      StrCpy $0 "1"
    !else
      nsExec::ExecToLog '${COMMAND}'
      Pop $0
    !endif
  !else
    nsExec::ExecToLog '${COMMAND}'
    Pop $0
  !endif
  ${if} $0 != 0
    !insertmacro ubcVpnUndoInstall
    MessageBox MB_OK|MB_ICONSTOP "UBC VPN could not secure its folder (${LABEL}, $0). Nothing was installed; run the setup program again." /SD IDOK
    SetErrorLevel 2
    Abort
  ${endif}
!macroend

!macro customInstall
  # Only the updater uses it, and there is none.
  Delete "$INSTDIR\resources\elevate.exe"

  !insertmacro ubcVpnRun "owner" '"$SYSDIR\icacls.exe" "$INSTDIR" /setowner ${UBC_VPN_ACL_ADMINS} /T /C /Q'
  # Drops any entry set on the folder itself, so the next step leaves only
  # the four below.
  !insertmacro ubcVpnRun "reset" '"$SYSDIR\icacls.exe" "$INSTDIR" /reset /Q'
  !insertmacro ubcVpnRun "access list" '"$SYSDIR\icacls.exe" "$INSTDIR" /inheritance:r /grant:r ${UBC_VPN_ACL_SYSTEM}:(OI)(CI)F ${UBC_VPN_ACL_ADMINS}:(OI)(CI)F ${UBC_VPN_ACL_INSTALLER}:(OI)(CI)F ${UBC_VPN_ACL_USERS}:(OI)(CI)RX /Q'
  !insertmacro ubcVpnRun "contents" '"$SYSDIR\icacls.exe" "$INSTDIR\*" /reset /T /C /Q'
!macroend
