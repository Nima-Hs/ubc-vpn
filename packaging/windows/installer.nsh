# Our additions to the setup program electron-builder makes (nsis.include in
# app/electron-builder.yml). Each macro is a hook electron-builder calls if it
# is defined. The rules are in docs/architecture.md, "What the installers
# must do".

# Exit codes of our own, apart from /D= (2), so a test can tell which path
# ran: the folder could not be secured, the service could not be installed,
# the folder holds another product, and (the uninstaller) the service could
# not be removed.
!define UBC_VPN_EXIT_NOT_SECURED 3
!define UBC_VPN_EXIT_SERVICE_FAILED 4
!define UBC_VPN_EXIT_FOREIGN_FOLDER 5
!define UBC_VPN_EXIT_SERVICE_NOT_REMOVED 6

# Declining the licence page, or cancelling on any page before the install
# starts: nothing has been written but the empty folder electron-builder's
# .onInit makes, which is removed here. RMDir removes it only if it is empty,
# so an earlier install there is untouched.
!ifndef BUILD_UNINSTALLER
  # Whether our own earlier install is in the folder (see customInit).
  Var ubcVpnEarlierInstall
  !define MUI_CUSTOMFUNCTION_ABORT ubcVpnUserAbort
  Function ubcVpnUserAbort
    SetOutPath $TEMP
    RMDir $INSTDIR
  FunctionEnd
!endif

# Runs in .onInit, after electron-builder has chosen the folder.
#
# The app installs for the whole machine into Program Files, where only
# administrators can change it, and the service runs from there.
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

  # Another product may already be in that folder: an earlier UBC VPN
  # client used the same one. Installing over it would mix two products'
  # files and take its folder's ownership away, so the setup program stops,
  # says so, and changes nothing. The folder is ours only when our own
  # install entry names it. electron-builder's .onInit has already made the
  # folder if it was missing, so only one with something in it counts.
  #
  # Whether our own earlier install is here is read now, before the earlier
  # version's uninstaller removes its entry. An install over it is an update
  # whether or not the updater started it, so it keeps the data folder and
  # the owner in it.
  ReadRegStr $R2 HKLM "${INSTALL_REGISTRY_KEY}" InstallLocation
  ${if} $R2 == $INSTDIR
    StrCpy $ubcVpnEarlierInstall "1"
  ${else}
    StrCpy $ubcVpnEarlierInstall ""
  ${endif}
  StrCpy $R1 ""
  FindFirst $R3 $R4 "$INSTDIR\*.*"
  ubcVpnForeignNext:
    StrCmp $R4 "" ubcVpnForeignDone
    StrCmp $R4 "." ubcVpnForeignSkip
    StrCmp $R4 ".." ubcVpnForeignSkip
    StrCpy $R1 "occupied"
    Goto ubcVpnForeignDone
  ubcVpnForeignSkip:
    FindNext $R3 $R4
    Goto ubcVpnForeignNext
  ubcVpnForeignDone:
  FindClose $R3
  ${if} $R1 == "occupied"
    ${if} $ubcVpnEarlierInstall != "1"
      SetOutPath $TEMP
      MessageBox MB_OK|MB_ICONSTOP "$INSTDIR already holds another program, perhaps an earlier UBC VPN client. Uninstall it first, then run this setup program again. Nothing was changed." /SD IDOK
      SetErrorLevel ${UBC_VPN_EXIT_FOREIGN_FOLDER}
      Quit
    ${endif}
  ${endif}
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
# The service is registered after these steps, never before: it must not
# run from a folder others could change.
!define UBC_VPN_ACL_SYSTEM "*S-1-5-18"
!define UBC_VPN_ACL_ADMINS "*S-1-5-32-544"
!define UBC_VPN_ACL_INSTALLER "*S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
!define UBC_VPN_ACL_USERS "*S-1-5-32-545"

# Removes what this install has put in place so far: the service, the app's
# folder, the Start menu and desktop shortcuts, and the uninstall and
# install entries.
!define UBC_VPN_SERVICE_PROGRAM "$INSTDIR\resources\bin\ubc-vpn-service.exe"
!macro ubcVpnUndoInstall
  SetOutPath $TEMP
  # First the service, if it is there: `uninstall` stops it, which removes
  # its routes and DNS, waits until it has stopped, and deletes it. Only then
  # is its folder removed. Its result is not checked: the rest of the undo
  # goes ahead either way.
  #
  # On an update the data folder stays: the earlier version's uninstaller
  # kept it, with the owner in state.json, and a failed update must not
  # lose that. Anyone could make an update fail (by holding the service's
  # pipe name while it starts, say), so deleting it would let them reset
  # the owner. Only a failed first install removes it.
  ${if} ${FileExists} "${UBC_VPN_SERVICE_PROGRAM}"
    ${if} ${isUpdated}
    ${orIf} $ubcVpnEarlierInstall == "1"
      nsExec::ExecToLog '"${UBC_VPN_SERVICE_PROGRAM}" uninstall --keep-data'
    ${else}
      nsExec::ExecToLog '"${UBC_VPN_SERVICE_PROGRAM}" uninstall'
    ${endif}
    Pop $1
  ${endif}
  RMDir /r "$INSTDIR"
  Delete "$newStartMenuLink"
  Delete "$newDesktopLink"
  DeleteRegKey SHELL_CONTEXT "${UNINSTALL_REGISTRY_KEY}"
  DeleteRegKey SHELL_CONTEXT "${INSTALL_REGISTRY_KEY}"
!macroend

# Runs one step, and on failure undoes the install and stops with EXIT.
#
# No step uses icacls /C: with it, icacls carries on past a file it cannot
# change and still exits 0, so a partly secured folder would count as done.
# Without it, icacls stops at the first such file with a non-zero code.
#
# A setup program built to test that (packaging/windows/tests/fail-step.nsh)
# defines UBC_VPN_TEST_FAIL_STEP as a step's label, and that step then
# fails without running. The define exists only in that build.
!macro ubcVpnStep LABEL COMMAND EXIT WHAT
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
    MessageBox MB_OK|MB_ICONSTOP "UBC VPN could not ${WHAT} (${LABEL}, $0). The install was undone, and UBC VPN is not installed; run the setup program again." /SD IDOK
    SetErrorLevel ${EXIT}
    Quit
  ${endif}
!macroend

!macro ubcVpnRun LABEL COMMAND
  !insertmacro ubcVpnStep "${LABEL}" '${COMMAND}' ${UBC_VPN_EXIT_NOT_SECURED} "secure its folder"
!macroend

!macro customInstall
  # Only the updater uses it, and there is none.
  Delete "$INSTDIR\resources\elevate.exe"

  !insertmacro ubcVpnRun "owner" '"$SYSDIR\icacls.exe" "$INSTDIR" /setowner ${UBC_VPN_ACL_ADMINS} /T /Q'
  # Drops any entry set on the folder itself, so the next step leaves only
  # the four below.
  !insertmacro ubcVpnRun "reset" '"$SYSDIR\icacls.exe" "$INSTDIR" /reset /Q'
  !insertmacro ubcVpnRun "access list" '"$SYSDIR\icacls.exe" "$INSTDIR" /inheritance:r /grant:r ${UBC_VPN_ACL_SYSTEM}:(OI)(CI)F ${UBC_VPN_ACL_ADMINS}:(OI)(CI)F ${UBC_VPN_ACL_INSTALLER}:(OI)(CI)F ${UBC_VPN_ACL_USERS}:(OI)(CI)RX /Q'
  !insertmacro ubcVpnRun "contents" '"$SYSDIR\icacls.exe" "$INSTDIR\*" /reset /T /Q'

  # Only now that the folder is secured: the service. `install` checks the
  # folder itself again, makes the data folder and writes the policy into
  # it, registers the service and starts it. A first install empties a data
  # folder someone else may have made; an update keeps the state in it.
  ${if} ${isUpdated}
  ${orIf} $ubcVpnEarlierInstall == "1"
    StrCpy $R5 ""
  ${else}
    StrCpy $R5 " --fresh"
  ${endif}
  !insertmacro ubcVpnStep "service" '"${UBC_VPN_SERVICE_PROGRAM}" install --policy "$INSTDIR\resources\policy.json"$R5' ${UBC_VPN_EXIT_SERVICE_FAILED} "install its service"
  # A step only the test builds have, to fail once the service is registered
  # and running, so the undo is seen removing it.
  !ifdef UBC_VPN_TEST_FAIL_STEP
    !insertmacro ubcVpnStep "after service" '"$SYSDIR\cmd.exe" /c exit 0' ${UBC_VPN_EXIT_SERVICE_FAILED} "install its service"
  !endif
!macroend

# Runs in the uninstaller before any file is removed, for an uninstall and
# for the old version's removal during an update. The service is stopped,
# which removes its routes and DNS, waits until it has, and is deleted;
# with an uninstall the data folder (policy and state) goes too, and with an
# update it stays, so the owner is kept. If that fails nothing is removed:
# the service would otherwise be left pointing at files that are gone.
!macro customUnInstall
  ${if} ${FileExists} "${UBC_VPN_SERVICE_PROGRAM}"
    ${if} ${isUpdated}
      nsExec::ExecToLog '"${UBC_VPN_SERVICE_PROGRAM}" uninstall --keep-data'
    ${else}
      nsExec::ExecToLog '"${UBC_VPN_SERVICE_PROGRAM}" uninstall'
    ${endif}
    Pop $0
    ${if} $0 != 0
      MessageBox MB_OK|MB_ICONSTOP "UBC VPN could not stop and remove its service ($0). Nothing was removed; restart Windows and try again." /SD IDOK
      SetErrorLevel ${UBC_VPN_EXIT_SERVICE_NOT_REMOVED}
      Quit
    ${endif}
  ${endif}
!macroend
