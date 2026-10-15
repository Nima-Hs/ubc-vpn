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
