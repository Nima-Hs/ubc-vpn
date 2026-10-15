# For the installer workflow only: a setup program whose last folder step
# fails, to show a failed install leaves nothing behind. Built with
# -c.nsis.include pointing here; the setup program people get never has it.
!define UBC_VPN_TEST_FAIL_STEP "contents"
!include "${__FILEDIR__}\..\installer.nsh"
