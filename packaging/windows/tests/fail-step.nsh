# For the installer workflow only: a setup program one of whose folder steps
# fails, to show a failed install leaves nothing behind. Built with
# -c.nsis.include pointing here; the setup program people get never has it.
# The step to fail is named by the environment variable
# UBC_VPN_TEST_FAIL_STEP when the setup program is built: owner, reset,
# access list or contents.
!define UBC_VPN_TEST_FAIL_STEP "$%UBC_VPN_TEST_FAIL_STEP%"
# Anything else, an unset variable included, would build a setup program
# with no step failing, so it is refused.
!if "${UBC_VPN_TEST_FAIL_STEP}" != "owner"
  !if "${UBC_VPN_TEST_FAIL_STEP}" != "reset"
    !if "${UBC_VPN_TEST_FAIL_STEP}" != "access list"
      !if "${UBC_VPN_TEST_FAIL_STEP}" != "contents"
        !error "Set UBC_VPN_TEST_FAIL_STEP to owner, reset, access list or contents."
      !endif
    !endif
  !endif
!endif
!include "${__FILEDIR__}\..\installer.nsh"
