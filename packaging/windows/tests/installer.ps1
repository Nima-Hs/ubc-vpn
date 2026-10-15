# Checks for the Windows setup program, run by .github/workflows/installer-windows.yml
# on a GitHub runner as an administrator. Never run it on your own computer:
# it installs and removes UBC VPN for the whole machine.
#
#   installer.ps1 refuse-folder <setup.exe>          /D= is refused and nothing is installed
#   installer.ps1 install <setup.exe>                silent install; must succeed
#   installer.ps1 install-fails <setup.exe>          silent install that must fail and
#                                                    leave nothing behind
#   installer.ps1 installed <win-unpacked folder>    what the install left, file by file
#   installer.ps1 who-can-change                     only SYSTEM, Administrators and
#                                                    TrustedInstaller may change the folder
#   installer.ps1 uninstall                          silent uninstall; waits for it to finish
#   installer.ps1 removed                            nothing is left but the user's data
#
# Each command stops with an error at the first thing that is wrong.

param(
    [Parameter(Mandatory = $true, Position = 0)][string]$Command,
    [Parameter(Position = 1)][string]$Path
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$ProductName = 'UBC VPN'
$InstallFolder = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) $ProductName
$StartMenuShortcut = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\$ProductName.lnk"
$UninstallKeys = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall'
)

function Fail([string]$why) { throw "installer.ps1 ${Command}: $why" }

function Uninstall-Entries {
    @(Get-ChildItem $UninstallKeys -ErrorAction SilentlyContinue |
            Get-ItemProperty |
            Where-Object { $_.PSObject.Properties['DisplayName'] -and $_.DisplayName -like "$ProductName*" })
}

# Fails unless no trace of an install is left: the folder, the uninstall
# entry, the install entry electron-builder keeps, and the shortcuts.
function Assert-NotInstalled {
    if (Test-Path -LiteralPath $InstallFolder) { Fail "$InstallFolder is still there: $((Get-ChildItem -LiteralPath $InstallFolder -Recurse -Force | ForEach-Object FullName) -join ', ')" }
    if (@(Uninstall-Entries).Count -ne 0) { Fail 'an uninstall entry is still there' }
    $installEntries = @(Get-ChildItem 'HKLM:\Software', 'HKCU:\Software' -ErrorAction SilentlyContinue |
            Get-ItemProperty -ErrorAction SilentlyContinue |
            Where-Object { $_.PSObject.Properties['InstallLocation'] -and $_.InstallLocation -eq $InstallFolder })
    if ($installEntries.Count -ne 0) { Fail "an install entry is still there: $($installEntries[0].PSPath)" }
    if (Test-Path -LiteralPath $StartMenuShortcut) { Fail "$StartMenuShortcut is still there" }
    $desktop = Join-Path $env:PUBLIC "Desktop\$ProductName.lnk"
    if (Test-Path -LiteralPath $desktop) { Fail "$desktop is still there" }
}

function Run-Setup([string]$setup, [string[]]$arguments) {
    $process = Start-Process -FilePath (Resolve-Path $setup).Path -ArgumentList $arguments -Wait -PassThru
    Write-Host "$(Split-Path -Leaf $setup) $($arguments -join ' ') exited with $($process.ExitCode)"
    $process.ExitCode
}

# The SIDs that may hold rights to change the install folder.
$Trusted = @(
    'S-1-5-18',                                                       # SYSTEM
    'S-1-5-32-544',                                                   # Administrators
    'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'  # TrustedInstaller
)

# The install folder's access list, exactly: the installer sets it, protected
# and by SID, and everything inside inherits it.
$Expected = @(
    'S-1-5-18|FullControl',
    'S-1-5-32-544|FullControl',
    'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464|FullControl',
    'S-1-5-32-545|ReadAndExecute, Synchronize'
)

# Every right that lets someone change, replace or take over a file or folder.
$ChangeRights = [Security.AccessControl.FileSystemRights]'WriteData, AppendData, WriteExtendedAttributes, DeleteSubdirectoriesAndFiles, WriteAttributes, Delete, ChangePermissions, TakeOwnership'
# GENERIC_ALL and GENERIC_WRITE.
$GenericChange = 0x10000000 -bor 0x40000000
# On a folder above the install folder, the rights that could swap what is
# in it: delete it, delete what is inside, change its access list or owner,
# or all of them. Adding something new to C:\ does not change any path.
$ReplaceRights = [Security.AccessControl.FileSystemRights]'DeleteSubdirectoriesAndFiles, Delete, ChangePermissions, TakeOwnership'
$GenericReplace = 0x10000000

function Sid([Security.Principal.IdentityReference]$who) {
    $who.Translate([Security.Principal.SecurityIdentifier]).Value
}

# Who other than the trusted accounts may change this path: its owner, and
# every allow entry that grants one of `$rights` or `$generic` on it. An
# inherit-only entry is not a right on the path itself and is not counted.
function Changers([string]$item, [int64]$rights, [int64]$generic) {
    $acl = Get-Acl -LiteralPath $item
    $owner = Sid $acl.GetOwner([Security.Principal.NTAccount])
    $found = @()
    if ($Trusted -notcontains $owner) { $found += "owner $($acl.Owner)" }
    foreach ($entry in $acl.Access) {
        if ($entry.AccessControlType -ne 'Allow') { continue }
        if ($entry.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) { continue }
        $granted = [int64]$entry.FileSystemRights
        if ((($granted -band $rights) -eq 0) -and (($granted -band $generic) -eq 0)) { continue }
        if ($Trusted -contains (Sid $entry.IdentityReference)) { continue }
        $found += "$($entry.IdentityReference.Value) ($($entry.FileSystemRights))"
    }
    $found
}

switch ($Command) {
    'refuse-folder' {
        $elsewhere = Join-Path $env:PUBLIC 'ubc-vpn-elsewhere'
        if (Test-Path -LiteralPath $elsewhere) { Fail "$elsewhere exists before the test" }
        if (Test-Path -LiteralPath $InstallFolder) { Fail "$InstallFolder exists before the test" }
        $code = Run-Setup $Path @('/S', "/D=$elsewhere")
        if ($code -eq 0) { Fail 'the setup program accepted /D= and reported success' }
        if (Test-Path -LiteralPath $elsewhere) { Fail "it created $elsewhere" }
        if (Test-Path -LiteralPath $InstallFolder) { Fail "it installed into $InstallFolder" }
        if (@(Uninstall-Entries).Count -ne 0) { Fail 'it registered an uninstaller' }
        Write-Output 'refused /D= and installed nothing'
    }
    'install' {
        $code = Run-Setup $Path @('/S')
        if ($code -ne 0) { Fail "exit code $code" }
        if (-not (Test-Path -LiteralPath (Join-Path $InstallFolder "$ProductName.exe"))) { Fail "no $ProductName.exe in $InstallFolder" }
        $entries = @(Uninstall-Entries)
        if ($entries.Count -ne 1) { Fail "$($entries.Count) uninstall entries, not 1" }
        if ($entries[0].PSPath -notlike '*HKEY_LOCAL_MACHINE*') { Fail "the uninstall entry is not for the whole machine: $($entries[0].PSPath)" }
        $expected = "`"$InstallFolder\Uninstall $ProductName.exe`""
        if (-not $entries[0].UninstallString.StartsWith($expected)) { Fail "the uninstaller is recorded as $($entries[0].UninstallString)" }
        Write-Output "installed in $InstallFolder"
    }
    'installed' {
        # Every file electron-builder put in the app folder is installed byte
        # for byte. The install adds the uninstaller and nothing else.
        $unpacked = (Resolve-Path $Path).Path
        $built = @{}
        Get-ChildItem -LiteralPath $unpacked -Recurse -File | ForEach-Object {
            $built[$_.FullName.Substring($unpacked.Length).TrimStart('\')] = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
        }
        $extra = @()
        Get-ChildItem -LiteralPath $InstallFolder -Recurse -File | ForEach-Object {
            $relative = $_.FullName.Substring($InstallFolder.Length).TrimStart('\')
            if ($built.ContainsKey($relative)) {
                if ((Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash -ne $built[$relative]) { Fail "$relative differs from the build" }
                $built.Remove($relative)
            } else {
                $extra += $relative
            }
        }
        # Only the updater uses it, so the installer removes it.
        $elevate = 'resources\elevate.exe'
        if (-not $built.ContainsKey($elevate)) { Fail "the build has no $elevate, so this check is out of date" }
        $built.Remove($elevate)
        if ($built.Count -ne 0) { Fail "not installed: $($built.Keys -join ', ')" }
        if (($extra.Count -ne 1) -or ($extra[0] -ne "Uninstall $ProductName.exe")) { Fail "unexpected files: $($extra -join ', ')" }
        if (-not (Test-Path -LiteralPath $StartMenuShortcut)) { Fail "no shortcut at $StartMenuShortcut" }
        Write-Output 'every built file is installed unchanged, plus the uninstaller'
    }
    'who-can-change' {
        # The folder, everything in it, and every folder above it.
        $inside = @(Get-Item -LiteralPath $InstallFolder) + @(Get-ChildItem -LiteralPath $InstallFolder -Recurse -Force)
        $aboveAll = @()
        $above = Split-Path -Parent $InstallFolder
        while ($above) {
            $aboveAll += Get-Item -LiteralPath $above -Force
            $above = Split-Path -Parent $above
        }
        $bad = @()
        foreach ($item in $inside) {
            $changers = @(Changers $item.FullName ([int64]$ChangeRights) $GenericChange)
            if ($changers.Count -ne 0) { $bad += "$($item.FullName): $($changers -join '; ')" }
            # Owned by Administrators, not by the account that installed.
            $owner = Sid (Get-Acl -LiteralPath $item.FullName).GetOwner([Security.Principal.NTAccount])
            if ($owner -ne 'S-1-5-32-544') { $bad += "$($item.FullName): owned by $owner, not Administrators" }
        }
        foreach ($item in $aboveAll) {
            $changers = @(Changers $item.FullName ([int64]$ReplaceRights) $GenericReplace)
            if ($changers.Count -ne 0) { $bad += "$($item.FullName): $($changers -join '; ')" }
        }
        # The folder's own access list: protected, and exactly the expected
        # entries, none of them inherit-only and none for CREATOR OWNER.
        $acl = Get-Acl -LiteralPath $InstallFolder
        if (-not $acl.AreAccessRulesProtected) { $bad += "$InstallFolder inherits from the folder above" }
        $entries = @($acl.Access | ForEach-Object {
                if ($_.AccessControlType -ne 'Allow' -or $_.IsInherited -or $_.PropagationFlags -ne 'None' -or $_.InheritanceFlags -ne 'ContainerInherit, ObjectInherit') {
                    "unexpected: $($_.IdentityReference.Value) $($_.AccessControlType) $($_.FileSystemRights) $($_.InheritanceFlags) $($_.PropagationFlags) inherited=$($_.IsInherited)"
                } else {
                    "$(Sid $_.IdentityReference)|$($_.FileSystemRights)"
                }
            } | Sort-Object)
        $wanted = @($Expected | Sort-Object)
        if (($entries -join ';') -ne ($wanted -join ';')) { $bad += "$InstallFolder access list: $($entries -join '; ')" }
        $items = $inside + $aboveAll
        if ($bad.Count -ne 0) {
            & icacls.exe $InstallFolder
            Fail "others may change:`n$($bad -join "`n")"
        }
        Write-Output "only SYSTEM, Administrators and TrustedInstaller may change $InstallFolder, its contents and the folders above it ($($items.Count) checked)"
    }
    'uninstall' {
        $uninstaller = Join-Path $InstallFolder "Uninstall $ProductName.exe"
        if (-not (Test-Path -LiteralPath $uninstaller)) { Fail "no $uninstaller" }
        $code = Run-Setup $uninstaller @('/S')
        if ($code -ne 0) { Fail "exit code $code" }
        # The uninstaller copies itself to a temporary folder and carries on
        # from there, so the process started above can end before it is done.
        for ($i = 0; $i -lt 120 -and ((Test-Path -LiteralPath $InstallFolder) -or @(Uninstall-Entries).Count -ne 0); $i++) {
            Start-Sleep -Seconds 1
        }
        Write-Output 'uninstaller finished'
    }
    'install-fails' {
        if (Test-Path -LiteralPath $InstallFolder) { Fail "$InstallFolder exists before the test" }
        $code = Run-Setup $Path @('/S')
        # 3: the folder could not be secured and the install was undone (installer.nsh).
        if ($code -ne 3) { Fail "exit code $code, not 3" }
        Assert-NotInstalled
        Write-Output "failed with exit code $code and left nothing behind"
    }
    'removed' {
        Assert-NotInstalled
        # The user's own data stays: settings and the app's profile.
        $userData = Join-Path $env:APPDATA $ProductName
        if (-not (Test-Path -LiteralPath (Join-Path $userData 'app'))) { Fail "the app's profile in $userData was removed" }
        Write-Output "nothing left but the user's data in $userData"
    }
    default { Fail 'unknown command' }
}
