# Checks for the Windows setup program, run by .github/workflows/installer-windows.yml
# on a GitHub runner as an administrator. Never run it on your own computer:
# it installs and removes UBC VPN for the whole machine.
#
#   installer.ps1 refuse-folder <setup.exe>          /D= is refused and nothing is installed
#   installer.ps1 install <setup.exe>                silent install; must succeed
#   installer.ps1 install-fails <setup.exe> <code>   silent install that must stop with exit
#                                                    <code> and leave nothing behind
#   installer.ps1 update-fails <setup.exe> <code>    the same over an installed copy, but
#                                                    the data folder must stay
#   installer.ps1 foreign-folder <setup.exe>         another product's folder is refused
#                                                    (exit 5) and left as it was
#   installer.ps1 decline <setup.exe>                declining the licence page leaves nothing
#   installer.ps1 installed <win-unpacked folder>    what the install left, file by file
#   installer.ps1 as-staged <stage folder>           the service, client, libraries and policy
#                                                    are the staged files, byte for byte
#   installer.ps1 who-can-change                     only SYSTEM, Administrators and
#                                                    TrustedInstaller may change the folder
#   installer.ps1 service                            the service is registered, running, and
#                                                    its data folder and policy are right
#   installer.ps1 status-as-user                     `ubc-vpn status` answers a standard user
#   installer.ps1 plant-owner                        makes a data folder Users may change,
#                                                    with a state.json naming an owner
#   installer.ps1 planted-gone                       the install emptied it
#   installer.ps1 remember-state <file>              notes state.json's SHA-256 in <file>
#   installer.ps1 state-kept <file>                  state.json is unchanged since then
#   installer.ps1 uninstall                          silent uninstall; waits for it to finish
#   installer.ps1 removed                            nothing is left but the user's data
#
# Each command stops with an error at the first thing that is wrong.

param(
    [Parameter(Mandatory = $true, Position = 0)][string]$Command,
    [Parameter(Position = 1)][string]$Path,
    [Parameter(Position = 2)][int]$ExitCode = 3
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$ProductName = 'UBC VPN'
$InstallFolder = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) $ProductName
$StartMenuShortcut = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\$ProductName.lnk"
$ServiceName = 'ubc-vpn'
$DataFolder = Join-Path $env:ProgramData $ProductName
$Bin = Join-Path $InstallFolder 'resources\bin'
# What `ubc-vpn-service install` sets (crates/platform/src/windows/install.rs).
$DataFolderSddl = 'O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1200a9;;;BU)'
$PolicySddl = 'O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)'
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
function Assert-NotInstalled([switch]$KeepData) {
    if (Test-Path -LiteralPath $InstallFolder) { Fail "$InstallFolder is still there: $((Get-ChildItem -LiteralPath $InstallFolder -Recurse -Force | ForEach-Object FullName) -join ', ')" }
    if (@(Uninstall-Entries).Count -ne 0) { Fail 'an uninstall entry is still there' }
    $installEntries = @(Get-ChildItem 'HKLM:\Software', 'HKCU:\Software' -ErrorAction SilentlyContinue |
            Get-ItemProperty -ErrorAction SilentlyContinue |
            Where-Object { $_.PSObject.Properties['InstallLocation'] -and $_.InstallLocation -eq $InstallFolder })
    if ($installEntries.Count -ne 0) { Fail "an install entry is still there: $($installEntries[0].PSPath)" }
    if (Test-Path -LiteralPath $StartMenuShortcut) { Fail "$StartMenuShortcut is still there" }
    $desktop = Join-Path $env:PUBLIC "Desktop\$ProductName.lnk"
    if (Test-Path -LiteralPath $desktop) { Fail "$desktop is still there" }
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) { Fail "the service $ServiceName is still registered" }
    if ($KeepData) {
        if (-not (Test-Path -LiteralPath $DataFolder)) { Fail "$DataFolder was removed" }
    } elseif (Test-Path -LiteralPath $DataFolder) { Fail "$DataFolder is still there" }
}

# The SDDL owner and access list of a path, as Get-Acl gives it, less the
# group and the auto-inherited flag Windows adds.
function Sddl([string]$item) {
    $sddl = (Get-Acl -LiteralPath $item).GetSecurityDescriptorSddlForm('Owner, Access')
    $sddl.Replace('D:PAI(', 'D:P(')
}

# SHA-256 of every file under a folder, by path relative to it.
function Hashes([string]$folder) {
    $found = @{}
    Get-ChildItem -LiteralPath $folder -Recurse -File -Force | ForEach-Object {
        $found[$_.FullName.Substring($folder.Length).TrimStart('\')] = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
    }
    $found
}

function Same-Hashes([hashtable]$a, [hashtable]$b) {
    if ($a.Count -ne $b.Count) { return $false }
    foreach ($k in $a.Keys) { if (-not $b.ContainsKey($k) -or $b[$k] -ne $a[$k]) { return $false } }
    $true
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
        # installer.nsh: 3, the folder could not be secured; 4, the service
        # could not be installed. Either way the install was undone.
        if ($code -ne $ExitCode) { Fail "exit code $code, not $ExitCode" }
        Assert-NotInstalled
        Write-Output "failed with exit code $code and left nothing behind"
    }
    'update-fails' {
        if (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) { Fail 'nothing is installed to update' }
        $code = Run-Setup $Path @('/S')
        if ($code -ne $ExitCode) { Fail "exit code $code, not $ExitCode" }
        # The update was undone, but the data folder, with the owner in
        # state.json, stays (see state-kept).
        Assert-NotInstalled -KeepData
        Write-Output "failed with exit code $code, left nothing behind and kept $DataFolder"
    }
    'foreign-folder' {
        if (Test-Path -LiteralPath $InstallFolder) { Fail "$InstallFolder exists before the test" }
        # Another product's folder, as an earlier UBC VPN client leaves it.
        New-Item -ItemType Directory -Path $InstallFolder | Out-Null
        'not this UBC VPN' | Set-Content -LiteralPath (Join-Path $InstallFolder "$ProductName.exe")
        'an earlier client' | Set-Content -LiteralPath (Join-Path $InstallFolder 'readme.txt')
        $before = Hashes $InstallFolder
        $acl = Sddl $InstallFolder
        try {
            $code = Run-Setup $Path @('/S')
            if ($code -ne 5) { Fail "exit code $code, not 5" }
            if (-not (Same-Hashes $before (Hashes $InstallFolder))) { Fail "the other product's files changed: $((Get-ChildItem -LiteralPath $InstallFolder -Recurse -Force | ForEach-Object FullName) -join ', ')" }
            if ((Sddl $InstallFolder) -ne $acl) { Fail "the folder's access list changed: $(Sddl $InstallFolder)" }
            if (@(Uninstall-Entries).Count -ne 0) { Fail 'it registered an uninstaller' }
            if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) { Fail 'it registered the service' }
            if (Test-Path -LiteralPath $DataFolder) { Fail "it made $DataFolder" }
        } finally {
            Remove-Item -LiteralPath $InstallFolder -Recurse -Force
        }
        Write-Output 'refused another product''s folder (exit 5) and left it as it was'
    }
    'decline' {
        # Runs the setup program with its pages. Once its window shows the
        # licence page (it has an "I Agree" button), presses Cancel there,
        # the way the button does, by sending the window IDCANCEL; then Yes
        # to the quit question, if one is asked. "I Agree" is never pressed.
        if (Test-Path -LiteralPath $InstallFolder) { Fail "$InstallFolder exists before the test" }
        Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
public static class SetupWindows {
    delegate bool Visit(IntPtr window, IntPtr data);
    [DllImport("user32.dll")] static extern bool EnumWindows(Visit visit, IntPtr data);
    [DllImport("user32.dll")] static extern bool EnumChildWindows(IntPtr parent, Visit visit, IntPtr data);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr window, out uint process);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr window);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetWindowText(IntPtr window, StringBuilder text, int size);
    [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr window, uint message, IntPtr w, IntPtr l);
    public static List<IntPtr> Of(int process) {
        var found = new List<IntPtr>();
        EnumWindows((window, data) => {
            uint owner;
            GetWindowThreadProcessId(window, out owner);
            if (owner == process && IsWindowVisible(window)) found.Add(window);
            return true;
        }, IntPtr.Zero);
        return found;
    }
    public static List<string> Texts(IntPtr parent) {
        var texts = new List<string>();
        EnumChildWindows(parent, (window, data) => {
            var text = new StringBuilder(256);
            GetWindowText(window, text, 256);
            texts.Add(text.ToString());
            return true;
        }, IntPtr.Zero);
        return texts;
    }
}
'@
        $WM_COMMAND = 0x0111
        $process = Start-Process -FilePath (Resolve-Path $Path).Path -PassThru
        try {
            $page = [IntPtr]::Zero
            $deadline = (Get-Date).AddSeconds(120)
            while ($page -eq [IntPtr]::Zero -and (Get-Date) -lt $deadline -and -not $process.HasExited) {
                foreach ($window in [SetupWindows]::Of($process.Id)) {
                    $texts = [SetupWindows]::Texts($window)
                    if ($texts -contains 'I &Agree' -or $texts -contains 'I Agree') { $page = $window }
                }
                Start-Sleep -Milliseconds 500
            }
            if ($page -eq [IntPtr]::Zero) { Fail 'no licence page with an "I Agree" button appeared' }
            Write-Host "the licence page shows: $(([SetupWindows]::Texts($page) | Where-Object { $_ }) -join ' | ')"
            [void][SetupWindows]::PostMessage($page, $WM_COMMAND, [IntPtr]2, [IntPtr]::Zero)  # IDCANCEL
            # The quit question, if this setup program asks one: a second
            # window of the same process. Yes is IDYES.
            $deadline = (Get-Date).AddSeconds(10)
            while ((Get-Date) -lt $deadline -and -not $process.HasExited) {
                $others = @([SetupWindows]::Of($process.Id) | Where-Object { $_ -ne $page })
                if ($others.Count -gt 0) {
                    foreach ($question in $others) {
                        Write-Host "answering Yes to: $(([SetupWindows]::Texts($question) | Where-Object { $_ }) -join ' | ')"
                        [void][SetupWindows]::PostMessage($question, $WM_COMMAND, [IntPtr]6, [IntPtr]::Zero)  # IDYES
                    }
                    break
                }
                Start-Sleep -Milliseconds 250
            }
            if (-not $process.WaitForExit(60000)) { Fail 'the setup program did not end after Cancel' }
        } finally {
            if (-not $process.HasExited) { $process.Kill() }
        }
        Write-Host "the setup program ended with $($process.ExitCode)"
        if ($process.ExitCode -eq 0) { Fail 'declining was reported as success' }
        Assert-NotInstalled
        Write-Output 'declined the licence page and nothing was installed'
    }
    'as-staged' {
        # The programs, libraries and policy are the staged ones, byte for
        # byte: electron-builder copies them without signing or changing them.
        $stage = (Resolve-Path $Path).Path
        $staged = Hashes (Join-Path $stage 'bin')
        $installed = Hashes $Bin
        if (-not (Same-Hashes $staged $installed)) { Fail "resources\bin differs from the stage: staged $($staged.Keys -join ', '); installed $($installed.Keys -join ', ')" }
        $policy = Join-Path $InstallFolder 'resources\policy.json'
        if ((Get-FileHash -LiteralPath $policy).Hash -ne (Get-FileHash -LiteralPath (Join-Path $stage 'policy.json')).Hash) { Fail 'resources\policy.json differs from the stage' }
        Write-Output "resources\bin ($($installed.Count) files) and the policy are the staged files"
    }
    'service' {
        $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'"
        if (-not $service) { Fail "the service $ServiceName is not registered" }
        $program = "`"$Bin\ubc-vpn-service.exe`""
        if ($service.PathName -ne $program) { Fail "the service runs $($service.PathName), not $program" }
        if ($service.StartMode -ne 'Auto') { Fail "the service starts $($service.StartMode), not automatically" }
        if ($service.StartName -ne 'LocalSystem') { Fail "the service runs as $($service.StartName)" }
        if ($service.State -ne 'Running') { Fail "the service is $($service.State)" }
        if ((Sddl $DataFolder) -ne $DataFolderSddl) { Fail "$DataFolder has $(Sddl $DataFolder)" }
        $policy = Join-Path $DataFolder 'policy.json'
        if ((Sddl $policy) -ne $PolicySddl) { Fail "$policy has $(Sddl $policy)" }
        $shipped = Join-Path $InstallFolder 'resources\policy.json'
        if ((Get-FileHash -LiteralPath $policy).Hash -ne (Get-FileHash -LiteralPath $shipped).Hash) { Fail "$policy is not the shipped policy" }
        Write-Output "$ServiceName runs as LocalSystem from $program, starts with Windows, and its data folder and policy are as installed"
    }
    'status-as-user' {
        # A throwaway standard user, with a random password that stays in
        # this process, asks the installed service for its status through
        # the installed client.
        $user = 'ubcvpn-status'
        $bytes = [byte[]]::new(24)
        [Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
        $secure = ConvertTo-SecureString ('Aa1!' + [Convert]::ToBase64String($bytes)) -AsPlainText -Force
        New-LocalUser -Name $user -Password $secure -AccountNeverExpires | Out-Null
        try {
            Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $user
            $credential = New-Object Management.Automation.PSCredential(".\$user", $secure)
            $out = Join-Path $env:RUNNER_TEMP 'status-out.txt'
            $err = Join-Path $env:RUNNER_TEMP 'status-err.txt'
            $process = Start-Process -FilePath (Join-Path $Bin 'ubc-vpn.exe') -ArgumentList 'status', '--json' -Credential $credential -LoadUserProfile -WorkingDirectory $env:SystemRoot -RedirectStandardOutput $out -RedirectStandardError $err -Wait -PassThru
            $said = Get-Content -LiteralPath $out -Raw
            Write-Host "ubc-vpn status --json, as $user, exited with $($process.ExitCode): $said $(Get-Content -LiteralPath $err -Raw)"
            if ($process.ExitCode -ne 0) { Fail "ubc-vpn status exited with $($process.ExitCode)" }
            if ($said -notmatch 'disconnected') { Fail "ubc-vpn status said: $said" }
        } finally {
            Remove-LocalUser -Name $user
        }
        Write-Output "the installed service answered $user through the installed client"
    }
    'remember-state' {
        $state = Join-Path $DataFolder 'state.json'
        if (-not (Test-Path -LiteralPath $state)) { Fail "no $state" }
        (Get-FileHash -LiteralPath $state).Hash | Set-Content -LiteralPath $Path
        Write-Output "noted $state"
    }
    'plant-owner' {
        # What a standard user could leave before the first install: a data
        # folder others may change, naming an owner (a made-up one).
        if (Test-Path -LiteralPath $DataFolder) { Fail "$DataFolder exists before the test" }
        New-Item -ItemType Directory -Path $DataFolder | Out-Null
        & "$env:SystemRoot\System32\icacls.exe" $DataFolder /grant '*S-1-5-32-545:(OI)(CI)M' /Q | Out-Null
        if ($LASTEXITCODE -ne 0) { Fail "icacls exited with $LASTEXITCODE" }
        Set-Content -LiteralPath (Join-Path $DataFolder 'state.json') -Value '{"owner":"S-1-5-21-0-0-0-1001"}' -NoNewline
        Write-Output "planted an owner in $DataFolder, which Users may change"
    }
    'planted-gone' {
        $state = Join-Path $DataFolder 'state.json'
        if (Test-Path -LiteralPath $state) { Fail "the install kept the planted ${state}: $(Get-Content -LiteralPath $state)" }
        Write-Output "the install emptied the planted $DataFolder"
    }
    'state-kept' {
        $state = Join-Path $DataFolder 'state.json'
        if (-not (Test-Path -LiteralPath $state)) { Fail "$state is gone" }
        if ((Get-FileHash -LiteralPath $state).Hash -ne (Get-Content -LiteralPath $Path).Trim()) { Fail "$state changed" }
        Write-Output "$state is unchanged"
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
