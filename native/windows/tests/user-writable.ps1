# Reads a list of file paths, one per line, and prints those an ordinary user
# could create, replace or change: the path itself if it exists, or else the
# nearest folder above it that does, grants one of the groups every user is in
# the right to write, create, delete or change permissions.
#
# This reads the real permissions on the machine it runs on, so it finds
# places like C:\Windows\Temp without a list of them.
param([Parameter(Mandatory = $true)][string]$List)

# Everyone, Authenticated Users, Users, INTERACTIVE, Guests.
$ordinary = 'S-1-1-0', 'S-1-5-11', 'S-1-5-32-545', 'S-1-5-4', 'S-1-5-32-546'
# WriteData/CreateFiles, AppendData/CreateDirectories, DeleteSubdirectoriesAndFiles,
# Delete, ChangePermissions, TakeOwnership, GENERIC_WRITE, GENERIC_ALL.
$mask = 0x2 -bor 0x4 -bor 0x40 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x40000000 -bor 0x10000000

$known = @{}
function Test-Writable([string]$item) {
    if ($known.ContainsKey($item)) { return $known[$item] }
    $result = $false
    try {
        $acl = Get-Acl -LiteralPath $item -ErrorAction Stop
        $sid = [System.Security.Principal.SecurityIdentifier]
        foreach ($ace in $acl.GetAccessRules($true, $true, $sid)) {
            if ($ace.AccessControlType -ne 'Allow') { continue }
            if ($ace.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) { continue }
            if ($ordinary -notcontains $ace.IdentityReference.Value) { continue }
            if (([int]$ace.FileSystemRights -band $mask) -ne 0) { $result = $true; break }
        }
    }
    catch {
        # Permissions that cannot be read are reported, not assumed safe.
        $result = $true
    }
    $known[$item] = $result
    return $result
}

foreach ($path in Get-Content -LiteralPath $List) {
    if (-not $path) { continue }
    $item = $path.TrimEnd('\')
    if ($item -match '^[A-Za-z]:$') { $item += '\' }
    $why = $null
    if (Test-Path -LiteralPath $item) {
        if (Test-Writable $item) { $why = $item }
    }
    if (-not $why) {
        $folder = Split-Path -Parent $item
        while ($folder -and -not (Test-Path -LiteralPath $folder)) { $folder = Split-Path -Parent $folder }
        if ($folder -and (Test-Writable $folder)) { $why = $folder }
    }
    if ($why) { Write-Output "$path" }
}
