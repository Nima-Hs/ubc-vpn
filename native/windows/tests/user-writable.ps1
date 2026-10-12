# Reads a list of file paths, one per line, and prints those an ordinary user
# could create, replace or change. A path that exists counts if it grants one
# of the groups every user is in the right to write to it, delete it or change
# its permissions, or if its folder lets them delete what is in it. A path that
# does not exist counts if the nearest folder above it that does exist lets
# them create things there.
#
# This reads the real permissions on the machine it runs on, so it finds
# places like C:\Windows\Temp without a list of them.
param([Parameter(Mandatory = $true)][string]$List)

# Everyone, Authenticated Users, Users, INTERACTIVE, Guests.
$ordinary = 'S-1-1-0', 'S-1-5-11', 'S-1-5-32-545', 'S-1-5-4', 'S-1-5-32-546'
# DeleteSubdirectoriesAndFiles, GENERIC_ALL.
$deleteInside = 0x40 -bor 0x10000000
# WriteData/CreateFiles, AppendData/CreateDirectories, Delete,
# ChangePermissions, TakeOwnership, GENERIC_WRITE, and the two above.
$change = 0x2 -bor 0x4 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x40000000 -bor $deleteInside

$known = @{}
function Test-Granted([string]$item, [int]$rights) {
    $key = "$rights $item"
    if ($known.ContainsKey($key)) { return $known[$key] }
    $result = $false
    try {
        $acl = Get-Acl -LiteralPath $item -ErrorAction Stop
        $sid = [System.Security.Principal.SecurityIdentifier]
        foreach ($ace in $acl.GetAccessRules($true, $true, $sid)) {
            if ($ace.AccessControlType -ne 'Allow') { continue }
            if ($ace.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) { continue }
            if ($ordinary -notcontains $ace.IdentityReference.Value) { continue }
            if (([int]$ace.FileSystemRights -band $rights) -ne 0) { $result = $true; break }
        }
    }
    catch {
        # Permissions that cannot be read are reported, not assumed safe.
        $result = $true
    }
    $known[$key] = $result
    return $result
}

foreach ($path in Get-Content -LiteralPath $List) {
    if (-not $path) { continue }
    $item = $path.TrimEnd('\')
    if ($item -match '^[A-Za-z]:$') { $item += '\' }
    $folder = Split-Path -Parent $item
    if (Test-Path -LiteralPath $item) {
        $writable = (Test-Granted $item $change) -or ($folder -and (Test-Granted $folder $deleteInside))
    }
    else {
        while ($folder -and -not (Test-Path -LiteralPath $folder)) { $folder = Split-Path -Parent $folder }
        $writable = $folder -and (Test-Granted $folder $change)
    }
    if ($writable) { Write-Output $path }
}
