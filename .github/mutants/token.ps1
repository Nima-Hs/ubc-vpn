# Runs a command on Windows with the default owner and access list for new
# objects that the workflow's own PowerShell has.
#
# Git Bash, like any Cygwin program, changes its process token so that what
# it creates is owned by the user rather than the Administrators group, and
# every program it starts inherits that. The platform crate's elevated tests
# check exactly who owns the folders and files the service makes, so run
# under bash they fail. The scripts in this folder are bash, so each cargo
# they start on Windows goes through this script instead.
#
#   token.ps1 save         In the workflow's PowerShell, before bash starts:
#                          puts its token's defaults in MUTANTS_TOKEN_OWNER
#                          and MUTANTS_TOKEN_DACL.
#   token.ps1 run <file>   Sets those defaults on this process's token, then
#                          runs the command in <file>, one argument after
#                          each NUL, and exits with its status.

$ErrorActionPreference = 'Stop'

Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class MutantsToken {
    const uint TOKEN_QUERY = 0x0008, TOKEN_ADJUST_DEFAULT = 0x0080;
    const int TokenOwner = 4, TokenDefaultDacl = 6;

    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool GetTokenInformation(IntPtr token, int cls, IntPtr info, int length, out int needed);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool SetTokenInformation(IntPtr token, int cls, IntPtr info, int length);
    [DllImport("advapi32.dll")] static extern int GetLengthSid(IntPtr sid);

    // TOKEN_OWNER and TOKEN_DEFAULT_DACL are each a pointer to one SID or ACL.
    // These read and write what the pointer points to.
    static byte[] Get(int cls) {
        IntPtr token;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, out token)) throw new Win32Exception();
        try {
            int needed;
            GetTokenInformation(token, cls, IntPtr.Zero, 0, out needed);
            IntPtr info = Marshal.AllocHGlobal(needed);
            try {
                if (!GetTokenInformation(token, cls, info, needed, out needed)) throw new Win32Exception();
                IntPtr target = Marshal.ReadIntPtr(info);
                if (target == IntPtr.Zero) return new byte[0];
                int size = cls == TokenOwner ? GetLengthSid(target) : (ushort)Marshal.ReadInt16(target, 2);
                byte[] bytes = new byte[size];
                Marshal.Copy(target, bytes, 0, size);
                return bytes;
            } finally { Marshal.FreeHGlobal(info); }
        } finally { CloseHandle(token); }
    }

    static void Set(int cls, byte[] bytes) {
        IntPtr token;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_DEFAULT, out token)) throw new Win32Exception();
        try {
            int length = IntPtr.Size + bytes.Length;
            IntPtr info = Marshal.AllocHGlobal(length);
            try {
                IntPtr target = bytes.Length == 0 ? IntPtr.Zero : IntPtr.Add(info, IntPtr.Size);
                Marshal.WriteIntPtr(info, target);
                Marshal.Copy(bytes, 0, IntPtr.Add(info, IntPtr.Size), bytes.Length);
                if (!SetTokenInformation(token, cls, info, length)) throw new Win32Exception();
            } finally { Marshal.FreeHGlobal(info); }
        } finally { CloseHandle(token); }
    }

    public static string Owner() { return Convert.ToBase64String(Get(TokenOwner)); }
    public static string Dacl() { return Convert.ToBase64String(Get(TokenDefaultDacl)); }
    public static void SetOwner(string base64) { Set(TokenOwner, Convert.FromBase64String(base64)); }
    public static void SetDacl(string base64) { Set(TokenDefaultDacl, Convert.FromBase64String(base64)); }
}
'@

switch ($args[0]) {
    'save' {
        $env:MUTANTS_TOKEN_OWNER = [MutantsToken]::Owner()
        $env:MUTANTS_TOKEN_DACL = [MutantsToken]::Dacl()
        $sid = [Security.Principal.SecurityIdentifier]::new([Convert]::FromBase64String($env:MUTANTS_TOKEN_OWNER), 0)
        Write-Output "New objects are owned by $sid."
    }
    'run' {
        if (-not $env:MUTANTS_TOKEN_OWNER) { throw 'MUTANTS_TOKEN_OWNER is not set: run "token.ps1 save" first.' }
        [MutantsToken]::SetOwner($env:MUTANTS_TOKEN_OWNER)
        [MutantsToken]::SetDacl($env:MUTANTS_TOKEN_DACL)
        if ([MutantsToken]::Owner() -ne $env:MUTANTS_TOKEN_OWNER) { throw 'The default owner did not change.' }
        $command = [IO.File]::ReadAllText($args[1]).Split([char]0)
        # Each argument ends with a NUL, so the last piece is empty.
        $command = $command[0..($command.Length - 2)]
        $program = $command[0]
        $rest = @($command | Select-Object -Skip 1)
        & $program @rest
        exit $LASTEXITCODE
    }
    default { throw 'Usage: token.ps1 save | token.ps1 run <file>' }
}
