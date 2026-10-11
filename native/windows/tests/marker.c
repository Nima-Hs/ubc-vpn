/* A stand-in PKCS#11 module for planted-files.sh. It does nothing but record
 * that it was loaded, by creating "<its own path>.loaded". */
#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE self, DWORD reason, LPVOID reserved)
{
    char path[MAX_PATH + 8];
    DWORD len;
    HANDLE file;

    (void)reserved;
    if (reason != DLL_PROCESS_ATTACH)
        return TRUE;
    len = GetModuleFileNameA(self, path, MAX_PATH);
    if (len == 0 || len >= MAX_PATH)
        return TRUE;
    lstrcatA(path, ".loaded");
    file = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file != INVALID_HANDLE_VALUE)
        CloseHandle(file);
    return TRUE;
}
