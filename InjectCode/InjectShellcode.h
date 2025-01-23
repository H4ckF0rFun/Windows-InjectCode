#include <stdio.h>
#include <Windows.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <Shlwapi.h>
#pragma comment(lib,"Shlwapi.lib")

DWORD Pid(WCHAR* szName);
BOOL InjectThreadShellcode(HANDLE hProcess, DWORD ThreadId, UINT8 * sc, int sc_len);
int InjectProcessShellcode(TCHAR * process, unsigned char * sc, int sc_len);
int InjectProcessDll(TCHAR * process, char * dll_path, const char * entry, int free_after_call);