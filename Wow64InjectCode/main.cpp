#include "InjectShellcode.h"


int main(){

	InjectProcessDll(TEXT("ConsoleApplication1.exe"),
		"C:\\Users\\binsong\\Desktop\\loaddll_shellcode\\x64\\Release\\TestDll.dll",
		"TestFunc", 1);

	return 0;
}