#include "InjectShellcode.h"


int main(){

	InjectProcessDll(TEXT("explorer.exe"),
		"C:\\Users\\binsong\\Desktop\\Dll2Shellcode\\x64\\Release\\TestDll.dll",
		"TestFunc", 1);

	return 0;
}