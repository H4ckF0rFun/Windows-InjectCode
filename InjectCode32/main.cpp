#include "InjectShellcode.h"

int main(){

	InjectProcessDll(TEXT("ConsoleApplication1.exe"),
		"C:\\Users\\binsong\\Desktop\\Dll2Shellcode\\Release\\TestDll.dll",
		"TestFunc", 0);

	return 0;
}