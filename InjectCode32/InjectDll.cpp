#include "InjectShellcode.h"

unsigned char loaddll_sc[1383] = {
	0xe9, 0x20, 0x04, 0x00, 0x00, 0x55, 0x8b, 0xec, 0x51, 0xb8, 0x01, 0x00, 0x00, 0x00, 0x85, 0xc0,
	0x0f, 0x84, 0x81, 0x00, 0x00, 0x00, 0x8b, 0x4d, 0x08, 0x8a, 0x11, 0x88, 0x55, 0xff, 0x8b, 0x45,
	0x0c, 0x8a, 0x08, 0x88, 0x4d, 0xfe, 0x0f, 0xbe, 0x55, 0xff, 0x83, 0xfa, 0x41, 0x7c, 0x13, 0x0f,
	0xbe, 0x45, 0xff, 0x83, 0xf8, 0x5a, 0x7f, 0x0a, 0x0f, 0xbe, 0x4d, 0xff, 0x83, 0xc1, 0x20, 0x88,
	0x4d, 0xff, 0x0f, 0xbe, 0x55, 0xfe, 0x83, 0xfa, 0x41, 0x7c, 0x13, 0x0f, 0xbe, 0x45, 0xfe, 0x83,
	0xf8, 0x5a, 0x7f, 0x0a, 0x0f, 0xbe, 0x4d, 0xfe, 0x83, 0xc1, 0x20, 0x88, 0x4d, 0xfe, 0x0f, 0xbe,
	0x55, 0xff, 0x0f, 0xbe, 0x45, 0xfe, 0x3b, 0xd0, 0x74, 0x0c, 0x0f, 0xbe, 0x45, 0xff, 0x0f, 0xbe,
	0x4d, 0xfe, 0x2b, 0xc1, 0xeb, 0x23, 0x0f, 0xbe, 0x55, 0xff, 0x85, 0xd2, 0x75, 0x02, 0xeb, 0x17,
	0x8b, 0x45, 0x08, 0x83, 0xc0, 0x01, 0x89, 0x45, 0x08, 0x8b, 0x4d, 0x0c, 0x83, 0xc1, 0x01, 0x89,
	0x4d, 0x0c, 0xe9, 0x72, 0xff, 0xff, 0xff, 0x33, 0xc0, 0x8b, 0xe5, 0x5d, 0xc3, 0xcc, 0xcc, 0xcc,
	0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x55, 0x8b, 0xec, 0x51, 0xb8, 0x01, 0x00, 0x00, 0x00, 0x85, 0xc0,
	0x0f, 0x84, 0x81, 0x00, 0x00, 0x00, 0x8b, 0x4d, 0x08, 0x8a, 0x11, 0x88, 0x55, 0xff, 0x8b, 0x45,
	0x0c, 0x8a, 0x08, 0x88, 0x4d, 0xfe, 0x0f, 0xbe, 0x55, 0xff, 0x83, 0xfa, 0x41, 0x7c, 0x13, 0x0f,
	0xbe, 0x45, 0xff, 0x83, 0xf8, 0x5a, 0x7f, 0x0a, 0x0f, 0xbe, 0x4d, 0xff, 0x83, 0xc1, 0x20, 0x88,
	0x4d, 0xff, 0x0f, 0xbe, 0x55, 0xfe, 0x83, 0xfa, 0x41, 0x7c, 0x13, 0x0f, 0xbe, 0x45, 0xfe, 0x83,
	0xf8, 0x5a, 0x7f, 0x0a, 0x0f, 0xbe, 0x4d, 0xfe, 0x83, 0xc1, 0x20, 0x88, 0x4d, 0xfe, 0x0f, 0xbe,
	0x55, 0xff, 0x0f, 0xbe, 0x45, 0xfe, 0x3b, 0xd0, 0x74, 0x0c, 0x0f, 0xbe, 0x45, 0xff, 0x0f, 0xbe,
	0x4d, 0xfe, 0x2b, 0xc1, 0xeb, 0x23, 0x0f, 0xbe, 0x55, 0xff, 0x85, 0xd2, 0x75, 0x02, 0xeb, 0x17,
	0x8b, 0x45, 0x08, 0x83, 0xc0, 0x02, 0x89, 0x45, 0x08, 0x8b, 0x4d, 0x0c, 0x83, 0xc1, 0x01, 0x89,
	0x4d, 0x0c, 0xe9, 0x72, 0xff, 0xff, 0xff, 0x33, 0xc0, 0x8b, 0xe5, 0x5d, 0xc3, 0xcc, 0xcc, 0xcc,
	0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x55, 0x8b, 0xec, 0x83, 0xec, 0x30, 0x8b, 0x45, 0x08, 0x89, 0x45,
	0xe8, 0x8b, 0x4d, 0xe8, 0x8b, 0x55, 0x08, 0x03, 0x51, 0x3c, 0x89, 0x55, 0xe4, 0xb8, 0x08, 0x00,
	0x00, 0x00, 0x6b, 0xc8, 0x00, 0x8b, 0x55, 0xe4, 0x8d, 0x44, 0x0a, 0x78, 0x89, 0x45, 0xf4, 0x8b,
	0x4d, 0xf4, 0x8b, 0x55, 0x08, 0x03, 0x11, 0x89, 0x55, 0xf8, 0x8b, 0x45, 0xf4, 0x8b, 0x08, 0x89,
	0x4d, 0xf0, 0x8b, 0x55, 0xf4, 0x8b, 0x45, 0xf0, 0x03, 0x42, 0x04, 0x89, 0x45, 0xe0, 0x8b, 0x4d,
	0xf8, 0x8b, 0x55, 0x08, 0x03, 0x51, 0x1c, 0x89, 0x55, 0xd0, 0xc7, 0x45, 0xec, 0x00, 0x00, 0x00,
	0x00, 0x8b, 0x45, 0xe0, 0x3b, 0x45, 0xf0, 0x75, 0x04, 0x33, 0xc0, 0xeb, 0x75, 0x8b, 0x4d, 0xf8,
	0x8b, 0x55, 0x08, 0x03, 0x51, 0x20, 0x89, 0x55, 0xdc, 0x8b, 0x45, 0xf8, 0x8b, 0x4d, 0x08, 0x03,
	0x48, 0x24, 0x89, 0x4d, 0xd4, 0xc7, 0x45, 0xfc, 0x00, 0x00, 0x00, 0x00, 0xeb, 0x09, 0x8b, 0x55,
	0xfc, 0x83, 0xc2, 0x01, 0x89, 0x55, 0xfc, 0x8b, 0x45, 0xf8, 0x8b, 0x4d, 0xfc, 0x3b, 0x48, 0x18,
	0x73, 0x3a, 0x8b, 0x55, 0xfc, 0x8b, 0x45, 0xdc, 0x8b, 0x4d, 0x08, 0x03, 0x0c, 0x90, 0x89, 0x4d,
	0xd8, 0x8b, 0x55, 0x0c, 0x52, 0x8b, 0x45, 0xd8, 0x50, 0xe8, 0x07, 0xfe, 0xff, 0xff, 0x83, 0xc4,
	0x08, 0x85, 0xc0, 0x75, 0x15, 0x8b, 0x4d, 0xfc, 0x8b, 0x55, 0xd4, 0x0f, 0xb7, 0x04, 0x4a, 0x8b,
	0x4d, 0xd0, 0x8b, 0x14, 0x81, 0x89, 0x55, 0xec, 0xeb, 0x02, 0xeb, 0xb2, 0x8b, 0x45, 0x08, 0x03,
	0x45, 0xec, 0x8b, 0xe5, 0x5d, 0xc3, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
	0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x55, 0x8b, 0xec, 0x83, 0xec, 0x54, 0xc6, 0x45, 0xcc, 0x4b, 0xc6,
	0x45, 0xcd, 0x65, 0xc6, 0x45, 0xce, 0x72, 0xc6, 0x45, 0xcf, 0x6e, 0xc6, 0x45, 0xd0, 0x65, 0xc6,
	0x45, 0xd1, 0x6c, 0xc6, 0x45, 0xd2, 0x33, 0xc6, 0x45, 0xd3, 0x32, 0xc6, 0x45, 0xd4, 0x2e, 0xc6,
	0x45, 0xd5, 0x64, 0xc6, 0x45, 0xd6, 0x6c, 0xc6, 0x45, 0xd7, 0x6c, 0xc6, 0x45, 0xd8, 0x00, 0xc6,
	0x45, 0xbc, 0x4c, 0xc6, 0x45, 0xbd, 0x6f, 0xc6, 0x45, 0xbe, 0x61, 0xc6, 0x45, 0xbf, 0x64, 0xc6,
	0x45, 0xc0, 0x4c, 0xc6, 0x45, 0xc1, 0x69, 0xc6, 0x45, 0xc2, 0x62, 0xc6, 0x45, 0xc3, 0x72, 0xc6,
	0x45, 0xc4, 0x61, 0xc6, 0x45, 0xc5, 0x72, 0xc6, 0x45, 0xc6, 0x79, 0xc6, 0x45, 0xc7, 0x41, 0xc6,
	0x45, 0xc8, 0x00, 0xc6, 0x45, 0xdc, 0x46, 0xc6, 0x45, 0xdd, 0x72, 0xc6, 0x45, 0xde, 0x65, 0xc6,
	0x45, 0xdf, 0x65, 0xc6, 0x45, 0xe0, 0x4c, 0xc6, 0x45, 0xe1, 0x69, 0xc6, 0x45, 0xe2, 0x62, 0xc6,
	0x45, 0xe3, 0x72, 0xc6, 0x45, 0xe4, 0x61, 0xc6, 0x45, 0xe5, 0x72, 0xc6, 0x45, 0xe6, 0x79, 0xc6,
	0x45, 0xe7, 0x00, 0xc6, 0x45, 0xac, 0x47, 0xc6, 0x45, 0xad, 0x65, 0xc6, 0x45, 0xae, 0x74, 0xc6,
	0x45, 0xaf, 0x50, 0xc6, 0x45, 0xb0, 0x72, 0xc6, 0x45, 0xb1, 0x6f, 0xc6, 0x45, 0xb2, 0x63, 0xc6,
	0x45, 0xb3, 0x41, 0xc6, 0x45, 0xb4, 0x64, 0xc6, 0x45, 0xb5, 0x64, 0xc6, 0x45, 0xb6, 0x72, 0xc6,
	0x45, 0xb7, 0x65, 0xc6, 0x45, 0xb8, 0x73, 0xc6, 0x45, 0xb9, 0x73, 0xc6, 0x45, 0xba, 0x00, 0xc7,
	0x45, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x64, 0xa1, 0x30, 0x00, 0x00, 0x00, 0x89, 0x45, 0xec, 0x8b,
	0x4d, 0xec, 0x8b, 0x51, 0x0c, 0x89, 0x55, 0xe8, 0x8b, 0x45, 0xe8, 0x83, 0xc0, 0x0c, 0x89, 0x45,
	0xf4, 0x8b, 0x4d, 0xf4, 0x8b, 0x11, 0x89, 0x55, 0xfc, 0x8b, 0x45, 0xfc, 0x3b, 0x45, 0xf4, 0x74,
	0x32, 0x8b, 0x4d, 0xfc, 0x89, 0x4d, 0xf0, 0x8d, 0x55, 0xcc, 0x52, 0x8b, 0x45, 0xf0, 0x8b, 0x48,
	0x30, 0x51, 0xe8, 0x4e, 0xfd, 0xff, 0xff, 0x83, 0xc4, 0x08, 0x85, 0xc0, 0x75, 0x0b, 0x8b, 0x55,
	0xf0, 0x8b, 0x42, 0x18, 0x89, 0x45, 0xf8, 0xeb, 0x0a, 0x8b, 0x4d, 0xfc, 0x8b, 0x11, 0x89, 0x55,
	0xfc, 0xeb, 0xc6, 0x8d, 0x45, 0xac, 0x50, 0x8b, 0x4d, 0xf8, 0x51, 0xe8, 0xc5, 0xfd, 0xff, 0xff,
	0x83, 0xc4, 0x08, 0x8b, 0x55, 0x08, 0x89, 0x42, 0x08, 0x8d, 0x45, 0xbc, 0x50, 0x8b, 0x4d, 0xf8,
	0x51, 0x8b, 0x55, 0x08, 0x8b, 0x42, 0x08, 0xff, 0xd0, 0x8b, 0x4d, 0x08, 0x89, 0x01, 0x8d, 0x55,
	0xdc, 0x52, 0x8b, 0x45, 0xf8, 0x50, 0x8b, 0x4d, 0x08, 0x8b, 0x51, 0x08, 0xff, 0xd2, 0x8b, 0x4d,
	0x08, 0x89, 0x41, 0x04, 0x8b, 0xe5, 0x5d, 0xc3, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
	0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x55, 0x8b, 0xec, 0x83, 0xec, 0x14, 0xc7, 0x45, 0xfc, 0x00, 0x00,
	0x00, 0x00, 0x8d, 0x45, 0xec, 0x50, 0xe8, 0x5a, 0xfe, 0xff, 0xff, 0x83, 0xc4, 0x04, 0x8b, 0x4d,
	0x08, 0x51, 0xff, 0x55, 0xec, 0x89, 0x45, 0xfc, 0x83, 0x7d, 0xfc, 0x00, 0x74, 0x24, 0x8b, 0x55,
	0x0c, 0x52, 0x8b, 0x45, 0xfc, 0x50, 0xff, 0x55, 0xf4, 0x89, 0x45, 0xf8, 0x83, 0x7d, 0xf8, 0x00,
	0x74, 0x03, 0xff, 0x55, 0xf8, 0x83, 0x7d, 0x10, 0x00, 0x74, 0x07, 0x8b, 0x4d, 0xfc, 0x51, 0xff,
	0x55, 0xf0, 0x8b, 0xe5, 0x5d, 0xc3, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
	0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x81, 0xec, 0x84, 0x00, 0x00, 0x00, 0xe8, 0x1f, 0x00, 0x00, 0x00,
	0x05, 0x23, 0x00, 0x00, 0x00, 0x8b, 0x18, 0x53, 0x83, 0xc0, 0x04, 0x50, 0x83, 0xc0, 0x10, 0x50,
	0xe8, 0x80, 0xff, 0xff, 0xff, 0x83, 0xc4, 0x0c, 0x81, 0xc4, 0x84, 0x00, 0x00, 0x00, 0xc3, 0x8b,
	0x04, 0x24, 0xc3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

int InjectProcessDll(TCHAR * process, char * dll_path, const char * entry, int free_after_call){

	//fill args to loaddll_shellcode;
	*(UINT32*)&loaddll_sc[1107 + 0x0] = free_after_call;
	StrCpyA((char*)&loaddll_sc[1107 + 0x4], entry);
	StrCpyA((char*)&loaddll_sc[1107 + 0x4 + 0x10], dll_path);

	return InjectProcessShellcode(process,
		loaddll_sc,
		sizeof(loaddll_sc));
}
