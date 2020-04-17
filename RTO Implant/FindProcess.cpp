#include "FindProcess.h"
#include "Resolve.h"
#include "z85.h"


// Use NtQuerySystemInfo to get a list of running processes on the system
// Check if our target process is running and return the pid
DWORD FindProcess(LPCWSTR processName)
{
	DWORD pid = -1;
	NTSTATUS status;
	PSYSTEM_PROCESS_INFO spi;
	PVOID processBuffer;
	ULONG returnLength;

	CHAR e_ntdll[] = "2zGGA9yYBCn0000";
	CHAR d_ntdll[10] = {};

	CHAR e_NtQuerySystemInformation[] = "1piouQwPA5{D2[7szaORSz/PY6BzkVh0000";
	CHAR d_NtQuerySystemInformation[25] = {};

	CHAR e_kernel32[] = "1yH}K7wO:dT0000";
	CHAR d_kernel32[9] = {};

	CHAR e_VirtualFree[] = "1r+VO@BZY8QA+e!Z1234";
	CHAR d_VirtualFree[13] = {};

	CHAR e_VirtualAlloc[] = "1r+VO@BZY8Ly&1310000";
	CHAR d_VirtualAlloc[13] = {};

	CHAR e_lstrcmpiW[] = "1y&:Ysv@lg0r@-j21234";
	CHAR d_lstrcmpiW[13] = {};

	Z85_decode_with_padding(e_ntdll, d_ntdll, sizeof(e_ntdll));
	Z85_decode_with_padding(e_NtQuerySystemInformation, d_NtQuerySystemInformation, sizeof(e_NtQuerySystemInformation));


	// Decided to resolve the API just prior to the API being called.
	// Should try messing with this to determine which way is better...
	// Resolve them all at once or just before the API call
	NtQuerySystemInformationPrototype fNtQuerySystemInformation = (NtQuerySystemInformationPrototype)ResolveAPI(d_ntdll, d_NtQuerySystemInformation);

	// Get our return length with our first call to NtQuerySystemInfromation
	if (!NT_SUCCESS(status = fNtQuerySystemInformation(SystemProcessInformation, NULL, NULL, &returnLength)))
	{
		Z85_decode_with_padding(e_kernel32, d_kernel32, sizeof(e_kernel32));
		Z85_decode_with_padding(e_VirtualFree, d_VirtualFree, sizeof(e_VirtualFree));
		Z85_decode_with_padding(e_VirtualAlloc, d_VirtualAlloc, sizeof(e_VirtualAlloc));

		VirtualFreePrototype fVirtualFree = (VirtualFreePrototype)ResolveAPI(d_kernel32, d_VirtualFree);
		VirtualAllocPrototype fVirtualAlloc = (VirtualAllocPrototype)ResolveAPI(d_kernel32, d_VirtualAlloc);
		// Allocate our buffer of size returnLength here
		processBuffer = fVirtualAlloc(NULL, returnLength, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if (processBuffer == NULL)
		{
			return -1;
		}

		spi = (PSYSTEM_PROCESS_INFO)processBuffer;
		if (!NT_SUCCESS(status = fNtQuerySystemInformation(SystemProcessInformation, spi, returnLength, NULL)))
		{
			fVirtualFree(processBuffer, 0, MEM_RELEASE);
			return -1;
		}

		Z85_decode_with_padding(e_lstrcmpiW, d_lstrcmpiW, sizeof(e_lstrcmpiW));
		lstrcmpiWPrototype flstrcmpiW = (lstrcmpiWPrototype)ResolveAPI(d_kernel32, d_lstrcmpiW);
		// Iterate over the entire list 
		while (spi->NextEntryOffset)
		{
			if (flstrcmpiW(spi->ImageName.Buffer, processName) == 0)
			{

				pid = (DWORD)spi->UniqueProcessId;
				break;
			}

			// Get our next entry 
			spi = (PSYSTEM_PROCESS_INFO)((LPBYTE)spi + spi->NextEntryOffset);
		}

		fVirtualFree(processBuffer, 0, MEM_RELEASE);
	}

	else
	{
		return pid;
	}

	return pid;
}