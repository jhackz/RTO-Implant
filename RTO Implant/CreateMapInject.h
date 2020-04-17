#pragma once
#include "RTO Implant.h"

typedef struct _CID
{
	PVOID UniqueProcess;
	PVOID UniqueThread;
} CID, * PCID;


// Function prototypes in the order they are used
// https://ired.team/offensive-security/code-injection-process-injection/ntcreatesection-+-ntmapviewofsection-code-injection
using NtCreateSectionPrototype = NTSTATUS(NTAPI*)(OUT PHANDLE, IN ULONG, IN POBJECT_ATTRIBUTES OPTIONAL, IN PLARGE_INTEGER OPTIONAL, IN ULONG, IN ULONG, IN HANDLE OPTIONAL);
using GetCurrentProcessPrototype = HANDLE(WINAPI*)();
using NtMapViewOfSectionPrototype = NTSTATUS(NTAPI*)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);
using OpenProcessPrototype = HANDLE(WINAPI*)(DWORD, BOOL, DWORD);
using RtlCreateUserThreadPrototype = NTSTATUS(NTAPI*)(IN HANDLE, IN PSECURITY_DESCRIPTOR OPTIONAL, IN BOOLEAN, IN ULONG, IN OUT PULONG, IN OUT PULONG, IN PVOID, IN PVOID OPTIONAL, OUT PHANDLE, OUT PCID);
