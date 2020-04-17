#pragma once
#include "RTO Implant.h"


#if !defined(_WIN64)
#error The undocumented structures below are only valid for 64-bit code
#endif // !defined(_WIN64)

// Prototypes for the API calls used in this file (in the order they appear)
using NtQuerySystemInformationPrototype = NTSTATUS(NTAPI*)(IN SYSTEM_INFORMATION_CLASS, OUT PVOID, IN ULONG, OUT PULONG);
using VirtualFreePrototype = BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD);
using VirtualAllocPrototype = LPVOID(WINAPI*)(LPVOID, SIZE_T, DWORD, DWORD);
using lstrcmpiWPrototype = int(WINAPI*)(LPCWSTR, LPCWSTR);

// Thank you processhacker for all you internals struct documentation 
// https://github.com/processhacker/phnt/blob/33cfd75a2be59bbde3aa4db3399a9e6bab66ae6a/ntexapi.h
typedef struct _SYSTEM_PROCESS_INFO
{
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize; // since VISTA
    ULONG HardFaultCount; // since WIN7
    ULONG NumberOfThreadsHighWatermark; // since WIN7
    ULONGLONG CycleTime; // since WIN7
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey; // since VISTA (requires SystemExtendedProcessInformation)
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
    SYSTEM_THREAD_INFORMATION Threads[1];
} SYSTEM_PROCESS_INFO, * PSYSTEM_PROCESS_INFO;