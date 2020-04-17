#include "Resolve.h"
#include "z85.h"

// Globals for being used later 
PUCHAR Kernel32Base;
GetProcAddressPrototype fGetProcAddress;
GetModuleHandleAPrototype fGetModuleHandleA;


// There is a better way to do this
// Something to revise in the future 
VOID InitResolve()
{
    CHAR e_Kernel32dll[] = "1ogq-NmnbG)e<@xb0000";
    CHAR e_GetProcAddress[] = "1m}D^sA=kCNwmPZ(B8}rY1234";
    CHAR e_GetModuleHandleA[] = "1m}D^pz!a0bwK{lEwnC*y0000";

    CHAR d_Kernel32dll[13] = {};
    CHAR d_GetProcAddress[17] = {};
    CHAR d_GetModuleHandleA[17] = {};

    Z85_decode_with_padding(e_Kernel32dll, d_Kernel32dll, sizeof(e_Kernel32dll));
    Z85_decode_with_padding(e_GetProcAddress, d_GetProcAddress, sizeof(e_GetProcAddress));
    Z85_decode_with_padding(e_GetModuleHandleA, d_GetModuleHandleA, sizeof(e_GetModuleHandleA));

    Kernel32Base = FindModuleBase(d_Kernel32dll);
    fGetProcAddress = (GetProcAddressPrototype)FindModuleExport(Kernel32Base, d_GetProcAddress);
    fGetModuleHandleA = (GetModuleHandleAPrototype)FindModuleExport(Kernel32Base, d_GetModuleHandleA);

    return;
}

// Resolve API function used to dynamically resolve APIs used
PVOID ResolveAPI(LPCSTR module, LPCSTR functionName)
{
  	return (PVOID)fGetProcAddress(fGetModuleHandleA(module), functionName);
}
