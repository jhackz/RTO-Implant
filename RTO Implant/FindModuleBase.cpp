#include "RTO Implant.h"
#include "Resolve.h"

#pragma warning (disable:4055)
#pragma warning(disable:4996)


// Found this guy here
// https://support.microsoft.com/en-us/help/138813/how-to-convert-from-ansi-to-unicode-unicode-to-ansi-for-ole
HRESULT __fastcall UnicodeToAnsi(LPCOLESTR pszW, LPSTR* ppszA)
{

    ULONG cbAnsi, cCharacters;
    DWORD dwError;

    // If input is null then just return the same.
    if (pszW == NULL)
    {
        *ppszA = NULL;
        return NOERROR;
    }

    cCharacters = wcslen(pszW) + 1;
    // Determine number of bytes to be allocated for ANSI string. An
    // ANSI string can have at most 2 bytes per character (for Double
    // Byte Character Strings.)
    cbAnsi = cCharacters * 2;

    // Use of the OLE allocator is not required because the resultant
    // ANSI  string will never be passed to another COM component. You
    // can use your own allocator.
    *ppszA = (LPSTR)CoTaskMemAlloc(cbAnsi);
    if (NULL == *ppszA)
        return E_OUTOFMEMORY;

    // Convert to ANSI.
    if (0 == WideCharToMultiByte(CP_ACP, 0, pszW, cCharacters, *ppszA,
        cbAnsi, NULL, NULL))
    {
        dwError = GetLastError();
        CoTaskMemFree(*ppszA);
        *ppszA = NULL;
        return HRESULT_FROM_WIN32(dwError);
    }
    return NOERROR;

}


// I was doing this in a much more shotty fashion 
// The blog below detailed a much cleaner and elegant solution
//  https://blog.christophetd.fr/hiding-windows-api-imports-with-a-customer-loader/


// Dynamically finds the base address of a DLL in memory
PUCHAR FindModuleBase(PCHAR moduleName)
{
	// https://stackoverflow.com/questions/37288289/how-to-get-the-process-environment-block-peb-address-using-assembler-x64-os - x64 version
	PTEB teb = reinterpret_cast<PTEB>(__readgsqword(reinterpret_cast<DWORD_PTR>(&static_cast<NT_TIB*>(nullptr)->Self)));
	PPEB_LDR_DATA ldr = teb->ProcessEnvironmentBlock->Ldr;

	PLIST_ENTRY head = &ldr->InMemoryOrderModuleList;
	PLIST_ENTRY cur = head->Flink;


	do {
		PLDR_DATA_TABLE_ENTRY moduleEntry = CONTAINING_RECORD(cur, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		char* module_name;
		// Convert unicode buffer into char buffer for the time of the comparison, then free it
		UnicodeToAnsi(moduleEntry->FullDllName.Buffer, &module_name);
		char* result = strstr(module_name, moduleName);

		::CoTaskMemFree(module_name); // Free buffer allocated by UnicodeToAnsi

		if (result != NULL) {
			// Found the DLL entry in the PEB, return its base address
			return (PUCHAR)moduleEntry->DllBase;
		}
		cur = cur->Flink;
	} while (cur != head);


	return NULL;
}