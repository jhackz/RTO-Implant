#include "RTO Implant.h"

// Return the address of an exported function 
PVOID FindModuleExport(PUCHAR moduleBase, PCHAR functionName)
{
	// Read the PE and NT header
	PIMAGE_DOS_HEADER           DosHeader;
	PIMAGE_NT_HEADERS64         NtHeader;
	PIMAGE_OPTIONAL_HEADER64    OptionalHeader;
	PIMAGE_DATA_DIRECTORY       DataDirectory;
	PIMAGE_EXPORT_DIRECTORY     ExportDirectory;
	PULONG                      FunctionTable;
	PULONG                      NameTable;
	PUSHORT                     NameOrdinalTable;
	ULONG                       FunctionNameLen;
	

	// Using moduleBase as the base load address setup the pointers
	// DosHeader, NtHeader, OptionalHeader, DataDirectory and ExportDirectory
	DosHeader = (PIMAGE_DOS_HEADER)moduleBase;
	NtHeader = (PIMAGE_NT_HEADERS64)(moduleBase + DosHeader->e_lfanew);
	OptionalHeader = (PIMAGE_OPTIONAL_HEADER64)&NtHeader->OptionalHeader;
	DataDirectory = (PIMAGE_DATA_DIRECTORY)&OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(moduleBase + DataDirectory->VirtualAddress);

	// Great resource here for understanding these 3 parallel arrays
	// https://github.com/LloydLabs/Windows-API-Hashing
	FunctionTable = (PULONG)(moduleBase + ExportDirectory->AddressOfFunctions);
	NameTable = (PULONG)(moduleBase + ExportDirectory->AddressOfNames);
	NameOrdinalTable = (PUSHORT)(moduleBase + ExportDirectory->AddressOfNameOrdinals);

	FunctionNameLen = (ULONG)strlen(functionName);

	// Iterate through all the names in the NameTable 
	for (ULONG i = 0; i < ExportDirectory->NumberOfNames; i++)
	{
		PCHAR Name;
		Name = (PCHAR)(moduleBase + NameTable[i]);

		// Check to see if the our functionName matches the name in the nametable
		if (memcmp(Name, functionName, (FunctionNameLen + 1)) == 0)
		{
			USHORT NameOrdinal;
			PVOID ExportRVA;

			// Get the NameOrdinal from the NameOrdinalTable
			NameOrdinal = NameOrdinalTable[i];

			// Use the nameOrdinal to retrieve the RVA from the function table
			ExportRVA = (PVOID)(moduleBase + FunctionTable[NameOrdinal]);

			return ExportRVA;
		}
	}

	return NULL;
}