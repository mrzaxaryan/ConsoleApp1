#include "types.h"

HMODULE GetModuleBaseAddress(PPEB peb, const wchar_t* moduleName);
FARPROC GetFunction(HANDLE hModule, const char* functionName);
BOOL wcscmp_custom(const wchar_t* str1, const wchar_t* str2);
BOOL strcmp_custom(const char* str1, const char* str2);

int mainCRTStartup() {

	PEB* peb;
#ifdef _WIN64

	asm("movq %%gs:%1, %0" : "=r" (peb) : "m" (*(unsigned long long*)(PEB_OFFSET)));

#else // WIN32

	asm("movl %%fs:%1, %0" : "=r" (peb) : "m" (*(unsigned long*)(PEB_OFFSET)));

#endif // WIN32

	HANDLE kernel32Base = GetModuleBaseAddress(peb, 
		((wchar_t*)((wchar_t[]) { L'K', L'e', L'r', L'n', L'e', L'l', L'3', L'2', L'.', L'd', L'l', L'l', L'\0' })));
	
	if (kernel32Base == NULL)
		return -2;

	WriteConsoleA_t WriteConsoleAFunc = (WriteConsoleA_t)GetFunction(kernel32Base, 
		((char*)(char[]){'W','r', 'i', 't', 'e', 'C', 'o', 'n', 's', 'o', 'l', 'e', 'A', '\0'}));

	if (WriteConsoleAFunc == NULL)
		return -1;

	WriteConsoleAFunc(peb->ProcessParameters->StandardOutput, 
		((char*)((char []){ 'H', 'e', 'l','l','o',' ','W','o','r','l','d','!','\n' ,'\0' })), 
		sizeof(((char []){ 'H', 'e', 'l','l','o',' ','W','o','r','l','d','!','\n' ,'\0' })),
		 NULL, NULL);

	return 0;
}

// Get the base address of a module by its name
HMODULE GetModuleBaseAddress(PPEB peb,const wchar_t* moduleName) {
	PLIST_ENTRY entry = peb->LoaderData->InMemoryOrderModuleList.Flink; // Getting the first entry in the InMemoryOrderModuleList
	PVOID firstEntry = entry; // Save the first entry to detect when we loop back to it

	do {
		PLDR_MODULE entryData = (PLDR_MODULE)entry; // Cast the entry to a PLDR_MODULE structure
		// Check if the FullDllName.Buffer is NULL
		if (entryData->FullDllName.Buffer == NULL)
			break;
		
		if (wcscmp_custom(entryData->FullDllName.Buffer, moduleName)) { // Compare the module name with the target module name
			return (HMODULE)((PLDR_DATA_TABLE_ENTRY)entry)->DllBase;; // Return the base address if a match is found
		}
		entry = entry->Flink; // Move to the next entry in the list
	} while (entry != NULL && entry != firstEntry); // Loop until we either find the module or loop back to the first entry

	return NULL; // Return NULL if the module was not found
}

// Get the address of a function by its name from a module base address
FARPROC GetFunction(HANDLE hModule, const char* functionName) {
	PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PCHAR)hModule + ((PIMAGE_NT_HEADERS)((PCHAR)hModule + ((PIMAGE_DOS_HEADER)hModule)->e_lfanew))->OptionalHeader.DataDirectory[0].VirtualAddress);
	// Loop through the names in the export directory
	for (UINT32 i = 0; i < exportDirectory->NumberOfNames; ++i) {
		// Getting the address of the function name
		PCHAR pszVar = (PCHAR)hModule + ((INT32*)((PCHAR)hModule + exportDirectory->AddressOfNames))[i];
		// Compare the function name with the target function name
		if (strcmp_custom(pszVar, functionName)) {
			// Return the address of the function if a match is found
			return (FARPROC)((PCHAR)hModule + ((INT32*)((PCHAR)hModule + exportDirectory->AddressOfFunctions))[((PUINT16)((PCHAR)hModule + exportDirectory->AddressOfNameOrdinals))[i]]);
		}
	}
	return NULL;
}

// Custom case-insensitive wide string comparison
BOOL wcscmp_custom(const wchar_t* str1, const wchar_t* str2) {
	while (*str1 && *str2) {
		wchar_t c1 = towlower(*str1);
		wchar_t c2 = towlower(*str2);
		if (c1 != c2) {
			return FALSE; // They differ in case-folded form
		}
		str1++;
		str2++;
	}
	return (*str1 == *str2); // Both must land on the null terminator together
}

// Custom case-insensitive string comparison
BOOL strcmp_custom(const char* str1, const char* str2) {
	while (*str1 && *str2) {
		char c1 = tolower(*str1);
		char c2 = tolower((char)(*str2));
		if (c1 != c2) {
			return FALSE; // They differ in case-folded form
		}
		str1++;
		str2++;
	}
	return (*str1 == *str2); // Both must land on the null terminator together
}