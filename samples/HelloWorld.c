// Check Compiler
#if defined(_MSC_VER) && !defined(__clang__) && !defined(__GNUC__)
#define COMPILER_MSVC
#elif defined(__GNUC__) 
#define COMPILER_GCC
#elif defined(__clang__)
#define COMPILER_CLANG
#endif

// Check windows
#if defined(COMPILER_MSVC)
#if defined(_WIN64)
#define ENVIRONMENT_x86_64
#else
#define ENVIRONMENT_I386
#endif
// Check GCC
#elif defined(COMPILER_GCC) 
#if defined(__aarch64__) || defined(_M_ARM64)
#define ENVIRONMENT_ARM64
#elif defined(__arm__) || defined(_M_ARM)
#define ENVIRONMENT_ARM32
#elif defined(__x86_64__) || defined(__amd64__) || defined(_M_X64)
#define ENVIRONMENT_x86_64
#elif defined(__i386__) || defined(_M_IX86)
#define ENVIRONMENT_I386
#else
#error Unsupported architecture
#endif

#elif defined(COMPILER_CLANG)
#if defined(__aarch64__) || defined(_M_ARM64)
#define ENVIRONMENT_ARM64
#elif defined(__arm__) || defined(_M_ARM)
#define ENVIRONMENT_ARM32
#elif defined(__x86_64__) || defined(__amd64__) || defined(_M_X64)
#define ENVIRONMENT_x86_64
#elif defined(__i386__) || defined(_M_IX86)
#define ENVIRONMENT_I386
#else
#error Unsupported architecture
#endif
#endif	

#if defined(ENVIRONMENT_ARM64) || defined(ENVIRONMENT_ARM32)
int mainCRTStartup() {
	return -1; // Not supported
}
#else

#include "Windows.h"

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING* PUNICODE_STRING;


// Define LDR_DATA_TABLE_ENTRY structure
typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY										InLoadOrderLinks;
	PVOID Reserved2[2];
	PVOID DllBase;
	UNICODE_STRING FulllDLLName;
	// Other fields are omitted for brevity
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _LDR_MODULE {
	LIST_ENTRY					InMemoryOrderModuleList;
	LIST_ENTRY					InLoadOrderModuleList;
	LIST_ENTRY					InInitializationOrderModuleList;
	PVOID						BaseAddress;
	PVOID						EntryPoint;
	UINT32						SizeOfImage;
	UNICODE_STRING		FullDllName;
	UNICODE_STRING		BaseDllName;
	UINT32						Flags;
	INT16						LoadCount;
	INT16						TlsIndex;
	LIST_ENTRY					HashTableEntry;
	UINT32						TimeDateStamp;
} LDR_MODULE, * PLDR_MODULE;

typedef struct _PEB_LDR_DATA {
	UINT32											Length;
	UINT32											Initialized;
	PVOID											SsHandle;
	LIST_ENTRY										InLoadOrderModuleList;
	LIST_ENTRY										InMemoryOrderModuleList;
	LIST_ENTRY										InInitializationOrderModuleList;
}PEB_LDR_DATA, * PPEB_LDR_DATA;

#define RTL_MAX_DRIVE_LETTERS 32

typedef struct _CURDIR
{
	UNICODE_STRING DosPath;
	HANDLE Handle;
} CURDIR, * PCURDIR;

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
	UINT16 Flags;
	UINT16 Length;
	UINT32 TimeStamp;
	UNICODE_STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
	UINT32 MaximumLength;
	UINT32 Length;

	UINT32 Flags;
	UINT32 DebugFlags;

	HANDLE ConsoleHandle;
	UINT32 ConsoleFlags;
	HANDLE StandardInput;
	HANDLE StandardOutput;
	HANDLE StandardError;

	CURDIR CurrentDirectory;
	UNICODE_STRING DllPath;
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
	PWCHAR Environment;

	UINT32 StartingX;
	UINT32 StartingY;
	UINT32 CountX;
	UINT32 CountY;
	UINT32 CountCharsX;
	UINT32 CountCharsY;
	UINT32 FillAttribute;

	UINT32 WindowFlags;
	UINT32 ShowWindowFlags;
	UNICODE_STRING WindowTitle;
	UNICODE_STRING DesktopInfo;
	UNICODE_STRING ShellInfo;
	UNICODE_STRING RuntimeData;
	RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

	ULONG_PTR EnvironmentSize;
	ULONG_PTR EnvironmentVersion;
	PVOID PackageDependencyData;
	UINT32 ProcessGroupId;
	UINT32 LoaderThreads;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;



// Process Environment Block
typedef struct PEB {
	BOOLEAN											InheritedAddressSpace;
	BOOLEAN											ReadImageFileExecOptions;
	BOOLEAN											BeingDebugged;
	BOOLEAN											Spare;
	HANDLE											Mutant;
	PVOID											ImageBase;
	PPEB_LDR_DATA									LoaderData;
	PRTL_USER_PROCESS_PARAMETERS					ProcessParameters;
	PVOID											SubSystemData;
	PVOID											ProcessHeap;
} PEB, * PPEB;


typedef BOOL(WINAPI* WriteConsoleA_t)(HANDLE hConsoleOutput, LPCSTR lpBuffer, DWORD nNumberOfCharsToWrite, LPDWORD lpNumberOfCharsWritten, LPDWORD lpReserved);

#ifdef _WIN64

#define PEB_OFFSET 0x60

#else // WIN32

#define PEB_OFFSET 0x30

#endif // !WIN32

#define towlower(c) (((c) >= L'A' && (c) <= L'Z') ? ((c) + (L'a' - L'A')) : (c))

HMODULE GetModuleBaseAddress(PPEB peb, const wchar_t* moduleName);
BOOL wcscmp_custom(const wchar_t* str1, const wchar_t* str2);


int mainCRTStartup() {

	PEB* peb;
#ifdef _WIN64

#ifdef __GNUC__
	asm("movq %%gs:%1, %0" : "=r" (peb) : "m" (*(unsigned long long*)(PEB_OFFSET)));
#else
	peb = (PEB*)__readgsqword(PEB_OFFSET);
#endif 

#else // WIN32

#ifdef __GNUC__
	asm("movl %%fs:%1, %0" : "=r" (peb) : "m" (*(unsigned long*)(PEB_OFFSET)));
#else
	peb = (PEB*)__readfsdword(PEB_OFFSET);
#endif 

#endif // WIN32


	//Kernel32
	HANDLE kernel32Base = GetModuleBaseAddress(peb, L"Kernel32.dll");

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)kernel32Base;

	PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)((UINT64)kernel32Base + pDosHeader->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((UINT64)kernel32Base + pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);


	UINT32* pAddressOfFunctions = (UINT32*)((UINT64)kernel32Base + pExportDirectory->AddressOfFunctions);
	UINT32* pAddressOfNames = (UINT32*)((UINT64)kernel32Base + pExportDirectory->AddressOfNames);
	UINT16* pAddressOfNameOrdinals = (UINT16*)((UINT64)kernel32Base + pExportDirectory->AddressOfNameOrdinals);

	WriteConsoleA_t WriteConsoleAFunc = NULL;

	for (UINT32 i = 0; i < pExportDirectory->NumberOfNames; i++) {
		char* pFunctionName = (char*)((ULONG_PTR)kernel32Base + pAddressOfNames[i]);

		//long value = simple_hash64("WriteConsoleA");

		//printf("%s\n", pFunctionName);

		if (pFunctionName[0] == 'W' && pFunctionName[5] == 'C'&& pFunctionName[12] == 'A') {

			UINT32 functionOrdinal = pAddressOfNameOrdinals[i];
			UINT32 functionRVA = pAddressOfFunctions[functionOrdinal];

			WriteConsoleAFunc = (WriteConsoleA_t)((UINT64)kernel32Base + functionRVA);
		}
	}


	if (WriteConsoleAFunc != NULL)
#define ApiLoadedMessage ((char []){ 'H', 'e', 'l','l','o',' ','W','o','r','l','d','!','\n' ,'\0' })
		WriteConsoleAFunc(peb->ProcessParameters->StandardOutput, (char*)ApiLoadedMessage, sizeof(ApiLoadedMessage), NULL, NULL);

	return 0;
}

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

//compare w char strings

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
#endif
