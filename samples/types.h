#include "Windows.h"

typedef struct _UNICODE_STRING {
	USHORT 							Length;
	USHORT 							MaximumLength;
	PWSTR  							Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY						InLoadOrderLinks;
	PVOID 							Reserved2[2];
	PVOID 							DllBase;
	UNICODE_STRING 					FulllDLLName;
	// Other fields are omitted for brevity
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _LDR_MODULE {
	LIST_ENTRY						InMemoryOrderModuleList;
	LIST_ENTRY						InLoadOrderModuleList;
	LIST_ENTRY						InInitializationOrderModuleList;
	PVOID							BaseAddress;
	PVOID							EntryPoint;
	UINT32							SizeOfImage;
	UNICODE_STRING		        	FullDllName;
	UNICODE_STRING		        	BaseDllName;
	UINT32							Flags;
	INT16							LoadCount;
	INT16							TlsIndex;
	LIST_ENTRY						HashTableEntry;
	UINT32							TimeDateStamp;
} LDR_MODULE, * PLDR_MODULE;

typedef struct _PEB_LDR_DATA {
	UINT32							Length;
	UINT32							Initialized;
	PVOID							SsHandle;
	LIST_ENTRY						InLoadOrderModuleList;
	LIST_ENTRY						InMemoryOrderModuleList;
	LIST_ENTRY						InInitializationOrderModuleList;
}PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
	UINT32							MaximumLength;
	UINT32							Length;

	UINT32							Flags;
	UINT32							DebugFlags;
	HANDLE							ConsoleHandle;
	UINT32							ConsoleFlags;
	HANDLE							StandardInput;
	HANDLE 							StandardOutput;
	HANDLE							StandardError;
	// Other fields are omitted for brevity
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

// Process Environment Block
typedef struct PEB {
	BOOLEAN							InheritedAddressSpace;
	BOOLEAN							ReadImageFileExecOptions;
	BOOLEAN							BeingDebugged;
	BOOLEAN							Spare;
	HANDLE							Mutant;
	PVOID							ImageBase;
	PPEB_LDR_DATA					LoaderData;
	PRTL_USER_PROCESS_PARAMETERS	ProcessParameters;
	// Other fields are omitted for brevity
} PEB, * PPEB;


typedef BOOL(WINAPI* WriteConsoleA_t)(HANDLE hConsoleOutput, LPCSTR lpBuffer, DWORD nNumberOfCharsToWrite, LPDWORD lpNumberOfCharsWritten, LPDWORD lpReserved);

#ifdef _WIN64

#define PEB_OFFSET 0x60

#else // WIN32

#define PEB_OFFSET 0x30

#endif // !WIN32

#define towlower(c) (((c) >= L'A' && (c) <= L'Z') ? ((c) + (L'a' - L'A')) : (c))
#define tolower(c) (((c) >= 'A' && (c) <= 'Z') ? ((c) + ('a' - 'A')) : (c))
