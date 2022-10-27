#include <Windows.h>

typedef int (WINAPI *fnMessageBoxA)(
	HWND    hWnd,
	LPCSTR lpText,
	LPCSTR lpCaption,
	UINT    uType
);
fnMessageBoxA _MessageBoxA;

#define AddOfSetPointer(MODULE,Pointer) PCHAR(PCHAR(MODULE) + DWORD(Pointer))

PVOID MyGetProcAddress(HMODULE ModuleBase, LPSTR Func)
{
	PIMAGE_DOS_HEADER ImageDosHeader = PIMAGE_DOS_HEADER(ModuleBase);
	if (ImageDosHeader->e_magic == IMAGE_DOS_SIGNATURE)
	{
		PIMAGE_NT_HEADERS32 pNtHeader = PIMAGE_NT_HEADERS32(AddOfSetPointer(ModuleBase, ImageDosHeader->e_lfanew));
		if (pNtHeader->Signature == IMAGE_NT_SIGNATURE)
		{
			if (pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
			{
				if (IMAGE_DIRECTORY_ENTRY_EXPORT < pNtHeader->OptionalHeader.NumberOfRvaAndSizes)
				{
					PIMAGE_EXPORT_DIRECTORY pImageExport = PIMAGE_EXPORT_DIRECTORY(PVOID(AddOfSetPointer(ModuleBase, pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)));
					if (pImageExport != ERROR)
					{
						PDWORD pAddressOfNames = PDWORD(AddOfSetPointer(ModuleBase, pImageExport->AddressOfNames));
						for (DWORD n{}; n < pImageExport->NumberOfNames; ++n)
						{
							LPCSTR ImportFunction = AddOfSetPointer(ModuleBase, pAddressOfNames[n]);
							if (lstrcmpA(ImportFunction, Func) == 0)
							{
								PDWORD AddressOfFunctions = PDWORD(AddOfSetPointer(ModuleBase, pImageExport->AddressOfFunctions));
								PWORD AddressOfOrdinals = PWORD(AddOfSetPointer(ModuleBase, pImageExport->AddressOfNameOrdinals));
								return PVOID(AddOfSetPointer(ModuleBase, AddressOfFunctions[AddressOfOrdinals[n]]));
							}
						}
					}
				}
			}
		}
	}
}

INT WINAPI WinMain(HINSTANCE current, HINSTANCE previos, LPSTR Line, INT Show)
{
	HMODULE hModule = LoadLibraryA("USER32.DLL");
	_MessageBoxA = fnMessageBoxA(MyGetProcAddress(hModule, "MessageBoxA"));
	_MessageBoxA(0, "Hello", 0, 0);
}