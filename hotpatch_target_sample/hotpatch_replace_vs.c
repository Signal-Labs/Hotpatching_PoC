// hotpatch_replace_vs.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <windows.h>
#include <winternl.h>

#define DEFAULT_SECURITY_COOKIE 0x000005968773625;

UINT_PTR __security_cookie = DEFAULT_SECURITY_COOKIE;

__declspec(dllexport)
DWORD64 DllGetActivationFactory(DWORD64* arg1, DWORD64* arg2) {
    return 0x13371337;
}



__declspec(dllexport)
void CreateFileTest() {
    HANDLE hFile = 0;
    const wchar_t* str = L"\\??\\C:\\Code\\ITWORKS.txt";
    UNICODE_STRING path;
    OBJECT_ATTRIBUTES attributes;
    path.Buffer = str;
    path.Length = (USHORT)24 * sizeof(wchar_t);
    path.MaximumLength = path.Length + sizeof(wchar_t);
    InitializeObjectAttributes(&attributes,
        &path,
        OBJ_CASE_INSENSITIVE,
        0,
        0);
    IO_STATUS_BLOCK stat;
    NTSTATUS res = NtCreateFile(&hFile, GENERIC_ALL, &attributes, &stat, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN_IF, FILE_NON_DIRECTORY_FILE, NULL, 0);
    NtClose(hFile);
}


void __security_check_cookie() {
    return;
}

__declspec(dllexport)
void KernelbasePostInit() {
    CreateFileTest();
}

__declspec(dllexport)
void BaseThreadInitThunk() {
    CreateFileTest();
}

__declspec(dllexport)
void TermsrcGetWindowsDirectoryW() {
    CreateFileTest();
}

__declspec(dllexport)
void BaseQueryModuleData() {
    CreateFileTest();
}

__declspec(dllexport)
void __PatchMainCallout__() {
    CreateFileTest();
    __debugbreak();
    return;
}

__declspec(dllexport)
void _DllMainCRTStartup() {
    CreateFileTest();
}


BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,  // handle to DLL module
    DWORD fdwReason,     // reason for calling function
    LPVOID lpvReserved)  // reserved
{
    CreateFileTest();
    
    return TRUE;  // Successful DLL_PROCESS_ATTACH.
}