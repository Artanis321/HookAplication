// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "disasm-lib/disasm.h"
#include "ApiHookFunction.h"
#include <Windows.h>
#include "mhook.h"
#include <winternl.h>

typedef BOOL(WINAPI* WRITE_PROCESS_MEMORY)(
    _In_  HANDLE  hProcess,
    _In_  LPVOID  lpBaseAddress,
    _In_  LPCVOID lpBuffer,
    _In_  SIZE_T  nSize,
    _Out_ SIZE_T* lpNumberOfBytesWritten
    );
typedef BOOL(WINAPI* READ_PROCESS_MEMORY)(
    _In_  HANDLE  hProcess,
    _In_  LPCVOID lpBaseAddress,
    _Out_ LPVOID  lpBuffer,
    _In_  SIZE_T  nSize,
    _Out_ SIZE_T* lpNumberOfBytesRead
    );

typedef BOOL (WINAPI* READ_FILE)(
    HANDLE       hFile,
    LPVOID       lpBuffer,
    DWORD        nNumberOfBytesToRead,
    LPDWORD      lpNumberOfBytesRead,
    LPOVERLAPPED lpOverlapped
);

typedef BOOL(WINAPI* WRITE_FILE)(
    HANDLE       hFile,
    LPCVOID      lpBuffer,
    DWORD        nNumberOfBytesToWrite,
    LPDWORD      lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped
);

typedef NTSTATUS(WINAPI* PNT_QUERY_SYSTEM_INFORMATION)(
    __in       SYSTEM_INFORMATION_CLASS SystemInformationClass,
    __inout    PVOID SystemInformation,
    __in       ULONG SystemInformationLength,
    __out_opt  PULONG ReturnLength
    );

PNT_QUERY_SYSTEM_INFORMATION OriginalNtQuerySystemInformation =
(PNT_QUERY_SYSTEM_INFORMATION)::GetProcAddress(::GetModuleHandle(L"ntdll"),
    "NtQuerySystemInformation");

READ_PROCESS_MEMORY OriginalReadPM =
(READ_PROCESS_MEMORY)::GetProcAddress(::GetModuleHandle(L"Kernel32"), "ReadProcessMemory");

WRITE_PROCESS_MEMORY OriginalWritePM =
(WRITE_PROCESS_MEMORY)::GetProcAddress(::GetModuleHandle(L"Kernel32"), "WriteProcessMemory");

READ_FILE OriginalReadFile = (READ_FILE)::GetProcAddress(::GetModuleHandle(L"Kernel32"), "ReadFile");

WRITE_FILE OriginalWriteFile = (WRITE_FILE)::GetProcAddress(::GetModuleHandle(L"Kernel32"), "WriteFile");

BOOL WINAPI DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {

    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        Mhook_SetHook((PVOID*)&OriginalReadPM,
            HookReadProcessMemory);
        Mhook_SetHook((PVOID*)&OriginalWritePM,
            HookWriteProcessMemory);
        Mhook_SetHook((PVOID*)&OriginalReadFile, HookReadFile);
        Mhook_SetHook((PVOID*)&OriginalWriteFile, HookWriteFile);

        break;
    case DLL_PROCESS_DETACH:
        Mhook_Unhook((PVOID*)&OriginalReadPM);
        Mhook_Unhook((PVOID*)&OriginalWritePM);
        Mhook_Unhook((PVOID*)&OriginalReadFile);
        Mhook_Unhook((PVOID*)&OriginalWriteFile);
        break;

    }
}

