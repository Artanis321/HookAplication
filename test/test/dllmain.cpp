
#include "pch.h"
#include "ApiHookFunction.h"
#include <iostream>
#include <Windows.h>
#include "mhook.h"
#include <memoryapi.h>
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

BOOL WINAPI DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {

    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        Mhook_SetHook((PVOID*)&OriginalReadPM,
            HookReadProcessMemory);
        Mhook_SetHook((PVOID*)&OriginalWritePM,
            HookWriteProcessMemory);

        break;
    case DLL_PROCESS_DETACH:
        Mhook_Unhook((PVOID*)&OriginalReadPM);
        Mhook_Unhook((PVOID*)&OriginalWritePM);
        break;

    }
}