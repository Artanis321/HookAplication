// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <detours.h>
#include <iostream>
#include "ApiHookFunction.h"

HANDLE hMutex;

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{

    hMutex = OpenMutex(MUTEX_ALL_ACCESS, NULL, TEXT("MutexOnThreadSafe"));
    
    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH:
        {
            DetourTransactionBegin();
            DetourUpdateThread(GetCurrentThread());
            DetourAttach(&(PVOID&)RealWriteProcessMemory, HookWriteProcessMemory);
            DetourAttach(&(PVOID&)RealReadProcessMemory, HookReadProcessMemory);
            DetourAttach(&(PVOID&)RealVirtualAllocEx, HookVirtualAllocEx);
            DetourAttach(&(PVOID&)RealVirtualAlloc, HookVirtualAlloc);
            //DetourAttach(&(PVOID&)RealVirtualAlloc2, HookVirtualAlloc2);
            DetourAttach(&(PVOID&)RealCreateRemoteThread, HookCreateRemoteThread);
            DetourAttach(&(PVOID&)RealCreateRemoteThreadEx, HookCreateRemoteThreadEx);
            DetourAttach(&(PVOID&)RealOpenProcess, HookOpenProcess);
            DetourAttach(&(PVOID&)RealOpenThread, HookOpenThread);
            DetourAttach(&(PVOID&)RealResumeThread, HookResumeThread);
            DetourAttach(&(PVOID&)RealCreateProcessA, HookCreateProcessA);
            DetourAttach(&(PVOID&)RealCreateProcessW, HookCreateProcessW);
            DetourAttach(&(PVOID&)RealSetThreadContext, HookSetThreadContext);
            DetourAttach(&(PVOID&)RealZwUnmapViewOfSection, HookZwUnmapViewOfSection);
            DetourTransactionCommit();
            break;
        }
        case DLL_PROCESS_DETACH:
        {
            DetourTransactionBegin();
            DetourUpdateThread(GetCurrentThread());
            DetourDetach(&(PVOID&)RealWriteProcessMemory, HookWriteProcessMemory);
            DetourDetach(&(PVOID&)RealReadProcessMemory, HookReadProcessMemory);
            DetourDetach(&(PVOID&)RealVirtualAllocEx, HookVirtualAllocEx);
            DetourDetach(&(PVOID&)RealVirtualAlloc, HookVirtualAlloc);
            //DetourDetach(&(PVOID&)RealVirtualAlloc2, HookVirtualAlloc2);
            DetourDetach(&(PVOID&)RealCreateRemoteThread, HookCreateRemoteThread);
            DetourDetach(&(PVOID&)RealCreateRemoteThreadEx, HookCreateRemoteThreadEx);
            DetourDetach(&(PVOID&)RealOpenProcess, HookOpenProcess);
            DetourDetach(&(PVOID&)RealOpenThread, HookOpenThread);
            DetourDetach(&(PVOID&)RealResumeThread, HookResumeThread);
            DetourDetach(&(PVOID&)RealCreateProcessA, HookCreateProcessA);
            DetourDetach(&(PVOID&)RealCreateProcessW, HookCreateProcessW);
            DetourDetach(&(PVOID&)RealSetThreadContext, HookSetThreadContext);
            DetourDetach(&(PVOID&)RealZwUnmapViewOfSection, HookZwUnmapViewOfSection);
            DetourTransactionCommit();
            break;
        }
    }

    return TRUE;
}

