// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <detours.h>
#include <iostream>
#include "ApiHookFunction.h"
/*
int writeFileA(string originalFuncion) {
    HANDLE hMutex;
    hMutex = OpenMutex(MUTEX_ALL_ACCESS, NULL, TEXT("MutexOnThreadSafe"));
    time_t now = time(NULL);
    tm* ltm = localtime(&now);
    ofstream myFile;
    myFile.open("hookAplicationResult.txt", ofstream::app);
    myFile << 1 + ltm->tm_hour << ":" << 1 + ltm->tm_min << ":" << 1 + ltm->tm_sec << ";" + originalFuncion + ";" << endl;
    myFile.close();
    cout << "Write to file" << endl;
    CloseHandle(hMutex);
    return 0;

}

static BOOL(*RealReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED) = ReadFile;


BOOL HookedReadFile(
    HANDLE       hFile,
    LPVOID       lpBuffer,
    DWORD        nNumberOfBytesToRead,
    LPDWORD      lpNumberOfBytesRead,
    LPOVERLAPPED lpOverlapped
)
{
    std::cout << "ReadFile" << std::endl;
    writeFileA("ReadFile");

    return ReadFile(hFile,
        lpBuffer,
        nNumberOfBytesToRead,
        lpNumberOfBytesRead,
        lpOverlapped);
}
*/
BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    
    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH:
        {
            DetourTransactionBegin();
            DetourUpdateThread(GetCurrentThread());
            DetourAttach(&(PVOID&)RealReadFile, HookReadFile);
            //DetourAttach(&(PVOID&)RealWriteFile, HookWriteFile);
            DetourTransactionCommit();
            /*
            DetourAttach(&(PVOID&)RealWriteProcessMemory, HookWriteProcessMemory);
            DetourAttach(&(PVOID&)RealReadProcessMemory, HookReadProcessMemory);
            DetourAttach(&(PVOID&)RealVirtualAllocEx, HookVirtualAllocEx);
            DetourAttach(&(PVOID&)RealVirtualAlloc, HookVirtualAlloc);
            DetourAttach(&(PVOID&)RealCreateRemoteThread, HookCreateRemoteThread);
            DetourAttach(&(PVOID&)RealCreateRemoteThreadEx, HookCreateRemoteThreadEx);
            DetourAttach(&(PVOID&)RealWriteFile, HookWriteFile);
            DetourAttach(&(PVOID&)RealOpenProcess, HookOpenProcess);
            DetourAttach(&(PVOID&)RealOpenThread, HookOpenThread);
            DetourAttach(&(PVOID&)RealResumeThread, HookResumeThread);
            DetourTransactionCommit();
            */
            break;
        }
        case DLL_PROCESS_DETACH:
        {
            DetourTransactionBegin();
            DetourUpdateThread(GetCurrentThread());
            DetourDetach(&(PVOID&)RealReadFile, HookReadFile);
            //DetourDetach(&(PVOID&)RealWriteFile, HookWriteFile);
            /*
            DetourDetach(&(PVOID&)RealWriteProcessMemory, HookWriteProcessMemory);
            DetourDetach(&(PVOID&)RealReadProcessMemory, HookReadProcessMemory);
            DetourDetach(&(PVOID&)RealVirtualAllocEx, HookVirtualAllocEx);
            DetourDetach(&(PVOID&)RealVirtualAlloc, HookVirtualAlloc);
            DetourDetach(&(PVOID&)RealCreateRemoteThread, HookCreateRemoteThread);
            DetourDetach(&(PVOID&)RealCreateRemoteThreadEx, HookCreateRemoteThreadEx);
            DetourDetach(&(PVOID&)RealWriteFile, HookWriteFile);
            DetourDetach(&(PVOID&)RealOpenProcess, HookOpenProcess);
            DetourDetach(&(PVOID&)RealOpenThread, HookOpenThread);
            DetourDetach(&(PVOID&)RealResumeThread, HookResumeThread);
            */
            DetourTransactionCommit();
            break;
        }
    }

    return TRUE;
}

