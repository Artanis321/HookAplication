#pragma once
#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>
using namespace std;
#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable : 4996)

int writeFile(string processID, string originalFuncion) {

	time_t now = time(NULL);
	tm* ltm = localtime(&now);
	ofstream myFile;
	myFile.open("hookAplicationResault.txt");
	myFile << 1 + ltm->tm_hour << ":" << 1 + ltm->tm_min << ":" << 1 + ltm->tm_sec << ";" + processID + ";" + originalFuncion + ";" << endl;
	myFile.close();
	return 0;

}

typedef BOOL(WINAPI* fakeWriteProcessMemory)(
	_In_  HANDLE  hProcess,
	_In_  LPVOID  lpBaseAddress,
	_In_  LPCVOID lpBuffer,
	_In_  SIZE_T  nSize,
	_Out_ SIZE_T* lpNumberOfBytesWritten
	);
typedef BOOL(WINAPI* fakeReadProcessMemory)(
	_In_  HANDLE  hProcess,
	_In_  LPCVOID lpBaseAddress,
	_Out_ LPVOID  lpBuffer,
	_In_  SIZE_T  nSize,
	_Out_ SIZE_T* lpNumberOfBytesRead
	);

typedef LPVOID (WINAPI* fakeVirtualAllocEx)(
	_In_ HANDLE hProcess,
	_In_ LPVOID lpAddress,
	_In_ SIZE_T dwSize,
	_In_ DWORD  flAllocationType,
	_In_ DWORD  flProtect
);

typedef LPVOID(WINAPI* fakeVirtualAlloc)(
	_In_ LPVOID lpAddress,
	_In_ SIZE_T dwSize,
	_In_ DWORD  flAllocationType,
	_In_ DWORD  flProtect
);

typedef PVOID(WINAPI* fakeVirtualAllocFromApp)(
	PVOID  BaseAddress,
	SIZE_T Size,
	ULONG  AllocationType,
	ULONG  Protection
);

typedef PVOID(WINAPI* fakeVirtualAlloc2)(
	HANDLE                 Process,
	PVOID                  BaseAddress,
	SIZE_T                 Size,
	ULONG                  AllocationType,
	ULONG                  PageProtection,
	MEM_EXTENDED_PARAMETER* ExtendedParameters,
	ULONG                  ParameterCount
);

typedef PVOID(WINAPI* fakeVirtualAlloc2FromApp)(
	HANDLE                 Process,
	PVOID                  BaseAddress,
	SIZE_T                 Size,
	ULONG                  AllocationType,
	ULONG                  PageProtection,
	MEM_EXTENDED_PARAMETER* ExtendedParameters,
	ULONG                  ParameterCount
);

typedef HANDLE(WINAPI* fakeOpenProcess)(
	DWORD dwDesiredAccess,
	BOOL  bInheritHandle,
	DWORD dwProcessId
);

typedef HANDLE (WINAPI* fakeOpenThread)(
	DWORD dwDesiredAccess,
	BOOL  bInheritHandle,
	DWORD dwThreadId
);

typedef HANDLE (WINAPI* fakeCreateThread)(
	LPSECURITY_ATTRIBUTES   lpThreadAttributes,
	SIZE_T                  dwStackSize,
	LPTHREAD_START_ROUTINE  lpStartAddress,
	__drv_aliasesMem LPVOID lpParameter,
	DWORD                   dwCreationFlags,
	LPDWORD                 lpThreadId
);

typedef HANDLE(WINAPI* fakeCreateRemoteThread)(
	HANDLE                 hProcess,
	LPSECURITY_ATTRIBUTES  lpThreadAttributes,
	SIZE_T                 dwStackSize,
	LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID                 lpParameter,
	DWORD                  dwCreationFlags,
	LPDWORD                lpThreadId
);

typedef void (WINAPI* fakeExitThread)(
	DWORD dwExitCode
);

typedef void (WINAPI* fakeExitProcess)(
	UINT uExitCode
);

typedef HANDLE (WINAPI* fakeOpenThread)(
	DWORD dwDesiredAccess,
	BOOL  bInheritHandle,
	DWORD dwThreadId
);

typedef DWORD (WINAPI* fakeResumeThread)(
	HANDLE hThread
);

typedef BOOL (WINAPI* fakeSetThreadPriority)(
	HANDLE hThread,
	int    nPriority
);

typedef BOOL (WINAPI* fakeSwitchToThread());

typedef BOOL (WINAPI* fakeTerminateProcess)(
	HANDLE hProcess,
	UINT   uExitCode
);

typedef BOOL (WINAPI* fakeTerminateThread)(
	HANDLE hThread,
	DWORD  dwExitCode
);

typedef BOOL (WINAPI* fakeCreateProcessA)(
	LPCSTR                lpApplicationName,
	LPSTR                 lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL                  bInheritHandles,
	DWORD                 dwCreationFlags,
	LPVOID                lpEnvironment,
	LPCSTR                lpCurrentDirectory,
	LPSTARTUPINFOA        lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
);

typedef BOOL (WINAPI* fakeCreateProcessW)(
	LPCWSTR               lpApplicationName,
	LPWSTR                lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL                  bInheritHandles,
	DWORD                 dwCreationFlags,
	LPVOID                lpEnvironment,
	LPCWSTR               lpCurrentDirectory,
	LPSTARTUPINFOW        lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
);

typedef HANDLE(WINAPI* fakeCreateRemoteThread)(
	HANDLE                 hProcess,
	LPSECURITY_ATTRIBUTES  lpThreadAttributes,
	SIZE_T                 dwStackSize,
	LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID                 lpParameter,
	DWORD                  dwCreationFlags,
	LPDWORD                lpThreadId
);

typedef HANDLE (WINAPI* fakeCreateRemoteThreadEx)(
	HANDLE                       hProcess,
	LPSECURITY_ATTRIBUTES        lpThreadAttributes,
	SIZE_T                       dwStackSize,
	LPTHREAD_START_ROUTINE       lpStartAddress,
	LPVOID                       lpParameter,
	DWORD                        dwCreationFlags,
	LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
	LPDWORD                      lpThreadId
);

typedef HANDLE (WINAPI* fakeCreateThread)(
	LPSECURITY_ATTRIBUTES   lpThreadAttributes,
	SIZE_T                  dwStackSize,
	LPTHREAD_START_ROUTINE  lpStartAddress,
	__drv_aliasesMem LPVOID lpParameter,
	DWORD                   dwCreationFlags,
	LPDWORD                 lpThreadId
);



fakeWriteProcessMemory			hookFakeWpm;
fakeReadProcessMemory			hookFakeRpm;
fakeVirtualAllocEx				hookFakeVAllEx;
fakeVirtualAlloc				hookFakeVAll;
fakeVirtualAllocFromApp			hookFakeVAllFrom;
fakeVirtualAlloc2FromApp		hookFakeVAll2From;
fakeVirtualAlloc2				hookFakeVAll2;
fakeOpenProcess					hookFakeOpenProc;
fakeOpenThread					hookFakeOpenThr;
fakeResumeThread				hookFakeResThr;
fakeCreateRemoteThread			hookFakeCrRemThr;
fakeCreateRemoteThreadEx		hookFakeCrRemThrEx;
fakeCreateThread				hookFakeCrThr;
fakeCreateProcessW				hookFakeCrProcW;
fakeCreateProcessA				hookFakeCrProcA;



unsigned long attach(char* pName)
{
	HANDLE handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(entry);
	do
		if (!strcmp(entry.szExeFile, pName)) {
			CloseHandle(handle);
			return entry.th32ProcessID;
		}
	while (Process32Next(handle, &entry));
	return false;
}

//this will replace the DeleteFileA function in our target process
BOOL WINAPI HookWriteProcessMemory(
	_In_  HANDLE  hProcess,
	_In_  LPVOID  lpBaseAddress,
	_In_  LPCVOID lpBuffer,
	_In_  SIZE_T  nSize,
	_Out_ SIZE_T  *lpNumberOfBytesWritten
	)
{
	//TO DO:  
	//pridat zapis do suboru 
	writeFile(GetProcessId(hProcess), "WriteProcessMemory");

	//musi vravcat originalnu funkciu
	return hookFakeWpm(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten); //if the parameter does not contain this string, call the original API function
}

BOOL WINAPI HookReadProcessMemory(
	_In_  HANDLE  hProcess,
	_In_  LPCVOID lpBaseAddress,
	_Out_ LPVOID  lpBuffer,
	_In_  SIZE_T  nSize,
	_Out_ SIZE_T  *lpNumberOfBytesRead
	)
{
	writeFile(GetProcessId(hProcess), "ReadProcessMemory");


	return hookFakeRpm(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead); //if the parameter does not contain this string, call the original API function
}
