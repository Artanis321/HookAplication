#pragma once
#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>
#include <time.h>
#include <fstream>
#include <string>
#include <mutex>
#include <stdlib.h>
#include <winternl.h>
#include <winnt.rh>

#pragma comment(lib,"ntdll.lib")

using namespace std;
#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable : 4996)

HANDLE hMutex = OpenMutex(MUTEX_ALL_ACCESS, NULL, TEXT("MutexOnThreadSafe"));

int writeFile(string originalFuncion) {
	
	DWORD ret = WaitForSingleObject(hMutex, INFINITE);
	time_t now = time(NULL);
	tm* ltm = localtime(&now);
	ofstream myFile;
	myFile.open("hookAplicationResult.txt", ofstream::app);
	myFile << ltm->tm_hour << ":" << ltm->tm_min << ":" << ltm->tm_sec << ";" + originalFuncion << endl;
	myFile.close();
	cin.ignore();
	CloseHandle(hMutex);
	return 0;

}

static BOOL(__stdcall *RealWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*) = WriteProcessMemory;
static BOOL(__stdcall *RealReadProcessMemory)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*) = ReadProcessMemory;
static LPVOID(__stdcall *RealVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD) = VirtualAllocEx;
static LPVOID(__stdcall*RealVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD) = VirtualAlloc;
//static PVOID(*RealVirtualAlloc2)(HANDLE, PVOID, SIZE_T, ULONG, ULONG, MEM_EXTENDED_PARAMETER*, ULONG) = VirtualAlloc2;
static HANDLE(__stdcall *RealCreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD) = CreateThread;
static HANDLE(__stdcall*RealCreateRemoteThread)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD) = CreateRemoteThread;
static HANDLE(__stdcall *RealCreateRemoteThreadEx)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID,
	DWORD, LPPROC_THREAD_ATTRIBUTE_LIST, LPDWORD) = CreateRemoteThreadEx;
static BOOL(__stdcall *RealReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED) = ReadFile;
static BOOL(__stdcall *RealWriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED) = WriteFile;
static HANDLE(__stdcall *RealOpenProcess)(DWORD, BOOL, DWORD) = OpenProcess;
static HANDLE(__stdcall *RealOpenThread)(DWORD, BOOL, DWORD) = OpenThread;
static DWORD(__stdcall *RealResumeThread)(HANDLE) = ResumeThread;
static BOOL(__stdcall *RealCreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
	BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION) = CreateProcessA;
static BOOL(__stdcall *RealCreateProcessW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
	BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION) = CreateProcessW;
static VOID(__stdcall *RealExitProcess)(UINT) = ExitProcess;
static VOID(__stdcall *RealExitThread)(DWORD) = ExitThread;
static DWORD(__stdcall *RealGetThreadId)(HANDLE) = GetThreadId;
static BOOL (__stdcall *RealGetThreadContext)(HANDLE, LPCONTEXT) = GetThreadContext;
static BOOL(__stdcall* RealSetThreadContext)(HANDLE, const CONTEXT*) = SetThreadContext;
//static HANDLE(*RealCreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) = CreateFileW;
/*
EXTERN_C NTSTATUS NTAPI NtReadVirtualMemory(HANDLE, PVOID, PVOID, ULONG, PULONG);
EXTERN_C NTSTATUS NTAPI NtWriteVirtualMemory(HANDLE, PVOID, PVOID, ULONG, PULONG);
EXTERN_C NTSTATUS NTAPI NtGetContextThread(HANDLE, PCONTEXT);
EXTERN_C NTSTATUS NTAPI NtSetContextThread(HANDLE, PCONTEXT);
EXTERN_C NTSTATUS NTAPI NtUnmapViewOfSection(HANDLE, PVOID);
EXTERN_C NTSTATUS NTAPI NtResumeThread(HANDLE, PULONG);
*/
/*
typedef NTSYSAPI NTSTATUS(NTAPI* tNtReadVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesReaded);
tNtReadVirtualMemory NtReadVirtualMemory;
typedef NTSYSAPI NTSTATUS(NTAPI* tNtWriteVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWrote);
tNtWriteVirtualMemory NtWriteVirtualMemory;
typedef NTSYSAPI NTSTATUS(NTAPI* tNtSetContextThread)(HANDLE ProcessHandle, PCONTEXT context);
tNtSetContextThread NtSetContextThread;
typedef NTSYSAPI NTSTATUS(NTAPI* tNtGetContextThread)(HANDLE ProcessHandle, PCONTEXT context);
tNtGetContextThread NtGetContextThread;
typedef NTSYSAPI NTSTATUS(NTAPI* tNtResumeThread)(HANDLE ProcessHandle, PULONG context);
tNtResumeThread NtResumeThread;

//NtReadVirtualMemory = (tNtReadVirtualMemory)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtReadVirtualMemory");

static NTSTATUS(*RealNtReadVirtualMemory)(HANDLE, PVOID, PVOID, ULONG, PULONG) = (tNtReadVirtualMemory)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtReadVirtualMemory");
static NTSTATUS(*RealNtWriteVirtualMemory)(HANDLE, PVOID, PVOID, ULONG, PULONG) = (tNtWriteVirtualMemory)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtWriteVirtualMemory");
static NTSTATUS(*RealNtGetContextThread)(HANDLE, PCONTEXT) = (tNtGetContextThread)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtGetContextThread");
static NTSTATUS(*RealNtSetContextThread)(HANDLE, PCONTEXT) = (tNtSetContextThread)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtSetContextThread");
static NTSTATUS(*RealNtResumeThread)(HANDLE, PULONG) = (tNtResumeThread)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtResumeThread");
*/
/*
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
fakeReadFile					hookFakeReadFile;
fakeWriteFile					hookFakeWriteFile;
*/
/*
HANDLE WINAPI HookCreateFileW(
	LPCWSTR               lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
	)
{
	writeFile("CreateFileW");
	return RealCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}
*/
/*
NTSTATUS WINAPI HookNtReadVirtualMemory(
	HANDLE	hProcess,
	PVOID	pBaseAddress,
	PVOID	buffer,
	ULONG	numberOfBytestoRead,
	PULONG	numberOfBytesReaded OPTIONAL
	)
{
	writeFile("NtReadVirtualMemory");
	return RealNtReadVirtualMemory(hProcess, pBaseAddress, buffer, numberOfBytestoRead, numberOfBytesReaded);
}

NTSTATUS WINAPI HookNtWriteVirtualMemory(
	HANDLE	hProcess,
	PVOID	pBaseAddress,
	PVOID	buffer,
	ULONG	numberOfBytestoWrite,
	PULONG	numberOfBytesWritend OPTIONAL
	)
{
	writeFile("NtWriteVirtualMemory");
	return RealNtWriteVirtualMemory(hProcess, pBaseAddress, buffer, numberOfBytestoWrite, numberOfBytesWritend);
}

NTSTATUS WINAPI HookNtSetContextThread(
	HANDLE hThread,
	PCONTEXT context
	) 
{
	writeFile("SetContextThread");
	return RealNtSetContextThread(hThread, context);
}

NTSTATUS WINAPI HookNtGetContextThread(
	HANDLE hThread,
	PCONTEXT context
	)
{
	writeFile("GetContextThread");
	return RealNtGetContextThread(hThread, context);
}

NTSTATUS WINAPI HookNtResumeThread(
	HANDLE hThread,
	PULONG suspendCount OPTIONAL
	) 
{
	writeFile("NtResumeThread");
	return RealNtResumeThread(hThread, suspendCount);
}
*/

BOOL WINAPI HookSetThreadContext(
	HANDLE        hThread,
	const CONTEXT* lpContext
)
{
	writeFile("SetThreadContext");
	return RealSetThreadContext(hThread, lpContext);
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
	writeFile("WriteProcessMemory");
	return RealWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten); //if the parameter does not contain this string, call the original API function
}

BOOL WINAPI HookReadProcessMemory(
	_In_  HANDLE  hProcess,
	_In_  LPCVOID lpBaseAddress,
	_Out_ LPVOID  lpBuffer,
	_In_  SIZE_T  nSize,
	_Out_ SIZE_T  *lpNumberOfBytesRead
	)
{
	writeFile("ReadProcessMemory");
	return RealReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead); //if the parameter does not contain this string, call the original API function
}

BOOL WINAPI HookReadFile(
	HANDLE       hFile,
	LPVOID       lpBuffer,
	DWORD        nNumberOfBytesToRead,
	LPDWORD      lpNumberOfBytesRead,
	LPOVERLAPPED lpOverlapped
	) 
{
	writeFile("ReadFile");
	return RealReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
}

BOOL WINAPI HookWriteFile(
	HANDLE       hFile,
	LPCVOID      lpBuffer,
	DWORD        nNumberOfBytesToWrite,
	LPDWORD      lpNumberOfBytesWritten,
	LPOVERLAPPED lpOverlapped
)
{
	writeFile("WriteFile");
	return RealWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}

LPVOID WINAPI HookVirtualAllocEx(
	_In_ HANDLE hProcess,
	_In_ LPVOID lpAddress,
	_In_ SIZE_T dwSize,
	_In_ DWORD  flAllocationType,
	_In_ DWORD  flProtect
)
{
	writeFile("VirtualAllocEx");
	return RealVirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
}

LPVOID WINAPI HookVirtualAlloc(
	_In_ LPVOID lpAddress,
	_In_ SIZE_T dwSize,
	_In_ DWORD  flAllocationType,
	_In_ DWORD  flProtect
)
{
	return RealVirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
}
HANDLE WINAPI HookCreateRemoteThread(
	HANDLE                 hProcess,
	LPSECURITY_ATTRIBUTES  lpThreadAttributes,
	SIZE_T                 dwStackSize,
	LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID                 lpParameter,
	DWORD                  dwCreationFlags,
	LPDWORD                lpThreadId
)
{
	writeFile("CreateRemoteThread");
	return RealCreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
}

HANDLE WINAPI HookCreateRemoteThreadEx(
	HANDLE                       hProcess,
	LPSECURITY_ATTRIBUTES        lpThreadAttributes,
	SIZE_T                       dwStackSize,
	LPTHREAD_START_ROUTINE       lpStartAddress,
	LPVOID                       lpParameter,
	DWORD                        dwCreationFlags,
	LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
	LPDWORD                      lpThreadId
)
{
	writeFile("CreateRemoteThreadEx");
	return RealCreateRemoteThreadEx(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpAttributeList, lpThreadId);
}

HANDLE WINAPI HookOpenProcess(
	DWORD dwDesiredAccess,
	BOOL  bInheritHandle,
	DWORD dwProcessId
)
{
	writeFile("OpenProcess");
	return RealOpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
}
/*
PVOID WINAPI HookVirtualAlloc2(
	HANDLE                 Process,
	PVOID                  BaseAddress,
	SIZE_T                 Size,
	ULONG                  AllocationType,
	ULONG                  PageProtection,
	MEM_EXTENDED_PARAMETER* ExtendedParameters,
	ULONG                  ParameterCount
)
{
	writeFile("VirtualAlloc2");
	return RealVirtualAlloc2(Process, BaseAddress, Size, AllocationType, PageProtection, ExtendedParameters, ParameterCount);
}
*/
HANDLE WINAPI HookOpenThread(
	DWORD dwDesiredAccess,
	BOOL  bInheritHandle,
	DWORD dwThreadId
)
{
	writeFile("OpenThread");
	return RealOpenThread(dwDesiredAccess, bInheritHandle, dwThreadId);
}

DWORD WINAPI HookResumeThread(
	HANDLE hThread
)
{
	writeFile("ResumeThread");
	return RealResumeThread(hThread);
}

BOOL WINAPI HookCreateProcessA(
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
)
{
	writeFile("CreateProcessA");
	return  RealCreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles,
		dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}

BOOL WINAPI HookCreateProcessW(
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
)
{
	writeFile("CreateProcessW");
	return RealCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles,
		dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}