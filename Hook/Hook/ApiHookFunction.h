#pragma once
#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>
#include <time.h>
#include <fstream>
#include <string>
#include <mutex>
#include <stdlib.h>

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
	myFile << ltm->tm_hour << ":" << ltm->tm_min << ":" << ltm->tm_sec << ";" + originalFuncion + ";" << endl;
	myFile.close();
	//cout << "Write to file" << endl;
	if (hMutex != NULL)
	{
		cout << "Mutex exist "<< endl;
	}
	cin.ignore();
	CloseHandle(hMutex);
	return 0;

}

static BOOL(*RealWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*) = WriteProcessMemory;
static BOOL(*RealReadProcessMemory)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*) = ReadProcessMemory;
static LPVOID(*RealVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD) = VirtualAllocEx;
static LPVOID(*RealVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD) = VirtualAlloc;
//static PVOID(*RealVirtualAlloc2)(HANDLE, PVOID, SIZE_T, ULONG, ULONG, MEM_EXTENDED_PARAMETER*, ULONG) = VirtualAlloc2;
static HANDLE(*RealCreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD) = CreateThread;
static HANDLE(*RealCreateRemoteThread)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD) = CreateRemoteThread;
static HANDLE(*RealCreateRemoteThreadEx)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, 
	DWORD, LPPROC_THREAD_ATTRIBUTE_LIST, LPDWORD) = CreateRemoteThreadEx;
static BOOL(*RealReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED) = ReadFile;
static BOOL(*RealWriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED) = WriteFile;
static HANDLE(*RealOpenProcess)(DWORD, BOOL, DWORD) = OpenProcess;
static HANDLE(*RealOpenThread)(DWORD, BOOL, DWORD) = OpenThread;
static DWORD(*RealResumeThread)(HANDLE) = ResumeThread;
static BOOL(*RealCreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
	BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION) = CreateProcessA;
static BOOL(*RealCreateProcessW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
	BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION) = CreateProcessW;
static VOID(*RealExitProcess)(UINT) = ExitProcess;
static VOID(*RealExitThread)(DWORD) = ExitThread;
static DWORD(*RealGetThreadId)(HANDLE) = GetThreadId;
static BOOL (*RealGetThreadContext)(HANDLE, LPCONTEXT) = GetThreadContext;

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

	//musi vravcat originalnu funkciu
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