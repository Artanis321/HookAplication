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

void writeFunctionToFile(string originalFuncion) 
{
	DWORD ret = WaitForSingleObject(hMutex, INFINITE);

	if (ret == WAIT_OBJECT_0)
	{
		std::cout << originalFuncion << std::endl;
		time_t now = time(NULL);
		tm* ltm = localtime(&now);
		ofstream myFile;
		myFile.open("hookAplicationResult.txt", ofstream::app | ofstream::out);

		if (myFile.is_open())
		{
			myFile << ltm->tm_hour << ":" << ltm->tm_min << ":" << ltm->tm_sec << ";" + originalFuncion << endl;
			myFile.close();
		}

		ReleaseMutex(hMutex);
	}
}

typedef NTSTATUS(WINAPI* _ZwUnmapViewOfSection)(
	HANDLE ProcessHandle,
	PVOID BaseAddress
	);

FARPROC fpZwUnmapViewOfSection = GetProcAddress(GetModuleHandleA("ntdll"), "ZwUnmapViewOfSection");

_ZwUnmapViewOfSection ZwUnmapViewOfSection =
(_ZwUnmapViewOfSection)fpZwUnmapViewOfSection;

static BOOL(__stdcall *RealWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*) = WriteProcessMemory;
static BOOL(__stdcall *RealReadProcessMemory)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*) = ReadProcessMemory;
static LPVOID(__stdcall *RealVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD) = VirtualAllocEx;
static LPVOID(__stdcall*RealVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD) = VirtualAlloc;
static HANDLE(__stdcall *RealCreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD) = CreateThread;
static HANDLE(__stdcall*RealCreateRemoteThread)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD) = CreateRemoteThread;
static HANDLE(__stdcall *RealCreateRemoteThreadEx)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID,
	DWORD, LPPROC_THREAD_ATTRIBUTE_LIST, LPDWORD) = CreateRemoteThreadEx;
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
static BOOL(__stdcall *RealSetThreadContext)(HANDLE, const CONTEXT*) = SetThreadContext;
static NTSTATUS (__stdcall *RealZwUnmapViewOfSection)(	HANDLE, PVOID) = ZwUnmapViewOfSection;

NTSTATUS WINAPI HookZwUnmapViewOfSection(
	HANDLE ProcessHandle,
	PVOID  BaseAddress
) 
{
	writeFunctionToFile("ZwUnmapViewOfSection");
	return RealZwUnmapViewOfSection(ProcessHandle, BaseAddress);
}

BOOL WINAPI HookSetThreadContext(
	HANDLE        hThread,
	const CONTEXT* lpContext
)
{
	writeFunctionToFile("SetThreadContext");
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
	writeFunctionToFile("WriteProcessMemory");
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
	writeFunctionToFile("ReadProcessMemory");
	return RealReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead); //if the parameter does not contain this string, call the original API function
}

LPVOID WINAPI HookVirtualAllocEx(
	_In_ HANDLE hProcess,
	_In_ LPVOID lpAddress,
	_In_ SIZE_T dwSize,
	_In_ DWORD  flAllocationType,
	_In_ DWORD  flProtect
)
{
	writeFunctionToFile("VirtualAllocEx");
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
	writeFunctionToFile("CreateRemoteThread");
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
	writeFunctionToFile("CreateRemoteThreadEx");
	return RealCreateRemoteThreadEx(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpAttributeList, lpThreadId);
}

HANDLE WINAPI HookOpenProcess(
	DWORD dwDesiredAccess,
	BOOL  bInheritHandle,
	DWORD dwProcessId
)
{
	writeFunctionToFile("OpenProcess");
	return RealOpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
}

HANDLE WINAPI HookOpenThread(
	DWORD dwDesiredAccess,
	BOOL  bInheritHandle,
	DWORD dwThreadId
)
{
	writeFunctionToFile("OpenThread");
	return RealOpenThread(dwDesiredAccess, bInheritHandle, dwThreadId);
}

DWORD WINAPI HookResumeThread(
	HANDLE hThread
)
{
	writeFunctionToFile("ResumeThread");
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
	writeFunctionToFile("CreateProcessA");
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
	writeFunctionToFile("CreateProcessW");
	return RealCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles,
		dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}