#pragma once
#include <Windows.h>
#include <TlHelp32.h>

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

fakeWriteProcessMemory hookFakeWpm;
fakeReadProcessMemory hookFakeRpm;

unsigned long hookAttach(char* pName)
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