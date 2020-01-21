#include <iostream>
#include <Windows.h>
#include "apiHook.h"
#include "ApiHookFunction.h"

using namespace hook;
hook_structure Hook;


BOOL WINAPI DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
	if (dwReason == DLL_PROCESS_ATTACH)
	{
		GetCurrentProcessId();
		InitializeHook(&Hook, "kernel32.dll", "ReadProcessMemory", HookWriteProcessMemory);
		InitializeHook(&Hook, "kernel32.dll", "WriteProcessMemory", HookWriteProcessMemory);

		hookFakeRpm = (fakeReadProcessMemory)Hook.OriginalFuncion;
		hookFakeWpm = (fakeWriteProcessMemory)Hook.OriginalFuncion;
		InsertHook(&Hook);
	}
	else if (dwReason == DLL_PROCESS_DETACH)
	{
		UnHook(&Hook);
		FreeHook(&Hook);
	}
	return TRUE;
}