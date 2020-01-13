#pragma once


#include <Windows.h>

//Struktura obsahujuca zaznam o hook-ovani
struct hook_structure {	
	bool	isHooked;
	void*	FuncionAddress;
	void*	HookAddress;
	char	Jmp[6];
	char	OriginalBytes[6];
	void*	OriginalFuncion;

};

namespace hook {

	bool InitializeHook(hook_structure* Hook, char* Module, char* Funcion, void* HookFuncion) {

		HMODULE hModule;
		DWORD OrigFunc, FuncAddr;
		byte opcodes[] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0xe9, 0x00, 0x00, 0x00, 0x00 };
		
		if (Hook->isHooked) {
			return false;
		}
		hModule = GetModuleHandle(Module);
		if (hModule == INVALID_HANDLE_VALUE) {
			Hook->isHooked = false;
			return false;
		}
		Hook->Jmp[0] = 0xe9;
		*(PULONG)&Hook->Jmp[1] = (ULONG)HookFuncion - (ULONG)Hook->FuncionAddress - 5;
		memcpy(Hook->OriginalBytes, Hook->FuncionAddress, 5);
		Hook->OriginalFuncion = VirtualAlloc(0, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		
		if (Hook->OriginalFuncion == NULL) {
			return false;
		}
		memcpy(Hook->OriginalFuncion, Hook->OriginalBytes, 5);
		OrigFunc = (ULONG)Hook->OriginalFuncion + 5;
		FuncAddr = (ULONG)Hook->OriginalFuncion + 5;
		*(LPBYTE)((LPBYTE)Hook->OriginalFuncion + 5) = 0xe9;
		*(PULONG)((LPBYTE)Hook->OriginalFuncion + 6) = (ULONG)FuncAddr;
		Hook->isHooked = true;
		return true;
	}

	bool InsertHook(hook_structure* Hook) {
		DWORD operation;
		if (!Hook->isHooked) {
			return false;
		}

		VirtualProtect(Hook->FuncionAddress, 5, PAGE_EXECUTE_READWRITE, &operation);
		memcpy(Hook->FuncionAddress, Hook->Jmp, 5);
		VirtualProtect(Hook->FuncionAddress, 5, operation, &operation);
		return true;
	}

	bool UnHook(hook_structure* Hook) {
		DWORD operation;
		if (!Hook->isHooked) {
			return false;
		}

		VirtualProtect(Hook->FuncionAddress, 5, PAGE_EXECUTE_READWRITE, &operation);
		memcpy(Hook->FuncionAddress, Hook->OriginalBytes, 5);
		VirtualProtect(Hook->FuncionAddress, 5, operation, &operation);
		Hook->isHooked = false;
		return true;
	}
	
	bool FreeHook(hook_structure* Hook) {

		if (!Hook->isHooked) {
			return false;
		}
		VirtualFree(Hook->OriginalFuncion, 0, MEM_RELEASE);
		memset(Hook, 0, sizeof(hook_structure*));
		return true;
	}
}