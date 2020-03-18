#include <Windows.h>
#include <iostream>

int main(int argc, char* argv[])
{
	LPSTARTUPINFO startupInfo = new STARTUPINFO();
	LPPROCESS_INFORMATION processInfo = new PROCESS_INFORMATION();
	const char* dll_path = "Hook.dll";
	DWORD thread_id = 0;

	if (!CreateProcess(TEXT("RFApp.exe"), NULL, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, startupInfo, processInfo))
	{
		std::cout << "Nepodarilo sa spustit RFApp.exe" << std::endl;
		return -1;
	}

	HMODULE kernel = LoadLibrary(TEXT("KERNEL32.DLL"));

	if (kernel == NULL)
	{
		std::cout << "LoadLibrary fail" << std::endl;
		return -1;
	}

	void* path = VirtualAllocEx(processInfo->hProcess, NULL, sizeof(dll_path), MEM_COMMIT, PAGE_READWRITE);

	if (path == NULL)
	{
		std::cout << "VirtualAllocEx fail" << std::endl;
		return -1;
	}

	SIZE_T written = 0;
	if (!WriteProcessMemory(processInfo->hProcess, path, dll_path, strlen(dll_path), &written))
	{
		std::cout << "WriteProcessMemory failed" << std::endl;
		return -1;
	}

	std::cout << "Written " << written << std::endl;

	HANDLE remote = CreateRemoteThread(processInfo->hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(kernel, "LoadLibraryA"), path, 0, &thread_id);

	if (remote == NULL)
	{
		std::cout << "CreateRemoteThread fail" << std::endl;
		return -1;
	}

	DWORD ret = WaitForSingleObject(remote, INFINITE);
	std::cout << "Return WaitForSingleObject " << ret << std::endl;
	ret = ResumeThread(processInfo->hThread);
	std::cout << "Return ResumeThread " << ret << std::endl;
	CloseHandle(remote);

	return 0;
}