#include <Windows.h>

int main(int argc, char* argv[])
{
	HANDLE hFile;
	char writeBuffer[] = "test data";
	char readBuffer[10];
	DWORD bytesWritten = 0;
	DWORD bytesRead = 0;

	hFile = CreateFile(TEXT("test.txt"), GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	WriteFile(hFile, writeBuffer, strlen(writeBuffer), &bytesWritten, NULL);
	CloseHandle(hFile);

	hFile = CreateFile(TEXT("test.txt"), GENERIC_READ, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	ReadFile(hFile, readBuffer, 9, &bytesRead, NULL);
	CloseHandle(hFile);

	return 0;
}