#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <vector>
#include <list>
#include <iterator>
#include <mutex>
#include <Windows.h>
#include <time.h>

using namespace std;
#define _CRT_SECURE_NO_WARNINGS

static const string STATUS_S0 = "start";
static const string STATUS_S1 = "vytvorenie_Threadu";
static const string STATUS_S5 = "spustenie_Threadu";
static string CONFIG_FILE = "";
static string APP_PATH = "";
static const char* DLL_PATH = "";

HANDLE mutexOnThreadSafe;

void setConfig() {
    ifstream configFile;
    string line;
    int flag = 0;
    configFile.open("D:\\App Windows\\Visual Studio 2019\\Projekty\\HookDetours\\Hook\\config\\configFile.txt");
    if (configFile.is_open())
    {
        while (!configFile.eof())
        {
            configFile >> line;
            if (flag == 0)
            {
                CONFIG_FILE = line;
            }
            if (flag == 1)
            {
                APP_PATH = line;
            }
            flag++;
        }
    }
}

class Matrix {
private:
    ifstream myFile;
    string line;
    vector<string> vect;
public:
    vector < vector<string> > vector2D;
    Matrix() {
        myFile.open("configuration.txt", ofstream::app);
        int flag = 6;
        while (!myFile.eof())
        {
            myFile >> line;
            stringstream ss(line);
            int index = 0;
            while (ss.good()) {
                string substr;
                getline(ss, substr, ';');
                if (index == 1 && flag == 6) {
                    vect.push_back(substr);
                }
                if (index == 2) {

                    vect.push_back(substr);
                }
                index++;
            }
            flag--;
            if (flag == 0) {
                vector2D.push_back(vect);
                vect.clear();
                flag = 6;
            }
        }
        myFile.close();
    }
};

list<string> processHollowingEvaluation(list<string> arraylist, string winAPIFuncion) {
    Matrix matrix;
    string status;
    string helpField = "";
    int row_index = 0;
    bool flag = false;
    bool exist = false;

    for (size_t row = 1; row < matrix.vector2D.size(); row++) {
        if (winAPIFuncion._Equal(matrix.vector2D[row][0]))
        {
            row_index = row;
            exist = true;
        }
    }
    if (exist) {
        exist = false;
        for (size_t k = 0; k < arraylist.size(); k++) {
            auto iter = next(arraylist.begin(), k);
            status = *iter;
            for (size_t col = 1; col < matrix.vector2D[0].size(); col++) {
                if (status._Equal(matrix.vector2D[0][col]))
                {
                    helpField = matrix.vector2D[row_index][col];
                    break;
                }
            }
            if (STATUS_S1._Equal(helpField) && !STATUS_S0._Equal(status) && !STATUS_S1._Equal(status))
            {
                flag = true;
            }
            else {

                *iter = helpField;
                helpField = "";
            }
            //cout << *iter << endl;
        }
        if (flag) {
            arraylist.push_back(STATUS_S1);
            flag = false;
        }
    }
    return arraylist;
}

void clearFile() {
    ifstream hookFile;
    hookFile.open("hookAplicationResult.txt", ofstream::out | ofstream::trunc);
    hookFile.clear();
    hookFile.close();
}

list<string> findInApi(list<string> arraylist) {
    ifstream hookFile;
    ofstream archive;
    string line;
    archive.open("archive.txt", ofstream::app);
    hookFile.open("hookAplicationResult.txt", ofstream::app);
    while (!hookFile.eof())
    {
        hookFile >> line;
        stringstream ss(line);
        if (line != "") {
            archive << line << endl;
        }
        string winAPIFuncion;
        int index = 0;
        while (ss.good()) {

            getline(ss, winAPIFuncion, ';');
            if (index != 0) {
                arraylist = processHollowingEvaluation(arraylist, winAPIFuncion);
            }
            index++;
        }
    }
    hookFile.close();
    clearFile();
    archive.close();
    return arraylist;
}

bool injectDll() {
    LPSTARTUPINFO startupInfo = new STARTUPINFO();
    LPPROCESS_INFORMATION processInfo = new PROCESS_INFORMATION();
    const char* dll_path = "Hook.dll";
    DWORD thread_id = 0;
    char buffer_read[60];
    DWORD bytes_read = 0;

    if (!CreateProcess(TEXT("C:\\e75cc2ab8e398f05752faa6fa4b5c91e2f4a680a33d4d6aa41754a374313a8d4.exe"),
        NULL, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, startupInfo, processInfo))
    {
        std::cout << "Nepodarilo sa spustit Aplikaciu .exe" << std::endl;
        return false;
    }

    HMODULE kernel = LoadLibrary(TEXT("KERNEL32.DLL"));

    if (kernel == NULL)
    {
        std::cout << "LoadLibrary fail" << std::endl;
        return false;
    }

    void* path = VirtualAllocEx(processInfo->hProcess, NULL, sizeof(dll_path), MEM_COMMIT, PAGE_READWRITE);

    if (path == NULL)
    {
        std::cout << "VirtualAllocEx fail" << std::endl;
        return false;
    }

    SIZE_T written = 0;
    if (!WriteProcessMemory(processInfo->hProcess, path, dll_path, strlen(dll_path), &written))
    {
        std::cout << "WriteProcessMemory failed" << std::endl;
        return false;
    }

    std::cout << "Written " << written << std::endl;

    HANDLE remote = CreateRemoteThread(processInfo->hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(kernel, "LoadLibraryA"), path, 0, &thread_id);

    if (remote == NULL)
    {
        std::cout << "CreateRemoteThread fail" << std::endl;
        return false;
    }

    DWORD ret = WaitForSingleObject(remote, INFINITE);
    std::cout << "Return WaitForSingleObject " << ret << std::endl;
    ret = ResumeThread(processInfo->hThread);
    OFSTRUCT buffer;

    std::cout << "Return ResumeThread " << ret << std::endl;
    CloseHandle(remote);
    return true;
}

int main()
{
    mutexOnThreadSafe = CreateMutex(NULL, FALSE, TEXT("MutexOnThreadSafe"));

    if (mutexOnThreadSafe != NULL)
    {
        std::cout << "Mutex created" << std::endl;
    }

    //setConfig();
    if (!injectDll())
    {
        std::cout << "Nepodarilo sa injectovat DLL" << std::endl;
        return 0;
    }

    size_t row_size;
    size_t col_size;
    
    Matrix matrix;
    row_size = matrix.vector2D.size();
    col_size = matrix.vector2D[0].size();
    for (size_t i = 0; i < row_size; i++)
    {
        for (size_t j = 0; j < col_size; j++)
        {
            std::cout << matrix.vector2D[i][j] << ' ';
        }
        std::cout << std::endl;
    }

    list<string> arraylist;
    arraylist.push_back(STATUS_S0);
    
    thread th([&matrix, &arraylist]() {
        while (true) {
            this_thread::sleep_for(500ms);

            auto result = WaitForSingleObject(mutexOnThreadSafe, INFINITE);

            if (result == WAIT_OBJECT_0)
            {
                arraylist = findInApi(arraylist);

                for (size_t k = 0; k < arraylist.size(); k++) {
                    auto iter = next(arraylist.begin(), k);
                    std::cout << *iter << std::endl;
                    if (STATUS_S5._Equal(*iter)) {
                        std::cout << "Process Hollowing exist" << std::endl;
                        return 0;
                    }
                }

                ReleaseMutex(mutexOnThreadSafe);
            }
        }
        });

    th.join();
}