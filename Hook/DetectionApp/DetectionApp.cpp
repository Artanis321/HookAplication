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

static const string STATUS_S0 = "stav_0";
static const string STATUS_S1 = "stav_1";

HANDLE mutexOnThreadSafe;

class Matrix {
private:
    ifstream myFile;
    string line;
    vector<string> vect;
public:
    vector < vector<string> > vector2D;
    Matrix() {
       myFile.open("D:\\App Windows\\Visual Studio 2019\\Projekty\\HookDetours\\Hook\\x64\\Debug\\configuration.txt", ofstream::app);
        vect.push_back("Function");
        vect.push_back("stav_0");
        vect.push_back("stav_1");
        vect.push_back("stav_2");
        vect.push_back("stav_3");
        vect.push_back("stav_4");
        vect.push_back("stav_5");
        vector2D.push_back(vect);
        vect.clear();
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

    for (int row = 1; row < matrix.vector2D.size(); row++) {
        if (winAPIFuncion._Equal(matrix.vector2D[row][0]))
        {
            row_index = row;
            //cout << matrix.vector2D[row][0] << endl;
            exist = true;
        }
    }
    if (exist) {
        exist = false;
        cout << "WinAPI: " << winAPIFuncion << " New Instance:" << endl;

        for (int k = 0; k < arraylist.size(); k++) {
            auto iter = next(arraylist.begin(), k);
            status = *iter;
            for (int col = 1; col < matrix.vector2D[0].size(); col++) {
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
    hookFile.open("hookResult.txt", ofstream::out | ofstream::trunc);
    hookFile.clear();
    hookFile.close();
}

list<string> findInApi(list<string> arraylist) {
    ifstream hookFile;
    ofstream archive;
    string line;
    archive.open("archive.txt", ofstream::app);
    hookFile.open("hookResult.txt", ofstream::app);
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

int main()
{
	mutexOnThreadSafe = CreateMutex(NULL, FALSE, TEXT("MutexOnThreadSafe"));

    if (mutexOnThreadSafe != NULL)
    {
        cout << "Mutex created" << std::endl;
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
            cout << matrix.vector2D[i][j] << ' ';
        }
        cout << endl;
    }

    list<string> arraylist;
    string status = "stav_0";
    arraylist.push_back(status);

    thread th([&matrix, &arraylist]() {
		while (true) {
			this_thread::sleep_for(500ms); 

			auto result = WaitForSingleObject(mutexOnThreadSafe, INFINITE);

			if (result == WAIT_OBJECT_0)
			{
				arraylist = findInApi(arraylist);

				for (int k = 0; k < arraylist.size(); k++) {
					auto iter = next(arraylist.begin(), k);
					cout << *iter << endl;
				}

				ReleaseMutex(mutexOnThreadSafe);
			}
		}
    });

    th.join();
}