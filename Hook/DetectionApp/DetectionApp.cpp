// DetectionApp.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <vector>
#include <list>
#include <iterator>
#include <mutex>
#include <Windows.h>

using namespace std;
#define _CRT_SECURE_NO_WARNINGS

static const string STATUS_S0 = "stav_0";
static const string STATUS_S1 = "stav_1";

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

list<string> findInApi(list<string> arraylist) {
    Matrix matrix;
    ifstream hookFile;
    string line;
    string status;
    string helpField = "";
    int row_index = 0;
    bool flag = false;
    bool exist = false;
    hookFile.open("hookResult.txt", ofstream::app);
    while (!hookFile.eof())
    {
        hookFile >> line;
        stringstream ss(line);
        string winAPIFuncion;
        int index = 0;
        while (ss.good()) {

            getline(ss, winAPIFuncion, ';');
            if (index != 0) {
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
                        cout << *iter << endl;
                    }
                    if (flag) {
                        arraylist.push_back(STATUS_S1);
                        flag = false;
                    }
                }
            }
            index++;
        }
    }
    hookFile.close();
    return arraylist;
}

int main()
{

    HANDLE mutexOnThreadSafe;
    mutexOnThreadSafe = CreateMutex(
        NULL,
        FALSE,
        TEXT("MutexOnThreadSafe"));
    if (mutexOnThreadSafe != NULL)
    {
        std::cout << "Mutex created" << std::endl;
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
    ifstream hookFile;
    string line;
    string status = "stav_0";
    string helpField = "";
    int row_index = 0;
    bool flag = false;
    bool exist = false;
    arraylist.push_back(status);

    arraylist = findInApi(arraylist);

    for (int k = 0; k < arraylist.size(); k++) {
        auto iter = next(arraylist.begin(), k);
        cout << *iter << endl;
    }
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
