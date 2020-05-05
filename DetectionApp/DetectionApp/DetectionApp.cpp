// DetectionApp.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <vector>

using namespace std;
#define _CRT_SECURE_NO_WARNINGS

static const string F01 = "CreateThread";
static const string F02 = "CreateRemoteThread";
static const string F03 = "CreateRemoteThreadEx";
static const string F04 = "CreateProcessA";
static const string F05 = "CreateProcessW";
static const string F06 = "SwitchToThread";
static const string F07 = "OpenThread";
static const string F08 = "SuspendThread";
static const string F09 = "VirtualAlloc";
static const string F10 = "VirtualAllocEx";
static const string F11 = "VirtualAlloc2";
static const string F12 = "CopyMemory";
static const string F13 = "WriteProcessMemory";
static const string F14 = "ResumeThread";
static const string F15 = "ExitThread";
static const string F16 = "GetThreadContext";

class Matrix {
private:
    ifstream myFile;
    string line;
    vector<string> vect;
public:    
    vector < vector<string> > vector2D;
    Matrix() {
        myFile.open("configuration.txt", ofstream::app);
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

            //index++;
            //cout << index << endl;
            if (flag == 0) {
                vector2D.push_back(vect);
                vect.clear();
                flag = 6;
            }
        }
        myFile.close();
    }
};

int main()
{
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

    ifstream hookFile;
    string line;
    string status = "stav_0";
    string helpField = "";
    int index = 0;
    hookFile.open("hookResult.txt", ofstream::app);
    while (!hookFile.eof())
    {
        hookFile >> line;
        stringstream ss(line);
            string winAPIFuncion;
            getline(ss, winAPIFuncion, ';');
            cout << winAPIFuncion << endl;

            for (int j = 1; j < matrix.vector2D.size(); j++) {
                if (winAPIFuncion._Equal(matrix.vector2D[j][0]))
                {
                    cout << "Equal" << endl;
                    index = j;
                }
            }

            for (int i = 1; i < matrix.vector2D[0].size(); i++) {
                if (status._Equal(matrix.vector2D[0][i]))
                {
                    helpField = matrix.vector2D[index][i];
                }
            }
            status = helpField;
            cout << status << endl;
            
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
