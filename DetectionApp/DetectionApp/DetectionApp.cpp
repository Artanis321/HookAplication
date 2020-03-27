// DetectionApp.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <vector>

using namespace std;
#define _CRT_SECURE_NO_WARNINGS

class Matrix {
private:
    ifstream myFile;
    string line;
    vector<string> vect;
public:    
    vector < vector<string> > vector2D;
    Matrix() {
        myFile.open("hookAplicationResult.txt", ofstream::app);
        while (!myFile.eof())
        {
            myFile >> line;
            stringstream ss(line);

            while (ss.good()) {
                string substr;
                getline(ss, substr, ';');
                vect.push_back(substr);
            }
            vector2D.push_back(vect);
            vect.clear();
        }
        myFile.close();
    }
};

int main()
{
    size_t row_size;
    size_t col_size;
    /*
    ifstream myFile;
    string line;

    myFile.open("C:\\hookAplicationResult.txt", ofstream::app);
    vector < vector<string> > vector2D;
    vector<string> vect;
    while (!myFile.eof())
    {
        myFile >> line;
        stringstream ss(line);
        
        while (ss.good()) {
            string substr;
            getline(ss, substr, ';');
            vect.push_back(substr);
        }
        vector2D.push_back(vect);
        vect.clear();
    }
    */
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
    //myFile.close();
    
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
