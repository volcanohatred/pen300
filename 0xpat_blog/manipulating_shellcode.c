// reversing_hexcode.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>

using namespace std;

void swap(unsigned char a[], int i, int j) {
    
    char temp = a[i];
    a[i] = a[j];
    a[j] = temp;
}

int main()
{
    cout << "Hello World! lets reverse a hex\n";
    //unsigned char hex_code[] = "\xcf\x8e\x28\x00"; 
    unsigned char hex_code[] = "\xfc\xe8\x82\x00"; 
    unsigned char hex_code1[100] ;

    int counter = 0;

    for (int i = 0; i < sizeof hex_code; ++i) {
        cout << (char) hex_code[i] << "\n";
        if (i % 3> 0) {
            cout << " selected " << hex_code[i] << "\n";
            //swap(hex_code, i, i + 1);
            hex_code1[counter] = hex_code[i] + hex_code[i + 1];
            counter += 1;
            i = i + 1;
        }
    }
    

    cout << "after swap\n";
    
    for (int i = 0; i < counter; ++i) {
        cout << hex_code1[i];
    }

    return 0;
}