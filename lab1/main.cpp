#include <algorithm>
#include <fstream>
#include <iostream>
#include <string>
#include <io.h>
#include "blom.h"

using namespace std;

int main(int argc, char *argv[])
{
    Blom *trust=new Blom;
    unsigned int open_key_f[8]; //наш открытый ключ
    unsigned int close_key_f[8]; //наш закрытый ключ
    unsigned int open_key_b[8]; // открытый ключ партнера
    int k; // переменная для чтения чисел
    int count=0; // счетчик для данных

    cout<<"You are welcomed to the RC4 data exchange with the blom scheme.\n "
          "Module = 4294967295, 8x8 matrix.\n"
          "Enter your public key (Vector consisting of 8 numbers module 4294967295)"<<endl;


   while(count<8 || cin.fail())
    {
        cin>>k;
        if(k<=0)
        {
            cout<<"You number wrong,please enter another number: ";
            k=0;
            continue;
        }
        open_key_f[count]=k;
        count++;
    }
    cout<<"You open key is:(";
    for (int i=0;i<8;i++)
    {
        cout<<"\n"<<open_key_f[i];
    }
    cout<<")"<<endl;

    trust->create_close_key(open_key_f,close_key_f);
    cout<<"You close key is:(";
    for (int i=0;i<8;i++)
    {
        cout<<"\n"<<close_key_f[i];
    }
    cout<<")"<<endl;

   count=0;
   k=0;
   cout<<"Enter public key your partner (Vector consisting of 8 numbers module 4294967295)"<<endl;
   while(count<8|| cin.fail())
    {
        cin>>k;
        if(k<=0)
        {
            cout<<"You number wrong,please enter another number: ";
            k=0;
            continue;
        }
        open_key_b[count]=k;
        count++;
    }
    cout<<"partner open key is:(";
    for (int i=0;i<8;i++)
    {
        cout<<"\n"<<open_key_b[i];
    }
    cout<<")"<<endl;

    unsigned int keys=trust->create_session_key(open_key_b,close_key_f);
    cout<<"Your session key: "<<keys<<endl;
    string key=std::to_string(keys);
    string filename;
    cout << "Enter the filename: ";
    cin >> filename;

    if (access(filename.c_str(),0))
    {
        cout << "Filename is wrong";
        return -1;
    }
    bool choise;
    cout << "Encryption - 0, decryption - 1: ";
    cin >> choise;
    //инцилизация s Блока
    unsigned char S[256];
    int i = 0;
    for (i = 0; i < 256; i++)
        S[i] = i;
    int j = 0;
    for (i = 0; i < 256; i++)
    {
        j = (j + S[i] + key.at(i % key.length())) % 256;
        swap(S[i], S[j]);
    }

    string outfile;
    ifstream read(filename, ios::binary);
    if (!choise)
        outfile = filename + ".rc4";
    else
        outfile = "d_" + filename.substr(0, filename.length()-4);
    ofstream write(outfile,ios::binary );
    //генерация пвседослучайного слова
    char x;
    j = 0;
    i = 0;
    while (read.read(&x, 1))
    {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        swap(S[i], S[j]);
        char temp = S[(S[i] + S[j]) % 256] ^ x;
        write.write(&temp, 1);
    }
    return 0;
}
