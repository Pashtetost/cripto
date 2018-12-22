#include <algorithm>
#include <fstream>
#include <iostream>
#include <string>
#include <io.h>
#include <vector>
#include <QByteArray>
#include "eccrypt.h"
#include "kuznyechik.h"

using namespace std;

int main(int argc, char *argv[])
{
    start:
    bool pos=true;//позиция в обмене
    bool choise;
    eccrypt_curve_t ec; // параметры кривой
    eccrypt_point_t Pt; // точка эллиптической кривой
    eccrypt_point_t open_key; //наш открытый ключ
    eccrypt_point_t P_open_key; //открытый ключ собеседника
    eccrypt_point_t sess_key;
    string P,a,b,Px,Py,P_op_key_x,P_op_key_y;
    string filename; // имя файла с данными
    vector <string> text;
    string date;
    int close_k; //наш закрытый ключ

    cout<<"You are welcome to encrypt a grasshopper with key exchange along elliptic curves."<<endl;
    cout<<"First, enter the parameters of the elliptic curve (P,A,B): ";
    cin>>P>>a>>b;
    bignum_fromhex(ec.m,P.c_str(), ECCRYPT_BIGNUM_DIGITS);
    bignum_tohex(ec.m,(char*) P.c_str(), BIGNUM_DIGITS(*ec.m), ECCRYPT_BIGNUM_DIGITS);
    bignum_fromhex(ec.a,a.c_str(), ECCRYPT_BIGNUM_DIGITS);
    bignum_tohex(ec.a,(char*) a.c_str(), BIGNUM_DIGITS(*ec.a), ECCRYPT_BIGNUM_DIGITS);
    bignum_fromhex(ec.b,b.c_str(), ECCRYPT_BIGNUM_DIGITS);
    bignum_tohex(ec.b,(char*) b.c_str(), BIGNUM_DIGITS(*ec.b), ECCRYPT_BIGNUM_DIGITS);
    if(eccrypt_is_sing(ec)){
        cout<<"The curve is singular, please enter other data"<<endl;
        goto start;
    }
    cout<<"Enter the coordinates of the point curve to build the key."<<endl;
    cin>>Px>>Py;
    bignum_fromhex(Pt.x, Px.c_str(), ECCRYPT_BIGNUM_DIGITS);
    bignum_tohex(Pt.x,(char*) Px.c_str(), BIGNUM_DIGITS(*Pt.x), ECCRYPT_BIGNUM_DIGITS);
    bignum_fromhex(Pt.y, Py.c_str(), ECCRYPT_BIGNUM_DIGITS);
    bignum_tohex(Pt.y,(char*) Py.c_str(), BIGNUM_DIGITS(*Pt.y), ECCRYPT_BIGNUM_DIGITS);
    cout<<"The parameters of the resulting elliptic curve: a:"<<a<<"\nb:"<<b<<"\nP:"<<P<<"\nand elliptic curve non-singular"<<endl;
    cout<<"The coordinates of the selected point to build the key:P(x):"<<Px<<"\nP(y):"<<Py<<endl;

    cout<<"Enter your private key: "<<endl;
    cin>>close_k;
    open_key=eccrypt_point_mul(Pt,close_k,ec);
    char buff[BIGNUM_DIGIT_BITS*BIGNUM_MAX_DIGITS/8];
    bignum_tohex(open_key.x, buff, BIGNUM_DIGITS(*open_key.x), ECCRYPT_BIGNUM_DIGITS);
    cout<<"You open key:( "<<buff;
    bignum_tohex(open_key.y, buff, BIGNUM_DIGITS(*open_key.y), ECCRYPT_BIGNUM_DIGITS);
    cout<<","<<buff<<")"<<endl;

    cout<<"Enter your partner's public key: ";
    cin>>P_op_key_x>>P_op_key_y;
    bignum_fromhex(P_open_key.x, P_op_key_x.c_str(), ECCRYPT_BIGNUM_DIGITS);
    bignum_tohex(P_open_key.x,(char*) P_op_key_x.c_str(), BIGNUM_DIGITS(*P_open_key.x), ECCRYPT_BIGNUM_DIGITS);
    bignum_fromhex(P_open_key.y, P_op_key_y.c_str(), ECCRYPT_BIGNUM_DIGITS);
    bignum_tohex(P_open_key.y,(char*) P_op_key_y.c_str(), BIGNUM_DIGITS(*P_open_key.y), ECCRYPT_BIGNUM_DIGITS);
    cout<<"Your partner's public key: "<<endl;
    // cout<<"("<<P_open_key.x<<","<<P_open_key.y<<")"<<endl;

    sess_key = eccrypt_point_mul(P_open_key, close_k, ec); // вызов функции умножения точек
    char buffing [BIGNUM_DIGIT_BITS*BIGNUM_MAX_DIGITS/4]; // запись результата в качестве ключей ширования и дешифрования
    bignum_tohex(sess_key.x, buffing, BIGNUM_DIGITS(*sess_key.x), ECCRYPT_BIGNUM_DIGITS);
    cout<<"Your session key:\n"<<buffing;
    bignum_tohex(sess_key.y, buffing, BIGNUM_DIGITS(*sess_key.y), ECCRYPT_BIGNUM_DIGITS);
    cout<<" "<<buffing<<endl;
    cout<<"Choose your position: (1 - first, 0 - second) ";
    cin>>pos;
    if (pos)
    {
        bignum_tohex(sess_key.x, buffing, BIGNUM_DIGITS(*sess_key.y), ECCRYPT_BIGNUM_DIGITS);
    } else
    {
        bignum_tohex(sess_key.y, buffing, BIGNUM_DIGITS(*sess_key.y), ECCRYPT_BIGNUM_DIGITS);
    }
    cout << "Enter the filename: ";
    cin >> filename;
    if (access(filename.c_str(),0))
    {
        cout << "Filename is wrong";
        return -1;
    }
     cout<<strlen(buffing)<<endl;
     ifstream read(filename, ios::binary);
     cout << "Encryption - 0, decryption - 1: ";
     cin >> choise;
     string outfile;
     if (!choise)
     {
         outfile = filename + ".cuz";

     } else
     {
         outfile = "d_" + filename.substr(0, filename.length()-4);
     }

    if (!choise)
    {
    //проверка ключа
    if(strlen(buffing)>64)
    {
        while (strlen(buffing)!=64)
        {
          buffing[strlen(buffing)-1]='\0';
        }
    } else if(strlen(buffing)<64)
    {
        while(strlen(buffing)!=64)
        {
           buffing[strlen(buffing)] = '0';
           buffing[strlen(buffing)+1] = '\0';
        }
    }

    //ипользуем текст

    string bb;//промежуточные данные
    while(getline(read,date))
    {
        if(date.length()<16)
        {
            while(date.length()!=16)
            {
                date=date+'0';
            }
        } else if (date.length()>16)
        {
            while(date.length()!=16)
            {
                date=date.substr(0, date.size()-1);
            }
        }
        text.push_back(date);
    }

     ofstream write(outfile,ios::binary );

    uint8_t k[32];
    int j=0;
     for (int i=0;i<32;i++)
     {
         char af[2];
         copy(buffing +j, buffing +j+2, af);
         const char *cst=af;
         k[i]=strtol(cst,NULL,16);
            j=j+2;
     }


     for (int j=0;j<text.size();j++)
     {// пока есть текст который надо зашифровать
        uint8_t crip[BLOCK_SIZE];
        const char *dat= text[j].c_str();
        int m=0;
         for(int i = 0 ; i < BLOCK_SIZE ; i++) // конвертируем блок текста
         {
             char af[2];
             copy(dat +m, dat +m+2, af);
             const char *cst=af;
             crip[i] = strtol(cst,NULL,16);
             m=m+2;
         }
         kuznyechik_encrypt(k, crip, crip); // передаем ключ и блок текста в функцию шифрования
         for(int i = 0 ; i < BLOCK_SIZE ; i++)
         { // пишем результат в виджет последнего зашифрованного сообщения (передаем в канал связи)
             char bufffer [3];
             itoa (crip[i],bufffer,16);
             write.write(bufffer,2);
         }
         write.write("\n",1);
     }
    } else
    {
        if(strlen(buffing)>64)
        {
            while (strlen(buffing)!=64)
            {
              buffing[strlen(buffing)-1]='\0';
            }
        } else if(strlen(buffing)<64)
        {
            while(strlen(buffing)!=64)
            {
               buffing[strlen(buffing)] = '0';
               buffing[strlen(buffing)+1] = '\0';
            }
        }

        //ипользуем текст

        string bb;//промежуточные данные
        while(getline(read,date))
        {
            if(date.length()<32)
            {
                while(date.length()!=32)
                {
                    date=date+'0';
                }
            } else if (date.length()>32)
            {
                while(date.length()!=32)
                {
                    date=date.substr(0, date.size()-1);
                }
            }
            text.push_back(date);
        }

         ofstream write(outfile,ios::binary );

        uint8_t k[32];
        int j=0;
         for (int i=0;i<32;i++)
         {
             char af[2];
             copy(buffing +j, buffing +j+2, af);
             const char *cst=af;
             k[i]=strtol(cst,NULL,16);
                j=j+2;
         }


         for (int j=0;j<text.size();j++)
         {// пока есть текст который надо зашифровать
            uint8_t crip[BLOCK_SIZE];
            char *dat=(char*) text[j].c_str();
            int m=0;
             for(int i = 0 ; i < BLOCK_SIZE ; i++) // конвертируем блок текста
             {
                 string buf;
                 buf=text[j].substr(m,2);
                 const char *cstt=buf.c_str();
                 crip[i] = strtol(cstt,NULL,16);
                 m=m+2;
             }
             kuznyechik_decrypt(k, crip, crip); // передаем ключ и блок текста в функцию шифрования
             for(int i = 0 ; i < BLOCK_SIZE ; i++)
             { // пишем результат в виджет последнего зашифрованного сообщения (передаем в канал связи)
                 char bufffer [3];
                 itoa (crip[i],bufffer,16);
                 write.write(bufffer,3);
             }
             write.write("\n",1);
         }
    }
    return 0;

}

