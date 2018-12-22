#include <algorithm>
#include <fstream>
#include <iostream>
#include <string>
#include <io.h>
#include <vector>
#include "eccrypt.h"
#include "stribog.h"


using namespace std;

int main(int argc, char *argv[])
{
    start:
    bignum_digit_t Signature_key[ECCRYPT_BIGNUM_DIGITS];
    eccrypt_curve_t ec; // параметры кривой
    eccrypt_point_t Q; // ключ проверки подписи
    eccrypt_point_t C; // точка С=kP
    string P,a,b,m,q,Px,Py,d,HH,vector_R,vector_S;
    string filename; // имя файла с данными
    string date,dat;
    int close_k; //наш закрытый ключ

    cout<<"You are welcome to encrypt a grasshopper with key exchange along elliptic curves."<<endl;
    cout<<"First, enter the parameters of the elliptic curve (P,A,B): ";
    cin>>P>>a>>b;
    bignum_fromhex(ec.p,P.c_str(), ECCRYPT_BIGNUM_DIGITS);
    bignum_tohex(ec.p,(char*) P.c_str(), BIGNUM_DIGITS(*ec.m), ECCRYPT_BIGNUM_DIGITS);
    bignum_fromhex(ec.a,a.c_str(), ECCRYPT_BIGNUM_DIGITS);
    bignum_tohex(ec.a,(char*) a.c_str(), BIGNUM_DIGITS(*ec.a), ECCRYPT_BIGNUM_DIGITS);
    bignum_fromhex(ec.b,b.c_str(), ECCRYPT_BIGNUM_DIGITS);
    bignum_tohex(ec.b,(char*) b.c_str(), BIGNUM_DIGITS(*ec.b), ECCRYPT_BIGNUM_DIGITS);
    if(eccrypt_is_sing(ec)){
        cout<<"The curve is singular, please enter other data"<<endl;
        goto start;
    }
    stage1:
    cout<<"Enter the order of the group of points of the elliptic curve M: ";
    cin >>m;
    bignum_fromhex(ec.m,m.c_str(), ECCRYPT_BIGNUM_DIGITS);
    bignum_tohex(ec.m,(char*) m.c_str(), BIGNUM_DIGITS(*ec.m), ECCRYPT_BIGNUM_DIGITS);
    if(bignum_cmp(ec.p,ec.m, ECCRYPT_BIGNUM_DIGITS)==0)
    {
        cout<<"Error.The order of a group of points of an elliptic curve m is equal to the parameter of an elliptic curve p. \n"
              "Change one of the parameters."<<endl;
        goto stage1;
    }
    stage2:
    cout<<"Enter the order of the cyclic subgroup of points of the elliptic curve Q: ";
    cin >>q;
    bignum_fromhex(ec.q,q.c_str(), ECCRYPT_BIGNUM_DIGITS);
    bignum_tohex(ec.q,(char*) q.c_str(), BIGNUM_DIGITS(*ec.m), ECCRYPT_BIGNUM_DIGITS);
    // тут координата Y образующей точки прямой выступает пока в роли
                            //буффера для хранения результата деления m на q

    bignum_div(ec.m,ec.q,NULL,ec.g.y,ECCRYPT_BIGNUM_DIGITS);
    if(!bignum_iszero(ec.g.y,ECCRYPT_BIGNUM_DIGITS))
    {
        cout<<"The parameter q does not completely divide the parameter m. Change the parameters."<<endl;
        goto stage2;
    }

    cout<<"Enter the coordinates of the point curve to build the key."<<endl;
    cin>>Px>>Py;
    bignum_fromhex(ec.g.x, Px.c_str(), ECCRYPT_BIGNUM_DIGITS);
    bignum_tohex(ec.g.x,(char*) Px.c_str(), BIGNUM_DIGITS(*ec.g.x), ECCRYPT_BIGNUM_DIGITS);
    bignum_fromhex(ec.g.y, Py.c_str(), ECCRYPT_BIGNUM_DIGITS);
    bignum_tohex(ec.g.y,(char*) Py.c_str(), BIGNUM_DIGITS(*ec.g.x), ECCRYPT_BIGNUM_DIGITS);

    cout<<"The parameters of the resulting elliptic curve: a:"<<a<<"\nb:"<<b<<"\nP:"<<P<<"\nand elliptic curve non-singular"<<endl;
    cout<<"The order of the group of points of the eleptic curve m: "<<m<<endl;
    cout <<"The order of a cyclic subgroup of points of an eleptic curve q: "<<q<<endl;
    cout<<"The coordinates of the selected point to build the key:P(x):"<<Px<<"\nP(y):"<<Py<<endl;
    ec.g.is_inf = false;

    cout<<"Set the signing key d: "<<endl;
    cin>>d;
    bignum_fromhex(Signature_key, d.c_str(), ECCRYPT_BIGNUM_DIGITS);
    bignum_tohex(Signature_key, (char*)d.c_str(), BIGNUM_DIGITS(*Signature_key), ECCRYPT_BIGNUM_DIGITS);
    cout<<"The signing key d: \n"<<d<<endl;
    Q = eccrypt_point_mul(ec.g, Signature_key, ec);
    char *buff_Qx=new char[BIGNUM_DIGITS(*Q.x)];
    bignum_tohex(Q.x, buff_Qx, BIGNUM_DIGITS(*Q.x), ECCRYPT_BIGNUM_DIGITS);
    cout<<" Signature verification key Q:\n("<<buff_Qx;
    delete[] buff_Qx;
    char *buff_Qy=new char[BIGNUM_DIGITS(*Q.y)];
    bignum_tohex(Q.y, buff_Qy, BIGNUM_DIGITS(*Q.y), ECCRYPT_BIGNUM_DIGITS);
    cout<<","<<buff_Qy<<")"<<endl;
    delete[] buff_Qy;

    cout << "Enter the filename: ";
    cin >> filename;
    if (access(filename.c_str(),0))
    {
        cout << "Filename is wrong";
        return -1;
    }
     ifstream read(filename, ios::binary);
    //ипользуем текст
    while(getline(read,date))
    {
        dat=dat+date;
    }
    cout<<"Data:\n"<<dat<<endl;
    uint8_t *data = new uint8_t[dat.length()/2];
    int j=0;
    for (int i=0;i<_msize(data)/sizeof(data[0]);i++)
    {
        string buf;
        buf=dat.substr(j,2);
        const char *cst=buf.c_str();
        data[i]=strtol(cst,NULL,16);
        j=j+2;
    }

    container hash; // вектор в ктором будет результат
    unsigned int length_hash=0; // сколько в нем байт, понадобится для вывода результата в виджет
    if(ECCRYPT_BIGNUM_DIGITS * sizeof(ec.q[0])*8==512){ // если у нас q представляется 512 битами
        memcpy(hash,stribog_512(data),BLOCK_SIZE); // используем стрибог для 512 бит
        length_hash=BLOCK_SIZE; // а длина хеша весь блок
    }
    if(ECCRYPT_BIGNUM_DIGITS * sizeof(ec.q[0])*8==256){ // если 256 битами
        memcpy(hash,stribog_256(data),BLOCK_SIZE); // то стрибог соответственно для 256 бит
        length_hash=BLOCK_SIZE/2; // а длина хеша пол блока
    }
   
    char buffer [3];
    for(int i = 0 ; i < length_hash ; i++)
    { // пишем в него новый результат
        string s;
        itoa (hash[i],buffer,16);
        s.append(buffer);
        int k=0;
        while(s.length()<2)
        {
            s.insert(k,1,'0');
            k++;
        }
        HH+=s;
    }
    cout<<"The resulting hash function:\n"<<HH<<endl;
    
    bignum_digit_t alpha[ECCRYPT_BIGNUM_DIGITS]; // вектор альфа, векторное представление хэша сообщения
    bignum_digit_t e[ECCRYPT_BIGNUM_DIGITS]; // вектор e = альфа mod q, где q - порядок циклической подгруппы
    bignum_digit_t k[ECCRYPT_BIGNUM_DIGITS]; // случайно сгенерированное число, причем 0<k<q,
    bignum_fromhex(alpha, HH.c_str(), ECCRYPT_BIGNUM_DIGITS); // хеш  переводим в большое число
    // вычисляем e
    bignum_div(alpha, ec.q, 0, e, ECCRYPT_BIGNUM_DIGITS); // берем альфа по модулю q
    if(bignum_iszero(e, ECCRYPT_BIGNUM_DIGITS))
    { // если получился ноль
        e[0] = 1; // принимаем за еденицу
    }
    // если необходиио проверить контрольное значение из примера ГОСТа, то раскоментируйте строку ниже
    //bignum_fromhex(e, "2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5", ECCRYPT_BIGNUM_DIGITS);
    
    bignum_digit_t r[ECCRYPT_BIGNUM_DIGITS]; // вектор r = C.x mod q, где C.x - координата x точки C
    bignum_digit_t s[ECCRYPT_BIGNUM_DIGITS]; // вектор s = (rd+ke) mod q
    bignum_setzero(r, ECCRYPT_BIGNUM_DIGITS); // обнуляем вектора, для последующей удобной работы
    bignum_setzero(s, ECCRYPT_BIGNUM_DIGITS);
    // формируем подпись
    while(bignum_iszero(s, ECCRYPT_BIGNUM_DIGITS))
    { // что бы вектор s не был нулевым
        while(bignum_iszero(r, ECCRYPT_BIGNUM_DIGITS))
        { // что бы вектор r не был нулевым
            // генерируем k
            for(unsigned int i = 0 ; i < ECCRYPT_BIGNUM_DIGITS ; i++)
            { // заполняем случайными значениями
                k[i]=rand();
            }
            bignum_div(k, ec.q, 0, k, ECCRYPT_BIGNUM_DIGITS); // берем его по модулю для того что бы 0<k<q
            // существует вероятность что rand() сгенерирует k=0, но выполнять лишнюю проверку - тратить ресурсы

            // если необходиио проверить контрольное значение из примера ГОСТа, то раскоментируйте строку ниже
            //bignum_fromhex(k, "77105C9B20BCD3122823C8CF6FCC7B956DE33814E95B7FE64FED924594DCEAB3", ECCRYPT_BIGNUM_DIGITS);

            C = eccrypt_point_mul(ec.g, k, ec);// вычисляем точку C=kP

            bignum_div(C.x, ec.q, 0, r, ECCRYPT_BIGNUM_DIGITS); // берем его по модулю для того что бы 0<k<q
        }
        //вычмсляем s=(rd+ke) mod q
        bignum_digit_t second_term[ECCRYPT_BIGNUM_DIGITS];
        bignum_cpy(second_term, k, ECCRYPT_BIGNUM_DIGITS, ECCRYPT_BIGNUM_DIGITS);
        bignum_mmul(second_term, e, ec.q, ECCRYPT_BIGNUM_DIGITS);
        bignum_cpy(s, r, ECCRYPT_BIGNUM_DIGITS, ECCRYPT_BIGNUM_DIGITS);
        bignum_mmul(s, Signature_key, ec.q, ECCRYPT_BIGNUM_DIGITS);
        bignum_madd(s, second_term, ec.q, ECCRYPT_BIGNUM_DIGITS);
    }
    // выведем полученные значения
    char *buff_r=new char[BIGNUM_DIGITS(*r)];
    bignum_tohex(r, buff_r, BIGNUM_DIGITS(*r), ECCRYPT_BIGNUM_DIGITS);
    cout<<"Digital signature vector R:\n"<<buff_r<<endl;
    vector_R=buff_r;
    delete[] buff_r;
    char *buff_s=new char[BIGNUM_DIGITS(*s)];
    bignum_tohex(s, buff_s, BIGNUM_DIGITS(*s), ECCRYPT_BIGNUM_DIGITS);
    cout<<"and vector S:\n"<<buff_s<<endl;
    vector_S=buff_s;
    delete[] buff_s;

    cout<<"Verification of the received digital signature"<<endl;
    // вектора для проверки подписи
    bignum_digit_t v[ECCRYPT_BIGNUM_DIGITS]; // вектор v = e^(-1) mod q
    bignum_digit_t z1[ECCRYPT_BIGNUM_DIGITS]; // вектор z1 = sv mod q
    bignum_digit_t z2[ECCRYPT_BIGNUM_DIGITS]; // вектор z2 = -rv mod q
    bignum_digit_t R[ECCRYPT_BIGNUM_DIGITS]; // вектор R = C.x mod q, в данном случае точка C расчитывается как C=z1P+z2Q

    bignum_fromhex(r, vector_R.c_str(), ECCRYPT_BIGNUM_DIGITS);
    if(bignum_iszero(r, ECCRYPT_BIGNUM_DIGITS)||(bignum_cmp(r, ec.q, ECCRYPT_BIGNUM_DIGITS)!=-1))
    {
        cout<<("Last verified signature: invalid.Provided condition: 0 <r <q");
       return -3;
    }
    bignum_fromhex(s, vector_S.c_str(), ECCRYPT_BIGNUM_DIGITS);
    if(bignum_iszero(s, ECCRYPT_BIGNUM_DIGITS)||(bignum_cmp(s, ec.q, ECCRYPT_BIGNUM_DIGITS)!=-1))
    {
        cout<<("Last verified signature: invalid.Provided condition: 0 <s <q");
       return -4;
    }
    // вычисление хеша сообщения

    uint8_t *data2 = new uint8_t[dat.length()/2];
    j=0;
    for (int i=0;i<_msize(data2)/sizeof(data2[0]);i++)
    {
        string buf;
        buf=dat.substr(j,2);
        const char *cst=buf.c_str();
        data2[i]=strtol(cst,NULL,16);
        j=j+2;
    }

    container hash2;
    unsigned int length_res=0;
    if(ECCRYPT_BIGNUM_DIGITS * sizeof(ec.q[0])*8==512)
    {
        memcpy(hash2,stribog_512(data),BLOCK_SIZE);
        length_res=BLOCK_SIZE;
    }
    if(ECCRYPT_BIGNUM_DIGITS * sizeof(ec.q[0])*8==256)
    {
        memcpy(hash2,stribog_256(data),BLOCK_SIZE);
        length_res=BLOCK_SIZE/2;
    }
    string HaH;
    for(int i = 0 ; i < length_hash ; i++)
    { // пишем в него новый результат
        string s;
        itoa (hash[i],buffer,16);
        s.append(buffer);
        int k=0;
        while(s.length()<2)
        {
            s.insert(k,1,'0');
            k++;
        }
        HaH+=s;
    }
    cout<<"Hash function after checking:\n"<<HaH<<endl;

    // находим альфа
    bignum_fromhex(alpha,HaH.c_str(), ECCRYPT_BIGNUM_DIGITS);
    // вычисляем e
    bignum_div(alpha, ec.q, 0, e, ECCRYPT_BIGNUM_DIGITS);
    if(bignum_iszero(e, ECCRYPT_BIGNUM_DIGITS))
    {
        e[0] = 1;
    }
    // если необходиио проверить контрольное значение из примера ГОСТа, то раскоментируйте строку ниже
    bignum_fromhex(e, "2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5", ECCRYPT_BIGNUM_DIGITS);
    // вычисляем v
    bignum_cpy(v, e, ECCRYPT_BIGNUM_DIGITS, ECCRYPT_BIGNUM_DIGITS);
    bignum_inv(v, ec.q, ECCRYPT_BIGNUM_DIGITS);
    // вычисляем z1
    bignum_cpy(z1, s, ECCRYPT_BIGNUM_DIGITS, ECCRYPT_BIGNUM_DIGITS); // сейчас z1=s mod q
    bignum_mmul(z1, v, ec.q, ECCRYPT_BIGNUM_DIGITS); // сейчас z1=sv mod q
    // вычисляем z2
    bignum_cpy(z2, r, ECCRYPT_BIGNUM_DIGITS, ECCRYPT_BIGNUM_DIGITS); // сейчас z2=r mod q
    bignum_digit_t const_zero[ECCRYPT_BIGNUM_DIGITS];
    bignum_setzero(const_zero, ECCRYPT_BIGNUM_DIGITS);
    bignum_msub(const_zero, z2, ec.q, ECCRYPT_BIGNUM_DIGITS); // сейчас const_zero=-r mod q
    bignum_cpy(z2, const_zero, ECCRYPT_BIGNUM_DIGITS, ECCRYPT_BIGNUM_DIGITS); // сейчас z2=r mod q
    bignum_mmul(z2, v, ec.q, ECCRYPT_BIGNUM_DIGITS); // сейчас z2=-rv mod q
    // вычисляем C
    C = eccrypt_point_add(eccrypt_point_mul(ec.g, z1, ec), eccrypt_point_mul(Q, z2, ec), ec);
    // вычисляем R
    bignum_cpy(R, C.x, ECCRYPT_BIGNUM_DIGITS, ECCRYPT_BIGNUM_DIGITS);
    bignum_div(R, ec.q, 0 , R, ECCRYPT_BIGNUM_DIGITS);

    // проверяем R=r
    if(bignum_cmp(R, r, ECCRYPT_BIGNUM_DIGITS)!=0)
    {
        cout<<"Verified signature: invalid.Provided condition: R = r"<<endl;
        return -5;
    }
    cout<<"Verified signature: true"<<endl;
    return 0;
}
