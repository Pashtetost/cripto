#ifndef KUZNYECHIK_H
#define KUZNYECHIK_H

#include <stdint.h>

#define BLOCK_SIZE 16 // Размер блока 16 байт (или 128 бит)

typedef struct {
    uint8_t key[BLOCK_SIZE];		// один раундовый ключ
} one_key;
typedef struct {
    one_key keys[10];		// массив раундовых ключей
} round_keys;

/* сам алгоритм шифрования блоков данных*/
void kuznyechik_encrypt(uint8_t* input_key, //ключ 256 бит
                        uint8_t* plaintext, // открытый текст 128 бит
                        uint8_t* ciphertext); // шифротекст 128 бит

/*сложение двух двоичных векторов по модулю 2*/
void kuznyechik_X(uint8_t* first, // первое слогаемое
                  uint8_t* second, // второе слогаемое
                  uint8_t *result); // результат

/*S-преобразование*/
void kuznyechik_S(uint8_t* input); // входной блок

/*умножение над неприводимым полиномом x^8 + x^7 + x^6 + x + 1*/
uint8_t kuznyechik_GF_mul(uint8_t first, // бервый байт
                          uint8_t second); // второй байт
/*R-преобразование*/
void kuznyechik_R(uint8_t* input);// входной блок

/*L-преобразование*/
void kuznyechik_L(uint8_t* input);// входной блок

/*Функция генерации раундовых ключей*/
round_keys kuznyechik_generate_keys(uint8_t* input_key); // входной ключ

/*алгоритм дешифрования блоков шифротекста*/
void kuznyechik_decrypt(uint8_t* input_key, // входной ключ
                        uint8_t* ciphertext, // шифротект
                        uint8_t* plaintext); // результат

/*обратное R-преобразование*/
void kuznyechik_R_reverse(uint8_t* input);// входной блок

/*обратное L-преобразование*/
void kuznyechik_L_reverse(uint8_t* input);// входной блок

/*обратное S-преобразование*/
void kuznyechik_S_reverse(uint8_t* input);// входной блок

#endif // KUZNYECHIK_H
