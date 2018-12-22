#ifndef STRIBOG_H
#define STRIBOG_H

#include <stdint.h>
#include <string.h>
#define BLOCK_SIZE 64 // Размер блока 64 байт (или 512 бит)

typedef uint8_t container[BLOCK_SIZE];

typedef struct Context
{
    /* Буфер для очередного блока хешируемого сообщения / по факту вектор m */
  container buffer;
  container hash; /* Итоговый результат вычислений */
  container h; /* Промежуточный результат вычислений */
  container N;
  container Sigma; /*Контрольная сумма */
  container v_0; /* Инициализационный вектор */
  container v_512; /* Инициализационный вектор */
  /* Размер оставшейся части сообщения
                      (которая оказалась меньше очередных 64 байт) */
  unsigned int buf_size;
  int hash_size;   /* Размер хеш-суммы (512 или 256 бит) */
} Context;

/*Основные преобразования*/

//X-преобразование
void stribog_X(container first, // входной вектор
                  container second, // входной вектор
                  container result);  // результат

//S-преобразование
void stribog_S(container input); // входной вектор

//P-преобразование
void stribog_P(container input); // входной вектор

//L-преобразование
void stribog_L(container input); // входной вектор

//операция сложения в кольце Z2^n // она же исключающее или
void stribog_Add(container first, // входной вектор
                    container second, // входной вектор
                    container result); // результат

//Генерация раундового ключа
void stribog_GetKey(container K, // ключ
                       int i); // номер итерации

/*Функция сжатия*/

//Функция E
void stribog_E(container K, // ключ
                  container input, // входной вектор
                  container output); // результат

//Функция сжатия G
void stribog_G(container h, // вектор h
                  container N, // вектор N
                  container m); // входной блок сообщения

//Алгоритм

//Дополнение блока к виду 00 .. 00 01 ..
void stribog_Padding(container input, unsigned int size); // состаяние для обробатываемого блока

//Этап 1 //Инициализация базовой структуры для результата в 512 бит // IV 00 00 ...
void stribog_Init512(Context *Context); // сама структура

//Этап 1 //Инициализация базовой структуры для результата в 256 бит // IV 01 01 ...
void stribog_Init256(Context *Context); // сама структура

//Этап 2
void stribog_2(Context *Context); // состояние пред этапом

//Этап 3
void stribog_3(Context *Context); // состояние пред этапом

//Хеширование с результатом в 512 бит
uint8_t* stribog_512(uint8_t data[]);//входное сообщение/файл

//Хеширование с результатом в 256 бит
uint8_t* stribog_256(uint8_t data[]);//входное сообщение/файл

#endif // STRIBOG_H
