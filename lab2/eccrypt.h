#ifndef ECCRYPT_H
#define ECCRYPT_H

#include "bignumb.h"

/* число разрядов в числах, используемых модулем, <= BIGNUM_MAX_DIGITS */
#define ECCRYPT_BIGNUM_DIGITS BIGNUM_MAX_DIGITS

/* точка на эллиптической кривой */
struct eccrypt_point_t {
  bignum_digit_t x[ECCRYPT_BIGNUM_DIGITS]; /* координата x */
  bignum_digit_t y[ECCRYPT_BIGNUM_DIGITS]; /* координата y */
  int is_inf; /* является ли точка несобственной */
};

/* параметры кривой */
struct eccrypt_curve_t {
  bignum_digit_t a[ECCRYPT_BIGNUM_DIGITS]; /* коэффициенты уравнения     */
  bignum_digit_t b[ECCRYPT_BIGNUM_DIGITS]; /*     y^2 = x^3 + a*x + b    */
  bignum_digit_t m[ECCRYPT_BIGNUM_DIGITS]; /* в поле вычетов по модулю m */
  struct eccrypt_point_t g; /* генерирующая точка */
};
/*проверка кривой на сингулярность*/
bool eccrypt_is_sing(struct eccrypt_curve_t curve);

/* копирование точки */
void eccrypt_point_cpy(struct eccrypt_point_t* to, /* куда копируем */
                       struct eccrypt_point_t* from); /* откуда */

/* сложение точек эллиптической кривой */
eccrypt_point_t eccrypt_point_add( /* сумма */
                       eccrypt_point_t p, /* первое слогаемое */
                       eccrypt_point_t q, /* второе слогаемое */
                       eccrypt_curve_t curve); /* параметры кривой */

/* умножение точек эллиптической кривой */
eccrypt_point_t eccrypt_point_mul( /* результат */
                       struct eccrypt_point_t p, /* точка */
                       int m, /* множитель */
                       struct eccrypt_curve_t curve); /* параметры кривой */
#endif // ECCRYPT_H
