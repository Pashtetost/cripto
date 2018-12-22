#include <string.h>
#include "eccrypt.h"


/* копирование точки */
void eccrypt_point_cpy(struct eccrypt_point_t* to, /* куда копируем */
                       struct eccrypt_point_t* from) { /* откуда */
  if(to == from) return;
  if(to->is_inf = from->is_inf)
    return;

  memcpy(to->x, from->x, BIGNUM_SIZE(ECCRYPT_BIGNUM_DIGITS));
  memcpy(to->y, from->y, BIGNUM_SIZE(ECCRYPT_BIGNUM_DIGITS));
}

/* сложение точек эллиптической кривой */
eccrypt_point_t eccrypt_point_sum(// сумма
                       struct eccrypt_point_t p, // первое слогаемое
                       struct eccrypt_point_t q, // второе слогаемое
                       struct eccrypt_curve_t curve) { // параметры кривой
    struct eccrypt_point_t rslt; // вполне возможна ситуация s = p = q
    bignum_digit_t lambda[ECCRYPT_BIGNUM_DIGITS]; // коэффициент лямбда
    if((bignum_cmp(p.x, q.x, ECCRYPT_BIGNUM_DIGITS)==0)&&(bignum_cmp(p.y, q.y, ECCRYPT_BIGNUM_DIGITS)==0)){ // вычисляем лямбда по формулам
        bignum_fromhex(lambda, "3", ECCRYPT_BIGNUM_DIGITS); // если точки равны (3〖x_1〗^2+a)/2y_1 mod p
        bignum_mmul(lambda, p.x, curve.m, ECCRYPT_BIGNUM_DIGITS);
        bignum_mmul(lambda, p.x, curve.m, ECCRYPT_BIGNUM_DIGITS);
        bignum_madd(lambda, curve.a, curve.m, ECCRYPT_BIGNUM_DIGITS);
        bignum_digit_t const_2[ECCRYPT_BIGNUM_DIGITS];
        bignum_fromhex(const_2, "2", ECCRYPT_BIGNUM_DIGITS);
        bignum_mdiv(lambda, const_2, curve.m, ECCRYPT_BIGNUM_DIGITS);
        bignum_mdiv(lambda, p.y, curve.m, ECCRYPT_BIGNUM_DIGITS);
    }else{ // если не равны (y_2-y_1)/x_2-x_1)mod p
        bignum_digit_t second_term[ECCRYPT_BIGNUM_DIGITS];
        bignum_cpy(lambda, q.y, ECCRYPT_BIGNUM_DIGITS, ECCRYPT_BIGNUM_DIGITS);
        bignum_msub(lambda, p.y, curve.m, ECCRYPT_BIGNUM_DIGITS);
        bignum_cpy(second_term, q.x, ECCRYPT_BIGNUM_DIGITS, ECCRYPT_BIGNUM_DIGITS);
        bignum_msub(second_term, p.x, curve.m, ECCRYPT_BIGNUM_DIGITS);
        bignum_mdiv(lambda, second_term, curve.m, ECCRYPT_BIGNUM_DIGITS);
    }
    bignum_cpy(rslt.x, lambda, ECCRYPT_BIGNUM_DIGITS, ECCRYPT_BIGNUM_DIGITS); // вычисляем x_3=(λ^2-x_1-x_2 )mod p
    bignum_mmul(rslt.x, lambda, curve.m, ECCRYPT_BIGNUM_DIGITS);
    bignum_msub(rslt.x, p.x, curve.m, ECCRYPT_BIGNUM_DIGITS);
    bignum_msub(rslt.x, q.x, curve.m, ECCRYPT_BIGNUM_DIGITS);
    bignum_cpy(rslt.y, lambda, ECCRYPT_BIGNUM_DIGITS, ECCRYPT_BIGNUM_DIGITS); // вычисляем y_3=(λx_1-x_3-y_1)mod p
    bignum_cpy(lambda, p.x, ECCRYPT_BIGNUM_DIGITS, ECCRYPT_BIGNUM_DIGITS);
    bignum_msub(lambda, rslt.x, curve.m, ECCRYPT_BIGNUM_DIGITS);
    bignum_mmul(rslt.y, lambda, curve.m, ECCRYPT_BIGNUM_DIGITS);
    bignum_msub(rslt.y, p.y, curve.m, ECCRYPT_BIGNUM_DIGITS);
    return rslt;
}

/* умножение точек эллиптической кривой на константу */
eccrypt_point_t eccrypt_point_mul(eccrypt_point_t p, /* точка */
                       int m,  /* множитель */
                       eccrypt_curve_t curve){ /* параметры кривой */
    struct eccrypt_point_t rslt;
    rslt = p;

    for (int i = 1 ; i < m ; i++){
        rslt = eccrypt_point_sum(rslt, p, curve);
    }
    return rslt;
}

/*проверка кривой на сингулярность*/
bool eccrypt_is_sing(struct eccrypt_curve_t curve){
    bignum_digit_t second_term[ECCRYPT_BIGNUM_DIGITS];
    bignum_fromhex(second_term, "1b", ECCRYPT_BIGNUM_DIGITS); // во второй множитель пишем 27
    bignum_digit_t first_term[ECCRYPT_BIGNUM_DIGITS];
    bignum_fromhex(first_term, "4", ECCRYPT_BIGNUM_DIGITS); // в первый 4

    bignum_mmul(first_term, curve.a, curve.m, ECCRYPT_BIGNUM_DIGITS); /* 4*a */
    bignum_mmul(first_term, curve.a, curve.m, ECCRYPT_BIGNUM_DIGITS); /* 4*a^2 */
    bignum_mmul(first_term, curve.a, curve.m, ECCRYPT_BIGNUM_DIGITS); /* 4*a^3 */
    bignum_mmul(second_term, curve.b, curve.m, ECCRYPT_BIGNUM_DIGITS); /* 27*b */
    bignum_mmul(second_term, curve.b, curve.m, ECCRYPT_BIGNUM_DIGITS); /* 27*b^2 */
    bignum_madd(first_term, second_term, curve.m, ECCRYPT_BIGNUM_DIGITS); /* 4*a^3+27*b^2 */

    if(bignum_iszero(first_term, ECCRYPT_BIGNUM_DIGITS)){ // сравниваем с нулем
        return true;
    }
    return false;
}
