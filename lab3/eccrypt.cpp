#include <string.h>
#include "eccrypt.h"

//копирование точки
void eccrypt_point_cpy(struct eccrypt_point_t *to, // куда копируем
                       struct eccrypt_point_t *from) { // откуда
  if(&to == &from) return;
  to->is_inf = from->is_inf;
  bignum_cpy(to->x, from->x, ECCRYPT_BIGNUM_DIGITS, ECCRYPT_BIGNUM_DIGITS);
  bignum_cpy(to->y, from->y, ECCRYPT_BIGNUM_DIGITS, ECCRYPT_BIGNUM_DIGITS);
}

// Проверка на сингулярность
bool eccrypt_is_sing(struct eccrypt_curve_t curve){
    bignum_digit_t second_term[ECCRYPT_BIGNUM_DIGITS];
    bignum_fromhex(second_term, "1b", ECCRYPT_BIGNUM_DIGITS); // во второй множитель пишем 27
    bignum_digit_t first_term[ECCRYPT_BIGNUM_DIGITS];
    bignum_fromhex(first_term, "4", ECCRYPT_BIGNUM_DIGITS); // в первый 4

    bignum_mmul(first_term, curve.a, curve.p, ECCRYPT_BIGNUM_DIGITS); /* 4*a */
    bignum_mmul(first_term, curve.a, curve.p, ECCRYPT_BIGNUM_DIGITS); /* 4*a^2 */
    bignum_mmul(first_term, curve.a, curve.p, ECCRYPT_BIGNUM_DIGITS); /* 4*a^3 */
    bignum_mmul(second_term, curve.b, curve.p, ECCRYPT_BIGNUM_DIGITS); /* 27*b */
    bignum_mmul(second_term, curve.b, curve.p, ECCRYPT_BIGNUM_DIGITS); /* 27*b^2 */
    bignum_madd(first_term, second_term, curve.p, ECCRYPT_BIGNUM_DIGITS); /* 4*a^3+27*b^2 */

    if(bignum_iszero(first_term, ECCRYPT_BIGNUM_DIGITS)){ // сравниваем с нулем
        return true;
    }
    return false;
}

// суммирование двух точек
eccrypt_point_t eccrypt_point_add(// сумма
                       struct eccrypt_point_t p, // первое слогаемое
                       struct eccrypt_point_t q, // второе слогаемое
                       struct eccrypt_curve_t curve) { // параметры кривой
    struct eccrypt_point_t rslt; // вполне возможна ситуация s = p = q

    if(p.is_inf){ // если первая точка нулевой эелемент, то возвращаем в качестве результата вторую
        //eccrypt_point_cpy(&rslt, &q);
        rslt = q;
        return rslt;
    }
    if(q.is_inf){ // если торая точка нулевой эелемент, то возвращаем в качестве результата первую
        //eccrypt_point_cpy(&rslt, &p);
        rslt = p;
        return rslt;
    }
    bignum_digit_t lambda[ECCRYPT_BIGNUM_DIGITS]; // коэффициент лямбда
    bignum_cpy(lambda, p.y, ECCRYPT_BIGNUM_DIGITS, ECCRYPT_BIGNUM_DIGITS); // пока используем его как буффер для обратного элемента
    bignum_inv(lambda, curve.p, ECCRYPT_BIGNUM_DIGITS); // координаты y пеквой точки
    if((bignum_cmp(lambda, q.y, ECCRYPT_BIGNUM_DIGITS)==0)&&(bignum_cmp(p.x, q.x, ECCRYPT_BIGNUM_DIGITS)==0)){// если точки симетричны отностительно OX
        rslt.is_inf = true; // в качестве результата точка в бесконечности, она же нулевой элемент
        bignum_setmax(rslt.x, ECCRYPT_BIGNUM_DIGITS); // в качестве координат примем максимальное значение
        bignum_setmax(rslt.y, ECCRYPT_BIGNUM_DIGITS); // оно будет больше чем простое число принятое в качестве параметра кривой
        return rslt; // что позволит нам различать такую точку.
    }

    // в оставшемся случае вычисляем результат по алгебраическим формулам

    if((bignum_cmp(p.x, q.x, ECCRYPT_BIGNUM_DIGITS)==0)&&(bignum_cmp(p.y, q.y, ECCRYPT_BIGNUM_DIGITS)==0)){ // вычисляем лямбда по формулам
        bignum_fromhex(lambda, "3", ECCRYPT_BIGNUM_DIGITS); // если точки равны (3〖x_1〗^2+a)/2y_1 mod p
        bignum_mmul(lambda, p.x, curve.p, ECCRYPT_BIGNUM_DIGITS);
        bignum_mmul(lambda, p.x, curve.p, ECCRYPT_BIGNUM_DIGITS);
        bignum_madd(lambda, curve.a, curve.p, ECCRYPT_BIGNUM_DIGITS);
        bignum_digit_t const_2[ECCRYPT_BIGNUM_DIGITS];
        bignum_fromhex(const_2, "2", ECCRYPT_BIGNUM_DIGITS);
        bignum_mdiv(lambda, const_2, curve.p, ECCRYPT_BIGNUM_DIGITS);
        bignum_mdiv(lambda, p.y, curve.p, ECCRYPT_BIGNUM_DIGITS);
    }else{ // если не равны (y_2-y_1)/x_2-x_1)mod p
        bignum_digit_t second_term[ECCRYPT_BIGNUM_DIGITS];
        bignum_cpy(lambda, q.y, ECCRYPT_BIGNUM_DIGITS, ECCRYPT_BIGNUM_DIGITS);
        bignum_msub(lambda, p.y, curve.p, ECCRYPT_BIGNUM_DIGITS);
        bignum_cpy(second_term, q.x, ECCRYPT_BIGNUM_DIGITS, ECCRYPT_BIGNUM_DIGITS);
        bignum_msub(second_term, p.x, curve.p, ECCRYPT_BIGNUM_DIGITS);
        bignum_mdiv(lambda, second_term, curve.p, ECCRYPT_BIGNUM_DIGITS);
    }
    bignum_cpy(rslt.x, lambda, ECCRYPT_BIGNUM_DIGITS, ECCRYPT_BIGNUM_DIGITS); // вычисляем x_3=(λ^2-x_1-x_2 )mod p
    bignum_mmul(rslt.x, lambda, curve.p, ECCRYPT_BIGNUM_DIGITS);
    bignum_msub(rslt.x, p.x, curve.p, ECCRYPT_BIGNUM_DIGITS);
    bignum_msub(rslt.x, q.x, curve.p, ECCRYPT_BIGNUM_DIGITS);
    bignum_cpy(rslt.y, lambda, ECCRYPT_BIGNUM_DIGITS, ECCRYPT_BIGNUM_DIGITS); // вычисляем y_3=(λx_1-x_3-y_1)mod p
    bignum_cpy(lambda, p.x, ECCRYPT_BIGNUM_DIGITS, ECCRYPT_BIGNUM_DIGITS);
    bignum_msub(lambda, rslt.x, curve.p, ECCRYPT_BIGNUM_DIGITS);
    bignum_mmul(rslt.y, lambda, curve.p, ECCRYPT_BIGNUM_DIGITS);
    bignum_msub(rslt.y, p.y, curve.p, ECCRYPT_BIGNUM_DIGITS);
    return rslt;
}

// умножение точки на константу
eccrypt_point_t eccrypt_point_mul(eccrypt_point_t p, /* точка */
                       unsigned int k,  /* множитель */
                       eccrypt_curve_t curve){ /* параметры кривой */
    struct eccrypt_point_t rslt;
    rslt = p;

    for (unsigned int i = 1 ; i < k ; i++){
        rslt = eccrypt_point_add(rslt, p, curve);
    }
    return rslt;
}

// умножение точки эллиптической кривой
eccrypt_point_t eccrypt_point_mul(eccrypt_point_t p, // точка
                       bignum_digit_t *k, // множитель
                       eccrypt_curve_t curve){ // параметры кривой
    struct eccrypt_point_t rslt; // точка результат
    rslt.is_inf = true; // обнуляем ее, то есть говорим, что она нулевой элемент
    bignum_setmax(rslt.x, ECCRYPT_BIGNUM_DIGITS); // то есть точка в бесконечности
    bignum_setmax(rslt.y, ECCRYPT_BIGNUM_DIGITS); // символически присваиваем координатам максимальное значение, даже большее чем параметр

    if(bignum_iszero(k, ECCRYPT_BIGNUM_DIGITS)){ // если надо умножить на ноль, то
        return rslt; // возвращаем нулевой элемент
    }

    bignum_digit_t counter[ECCRYPT_BIGNUM_DIGITS]; // заводим переменную для разбиения на степени двойки
    bignum_cpy(counter, k , ECCRYPT_BIGNUM_DIGITS, ECCRYPT_BIGNUM_DIGITS); // даем ей значение константы, на которую надо умножить
    struct eccrypt_point_t iteration_point; // точка которая будет хранить результат 2^i*P, где i номер итерации(бита counter с которым мы работаем)
    iteration_point = p;
    for(unsigned short i = 0 ;// будем перебирать биты
        i < (ECCRYPT_BIGNUM_DIGITS * sizeof(counter[0])*8);// до последнего в нашем счетчике
        i++){
        if(counter[0] & (1 << 0)){ // если на конце 1
            //qDebug()<<"1";
            rslt = eccrypt_point_add(rslt, iteration_point, curve); // прибавляем к результату итерационную точку (она же значение 2^i*P)
        }
        iteration_point = eccrypt_point_add(iteration_point, iteration_point, curve); // повышаем степень у двойки
        //qDebug()<<iteration_point.x[0] << iteration_point.y[0];
        bool hi_bit = false; // старший бит разряда
        for(int j = ECCRYPT_BIGNUM_DIGITS ; j > 0  ; j--){
            if(hi_bit){ // если младший бит предыдущего разряда был 1
                hi_bit = counter[j-1] & (1 << 0); // запоминаем младший бит обрабатываемого разряда
                counter[j-1] = counter[j-1]>>1; // делаем сдвиг
                counter[j-1] |= (1 << ((sizeof(counter[j-1])*8)-1)); // в старший бит обрабатываемого пишем единицу
            }else{
                hi_bit = counter[j-1] & (1 << 0); // запоминаем младший бит обрабатываемого разряда
                counter[j-1] = counter[j-1]>>1; // делаем сдвиг
            }
        }
    }
    return rslt;
}
