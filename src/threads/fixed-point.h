#ifndef PINTOS_39_FIXED_POINT_H
#define PINTOS_39_FIXED_POINT_H

#include <stdint.h>

typedef int32_t fp_t;

#define P 17
#define Q 14
#define F (1 << Q)

#define fp_is_pos(x) (!((x) >> (P + Q)))

#define int_to_fp(n) ((n) * (F))
#define fp_to_int_zero(x) ((x) / (F))
#define fp_to_int_roundup(x) (fp_to_int_zero(x) + (fp_is_pos(x) ? 1 : -1))
#define fp_to_int(x)  ((fp_is_pos(x)) ? ((fp_add_fp((x), ((F) / 2))) / (F))  \
                                      : ((fp_sub_fp((x), ((F) / 2))) / (F)))

#define fp_add_fp(x, y) ((x) + (y))
#define fp_add_int(x, n) ((x) + int_to_fp(n))
#define fp_sub_fp(x, y) ((x) - (y))
#define fp_sub_int(x, n) ((x) - int_to_fp(n))
#define fp_mul_fp(x, y) ((fp_t) ((((int64_t) (x)) * (y)) / (F)))
#define fp_mul_int(x, n) ((x) * (n))
#define fp_div_fp(x, y) ((fp_t) ((((int64_t) (x)) * (F)) / (y)))
#define fp_div_int(x, n) ((x) / (n))
#define fp_frac(d, n) fp_div_int(int_to_fp(d), n)

#define adjust(x, u, l) ((x) > (u) ? (u) : ((x) < (l) ? (l) : (x)))

#endif //PINTOS_39_FIXED_POINT_H
