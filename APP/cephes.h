
#ifndef _CEPHES_H_
#define _CEPHES_H_


double cephes_igamc(double a, double x);
double cephes_igam(double a, double x);
double cephes_lgam(double x);
double cephes_p1evl(double x, double *coef, int N);
double cephes_polevl(double x, double *coef, int N);
double cephes_erf(double x);
double cephes_erfc(double x);
double cephes_normal(double x);

int poker_test(unsigned int M, unsigned char *test_buff, unsigned int buff_len);
#endif /*  _CEPHES_H_  */
