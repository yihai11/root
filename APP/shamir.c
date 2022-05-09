#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <math.h>
#include "shamir.h"
#include "FreeRTOS.h"
//#include "fpga_sm3.h"
#include "mcu_algorithm.h"
static int prime = 257;
//static int prime = 251;

unsigned long mix(unsigned long a, unsigned long b, unsigned long c) {
	a = a - b;
	a = a - c;
	a = a ^ (c >> 13);
	b = b - c;
	b = b - a;
	b = b ^ (a << 8);
	c = c - a;
	c = c - b;
	c = c ^ (b >> 13);
	a = a - b;
	a = a - c;
	a = a ^ (c >> 12);
	b = b - c;
	b = b - a;
	b = b ^ (a << 16);
	c = c - a;
	c = c - b;
	c = c ^ (b >> 5);
	a = a - b;
	a = a - c;
	a = a ^ (c >> 3);
	b = b - c;
	b = b - a;
	b = b ^ (a << 10);
	c = c - a;
	c = c - b;
	c = c ^ (b >> 15);
	return c;
}

int modular_exponentiation(int base, int exp, int mod) {
	if (exp == 0) {
		return 1;
	} else if (exp % 2 == 0) {
		int mysqrt = modular_exponentiation(base, exp / 2, mod);
		return (mysqrt * mysqrt) % mod;
	} else {
		return (base * modular_exponentiation(base, exp - 1, mod)) % mod;
	}
}

int split_number(int number, int n, int t, int *int_shares) {
	int *coef = pvPortMalloc( sizeof(int) * n );
	int x;
	int i;
	int random;

	coef[0] = number;

	for (i = 1; i < t; ++i) {
		/*  Generate random coefficients -- use arc4random if available  */
//		#ifdef HAVE_ARC4RANDOM
//		coef[i] = arc4random_uniform(prime);
//		#else
		//get_random_data((unsigned char *)&random,sizeof(int));
		get_random_MCU((unsigned char *)&random,sizeof(int));
//GetRandom((unsigned char *)&random, sizeof(int));
//	    random = 0x01040a34;
		coef[i] = random % (prime);
		//coef[i] = rand() % (prime);
//		#endif
	}
	for (x = 0; x < n; ++x) {
		int y = coef[0];

		/* Calculate the shares */
		for (i = 1; i < t; ++i) {
			int temp = modular_exponentiation(x + 1, i, prime);

			y = (y + (coef[i] * temp % prime)) % prime;
		}
		/* Sometimes we're getting negative numbers, and need to fix that */
		y = (y + prime) % prime;

		int_shares[x] = y;
	}
	vPortFree(coef);
	return 0;
}
/*
	Math stuff
*/

int * gcdD(int a, int b) {
	int * xyz = pvPortMalloc(sizeof(int) * 3);

	if (b == 0) {
		xyz[0] = a;
		xyz[1] = 1;
		xyz[2] = 0;
	} else {
		//int n = floor(a / b);
		int n = a / b;
		int c = a % b;
		int *r = gcdD(b, c);

		xyz[0] = r[0];
		xyz[1] = r[2];
		xyz[2] = r[1] - r[2] * n;

		vPortFree(r);
	}
	return xyz;
}
/*
	More math stuff
*/

int modInverse(int k) {
	
	int r;
	int * xyz;
  k = k % prime;
	if (k < 0) {
		xyz = gcdD(prime, -k);
		r = -xyz[2];
	} else {
		xyz = gcdD(prime, k);
		r = xyz[2];
	}
	vPortFree(xyz);
	return (prime + r) % prime;
}


/*
	join_shares() -- join some shares to retrieve the secret
	xy_pairs is array of int pairs, first is x, second is y 
	n is number of pairs submitted
*/

int join_shares(int *xy_pairs, int n) {
	int secret = 0;
	long numerator;
	long denominator;
	long startposition;
	long nextposition;
	long value;
	int i;
	int j;

	// Pairwise calculations between all shares
	for (i = 0; i < n; ++i) {
		numerator = 1;
		denominator = 1;

		for (j = 0; j < n; ++j) {
			if (i != j) {
				startposition = xy_pairs[i * 2];		// x for share i
				nextposition = xy_pairs[j * 2];		// x for share j
				numerator = (numerator * -nextposition) % prime;
				denominator = (denominator * (startposition - nextposition)) % prime;
			}
		}
		value = xy_pairs[i * 2 + 1];
		secret = (secret + (value * numerator * modInverse(denominator))) % prime;
	}
	/* Sometimes we're getting negative numbers, and need to fix that */
	secret = (secret + prime) % prime;
	return secret;
}

int split_data(unsigned char * secret, int len, int n, int t, unsigned char **shares) {
	int i, j;
	//int rtval;
	int letter;
	int *chunks = pvPortMalloc(sizeof(int) * n);
	short **share_ptr = pvPortMalloc(sizeof(short*) * n);
  //short *share_ptr[n];
	for (i = 0; i < n; ++i) {
		*(int *)(shares[i]) = i + 1;
		//*(int *)(shares[i] + sizeof(int)) = len + sizeof (int) * 2;
		*(int *)(shares[i] + sizeof(int)) = len * 2 + sizeof (int) * 2;
		share_ptr[i] = (short *)(shares[i] + sizeof(int) * 2);
	}
	for (i = 0; i < len; ++i) {
		letter = secret[i];
		if (letter < 0) {
			letter = 256 + letter;
		}
		split_number(letter, n, t, chunks);
		for (j = 0; j < n; ++j) {
			//shares[j][i + sizeof(int) * 2] = chunks[j];
			share_ptr[j][i] = chunks[j];
		}
	}
	vPortFree(chunks);
	vPortFree(share_ptr);
	return 0;
}

int join_data(unsigned char ** shares, int n, unsigned char *secret, int *secret_len) {
	int *x = pvPortMalloc(sizeof(int) * n);	// Integer value array
	int i;			// Counter
	int j;			// Counter
	int len;
	int *chunks = pvPortMalloc(sizeof(int)*2*n);
	unsigned char letter;
	short **share_ptr = pvPortMalloc(sizeof(short*)*n);

	if (n == 0) {
		return -1;
	}

	len = *(int *)(shares[0] + sizeof(int));
	len -= sizeof(int) * 2;
	*secret_len = len = len / 2;
	for (i = 0; i < n; ++i) {
		x[i] = *(int *)shares[i];
		share_ptr[i] = (short *)(shares[i] + sizeof(int) * 2);
	}

	for (i = 0; i < len; ++i) {
		for (j = 0; j < n; ++j) {
			chunks[j * 2] = x[j];
			chunks[j * 2 + 1] = share_ptr[j][i];
		}

		letter = join_shares(chunks, n);
		secret[i] = letter;
	}
  vPortFree(x);
	vPortFree(chunks);
	vPortFree(share_ptr);
	return 0;
}

int shamir_get_sharelen(int secret_len) {
	return secret_len * 2 + sizeof(int) * 2;
}

int shamir_recovery_sharelen(unsigned char *one_share)
{
	int share_len;
	if (NULL == one_share) {
		return 0;
	}
	share_len = *(unsigned int *)(one_share + sizeof(unsigned int));
	return share_len;
}

int shamir_split(unsigned char *secret, int len, int share_number, int share_threshold, unsigned char **shares) {
	int rtval;
	rtval = split_data(secret, len, share_number, share_threshold, shares);
	return rtval;
}

int shamir_combine(unsigned char **shares, int share_count, unsigned char *secret, int *secret_len) {
	int rtval;
	rtval = join_data(shares, share_count, secret, secret_len);
	return rtval;
}

/*
void Bprint(char *str,unsigned char *pbuff,unsigned int len)
{
#if 1
	if(NULL != str)
	{
		printf("%s:%d\n",str,len);
	}
	int i=0;
	for(i=0;i<len;i++)
	{
		printf("%02x",pbuff[i]);
		if(i%16 == 15)
			printf("\n");
	}
	printf("\n");
#endif
	return;
}
*/
/*********************************************************************************************************
** o‘那y??3?㏒oShamir_test
** o‘那y?豕那?㏒o2a那?Shamir??﹞“米?1|?邦
** 那?豕?2?那y㏒o?T
** ﹞米???米  ㏒o?T
*********************************************************************************************************/
/*
void Shamir_test()
{
	int g = 0;
	int n = 5;
	int t = 3;
	char secret[200] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
	char shares[10][200];
	char *p[10];// = &shares[0][0];
		
	char secret_out[200];
	int secret_outLen = 0;
	for( g=0; g<10; g++ )
	{
		p[g] = &shares[g][0];
	}
	shamir_split(secret, 16, n, t, p);
	for( g=0; g < n; g++ )
	{
		Bprint(NULL,p[g],34);
	}
	shamir_combine(p, t, secret_out, &secret_outLen);
	Bprint(NULL,secret_out,16);
}	

int main()
{
	Shamir_test();
}
*/

