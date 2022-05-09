#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include "cephes.h"
#include "test.h"
int char_2_dec(char *binstring, int bin_len) // converting binary string to decimal. 
{

	int i;
	int sum = 0;
	int len = bin_len;
	int num = 0;
	for(i=0;i<len;i++)
	{
		num=(int)binstring[i] - '0';
		sum=sum + (pow(2, len-i-1)*num);
	}
	return sum;
}


int char_2_bin(char input, char *output) // char to binary string. 
{

	int i = 0;
	int bit = 0;

	for(i=0;i<8;++i)
	{
		bit=((input>>i)&1);
		output[7-i]=bit + '0';  
	}

	return 0;
}

int poker_test(unsigned int M, unsigned char *test_buff, unsigned int buff_len)
{
	int i;
	int n;
	int k;
	int num;
	int loop_limit;
	int ctr_array_size;
	int ctr_array[256];
	char temp_cpy[8];
	char *original_str;
	double pow_val = 0.0;
	double pow_div = 0.0;
	double X3 = 0.0;
	double P_value;

	if (M < 2 || M > 8)
	{
		return -1;
	}

	if (buff_len > 2048)
	{
		return -1;
	}

	n = buff_len * 8;
	k = floor(n / M);
	loop_limit = n - (n % M);

	original_str = pvPortMalloc(n);
	if (original_str == NULL)
	{
		return -1;
	}
	for (i = 0; i < buff_len; i++)
	{
		char_2_bin(test_buff[i], original_str + i * 8);
	}

	ctr_array_size = pow(2, M);
	memset(ctr_array, 0, sizeof(int) * 256);

	for(i = 0; i < n; i += M)
	{
		memset(temp_cpy, 0, M);
		if (i < loop_limit)
		{
			memcpy(temp_cpy, original_str + i, M);
			num = char_2_dec(temp_cpy, M);
			ctr_array[num] += 1;
		}
		else
		{
			break;
		}
	}

	for(i = 0; i < ctr_array_size; i++)
	{
		pow_val += pow(ctr_array[i], 2);
	}

	pow_div = ((pow(2, M) * pow_val) / (double)k);
	X3 = pow_div - k;
	P_value = cephes_igamc((pow(2, M) - 1) / 2, X3 / 2);

	vPortFree(original_str);

	if(P_value > 0.01)
	{
		return 0;
	}
	else
	{
		return -1;
	}
}
