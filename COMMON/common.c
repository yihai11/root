/***********************************************************************
 * Copyright (c)  2008 - 2016, Shanghai AisinoChip Co.,Ltd .
 * All rights reserved.
 * Filename    : common.c
 * Description : conmmon source file
 * Author(s)   : Eric  
 * version     : V1.0
 * Modify date : 2016-03-24
 ***********************************************************************/
#include "common.h"
#include "uart.h"
#ifdef DEBUG
UINT8 BUG_DATA[BUG_DATA_SIZE]={"               \r\n"};
#endif

#define YEAR ((((__DATE__ [7] - '0') * 10 + (__DATE__ [8] - '0')) * 10 \
    + (__DATE__ [9] - '0')) * 10 + (__DATE__ [10] - '0'))

#define MONTH (__DATE__ [2] == 'n' ? (__DATE__ [1] == 'a' ? 1 : 6) \
    : __DATE__ [2] == 'b' ? 2 \
    : __DATE__ [2] == 'r' ? (__DATE__ [0] == 'M' ? 3 : 4) \
    : __DATE__ [2] == 'y' ? 5 \
    : __DATE__ [2] == 'l' ? 7 \
    : __DATE__ [2] == 'g' ? 8 \
    : __DATE__ [2] == 'p' ? 9 \
    : __DATE__ [2] == 't' ? 10 \
    : __DATE__ [2] == 'v' ? 11 : 12)

#define DAY ((__DATE__ [4] == ' ' ? 0 : __DATE__ [4] - '0') * 10 \
    + (__DATE__ [5] - '0'))


uint32_t FPGA_FLAG;  //1: fpga reset signal

UINT8 BUG_DATA_EN = 0;
char HSMD1_CHIP1_VAILD;  //0x01:表示芯片使能，0表示芯片无效
char HSMD1_CHIP2_VAILD;
char HSMD1_CHIP3_VAILD;
char HSMD1_CHIP4_VAILD;
char HSMD1; //(HSMD1_CHIP1_VAILD | HSMD1_CHIP2_VAILD<<1 | HSMD1_CHIP3_VAILD<<2 | HSMD1_CHIP4_VAILD<<3)

void get_version(char * sver,uint32_t tver)
{
	char *p = sver;
	memcpy(p,MCU_V_NAME,10);
	sprintf(p+10,"%x",tver>>4);
	sprintf(p+16,"%d",YEAR*10000+MONTH*100+DAY);
	p[11]=p[13]=p[15]='.';
	p[24]=0;
}

void delay_ms(uint16_t xms)
{
 
	uint16_t i,j;
 
	for(i=xms;i>0;i--)
 
		for(j=0;j<15000;j++);
}

void delay_us(uint16_t xus)
{
 
	uint16_t i,j;
 
	for(i=xus;i>0;i--)
 
		for(j=0;j<15;j++);
}

//#ifdef DEBUG
/************************************************************************
 * function   : printf_buff_byte
 * Description: printf data block by byte
 * input :
 *         UINT8* buff: buff
 *         UINT32 length: byte length
 * return: none
 ************************************************************************/
void printf_buff_byte(UINT8* buff, UINT32 length)
{
	UINT32 i;

	for(i=0;i<length;i++)
	{
		print(PRINT_COM,"%.2x ",buff[i]);
		if ((i + 1) % 32 == 0)
		{
			print(PRINT_COM,"\r\n");
		}
	}
	print(PRINT_COM,"\r\n");
}

/************************************************************************
 * function   : str_printf
 * Description: printf data block by str
 * input :
 *         UINT8* buff: buff
 *         UINT32 length: byte length
 * return: none
 ************************************************************************/
void dug_printf(UINT8* buff, UINT32 length)
{
	UINT32 i;//,*pHeap;
	
	//for(i=0;i<sizeof(UINT32);i++)
	//outbyte(DEBUG_UART, *pHeap++);
	for(i=0;i<length;i++)
	{
		if (buff[i] == 0) break;
		outbyte(DEBUG_UART, buff[i]);
		
	}
}
/************************************************************************
 * function   : printf_buff_word
 * Description: printf data block by word
 * input :
 *         UINT8* buff: buff
 *         UINT32 length: word length
 * return: none
 ************************************************************************/
void printf_buff_word(UINT32* buff, UINT32 length)
{
	UINT32 i;

	for(i=0;i<length;i++)
	{
		print(PRINT_COM,"%.8x ",buff[i]);
	}
	print(PRINT_COM,"\r\n");
}
//#endif

void delay(UINT32 count)
{
    while(count--);
}

//一个字内大小端转换
void reverse_DWORD(UINT32 *var)
{
    UINT8 *P = (UINT8 *)var;
    UINT8 tmp;

    tmp = P[0];
    P[0] = P[3];
    P[3] = tmp;
    tmp = P[1];
    P[1] = P[2];
    P[2] = tmp;
}

//整批数据前后大小端转换
void reverse_memory(UINT8 *buff, UINT32 length)
{
    UINT8 temp;
    UINT8 *buff_start = buff;
    UINT8 *buff_end = buff + length - 1;

    while(buff_end > buff_start)
    {
        temp = *buff_start;
        *buff_start++ = *buff_end;
        *buff_end-- = temp;
    }
}

