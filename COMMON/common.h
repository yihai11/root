/***********************************************************************
 * Copyright (c)  2008 - 2016, Shanghai AisinoChip Co.,Ltd .
 * All rights reserved.
 * Filename    : common.h
 * Description : common header file
 * Author(s)   : Eric  
 * version     : V1.0
 * Modify date : 2016-03-24
 ***********************************************************************/

#ifndef __COMMON_H__
#define __COMMON_H__

#include  "stdio.h"	   //printf .....
#include  "string.h"   //strlen ,memset,strcmp,memcmp,strcpy .....
#include  "types.h"
#include  "config.h"
#include  "ach512.h"
//#include  "uart.h"

#define SWAP(x)             ((((x) & 0xFF) << 8) | (((x) >> 8) & 0xFF))
#define max(a, b)		    (((a) > (b)) ? (a) : (b))
#define min(a, b)		    (((a) < (b)) ? (a) : (b))
#define FPGA_RESET 1
#define FPGA_NORMAL 0

#define BUG_DATA_SIZE 2048
#define BUG_START 16

#define PRINT_COM 2
#ifdef DEBUG
extern UINT8 BUG_DATA[BUG_DATA_SIZE];
#endif
extern UINT8 BUG_DATA_EN;
#define LOG_LEVEL 2
#define PRINT_LEVEL 2
#define print(level, ...) {\
    if (level >= LOG_LEVEL)  \
      BUG_DATA_EN = 1; \
    else \
      BUG_DATA_EN = 0; \
    if (level >= PRINT_LEVEL)\
      printf(__VA_ARGS__); \
	}
/************************************************************************
 * function   : printf_buff_byte
 * Description: printf data block by byte
 * input :
 *         UINT8* buff: buff
 *         UINT32 length: byte length
 * return: none
 ************************************************************************/
void printf_buff_byte(UINT8* buff, UINT32 length);

/************************************************************************
 * function   : printf_buff_word
 * Description: printf data block by word
 * input :
 *         UINT8* buff: buff
 *         UINT32 length: word length
 * return: none
 ************************************************************************/
void printf_buff_word(UINT32* buff, UINT32 length);
void dug_printf(UINT8* buff, UINT32 length);
void delay(UINT32 count);
void reverse_DWORD(UINT32 *var);
void reverse_memory(UINT8 *buff, UINT32 length);
void delay_ms(uint16_t xms);
void delay_us(uint16_t xus);
void get_version(char * sver,uint32_t tver);
extern uint32_t FPGA_FLAG;

#endif

