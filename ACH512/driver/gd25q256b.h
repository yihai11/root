/***********************************************************************
 * Copyright (c)  2008 - 2016, Shanghai AisinoChip Co.,Ltd .
 * All rights reserved.
 * Filename    : gd25q16b.h
 * Description : gd25q16b driver header file
 * Author(s)   : Eric
 * version     : V1.0
 * Modify date : 2016-03-24
 ***********************************************************************/
#ifndef _GD25Q256B_H_
#define _GD25Q256B_H_
#include "common.h"

#define 	gd25q256	
#define SPI_MEM_COM   SPIA

#define 	LOW_ARRAY_SELECTED			write_extended_addr_reg(0)
#define		HIGH_ARRAY_SELECTED			write_extended_addr_reg(0xFF)
//SPI Flash CMD define
#define READ_ID			                    0x90
#define READ     		                    0x03
#define READ_FAST		                    0x0B
#define WRITE_EN		                    0x06
#define WRITE_DISEN		                    0x04
#define READ_STATUS_L                       0x05
#define READ_STATUS_H	                    0x35
#define WRITE_STATUS 	                    0x01
#define ERASE_SECTOR	                    0x20
#define	ERASE_BLOCK												0x52
#define PAGE_PROGRAM	                    0x02
#define QUAD_PAGE_PROGRAM                   0x32

#define DUAL_OUT_FAST_READ                  0x3b
#define QUAD_OUT_FAST_READ                  0x6b

#define DUAL_IO_FAST_READ                   0xbb
#define QUAD_IO_FAST_READ                   0xeb
#define QUAD_IO_WORD_FAST_READ              0xe7

#define WRITE_EXTENDED_ADDR_REGISTER				0xC5

#define HIGH_PER_MODE                       0xA3

#define SECTOR_SHIFT                        12
#define PAGE_SHIFT                          8

#define BCH_SECTOR_SIZE                     4096

#ifdef gd25q16
#define SECTOR_NUM                          512
#endif
#ifdef	gd25q256
#define	SECTOR_NUM													8192
#endif

UINT16 read_id(void);
void flash_erase_sector(UINT32 addr);
void flash_erase_block(UINT32 addr);
void write_extended_addr_reg(UINT8 status);
void flash_page_program(UINT8 *pBuf, UINT32 addr, UINT32 lenth);
void flash_program(UINT8 *pBuf, UINT32 addr, UINT32 lenth);
void flash_read(UINT8 *pbuf, UINT32 addr, UINT32 length);
void flash_page_read_X1(UINT8 *pBuf, UINT32 addr, UINT32 length);

void flash_mem_page_read(UINT8 *pbuf, UINT32 addr, UINT32 length);

#endif


