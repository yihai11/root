/***********************************************************************
 * Copyright (c)  2020, beijing shudun Co.,Ltd .
 * All rights reserved.
 * Filename    : spiflash.h
 * Description : spiflash header file
 * Author(s)   : jaime
 * version     : V1.0
 * Modify date : 2020-7-6
 ***********************************************************************/
#ifndef _SPIFLASH_H_
#define	_SPIFLASH_H_
#include "common.h"

#define ID_ERROR	1
#define	WR_ERROR	2

int spi_testid(void);
void fatfs_GD25_write(uint8_t* pBuffer,uint32_t WriteAddr,uint16_t NumByteToWrite);
void fatfs_GD25_read(uint8_t* pBuffer,uint32_t ReadAddr,uint16_t NumByteToRead);
void spiflash_read(UINT8 *pBuf, UINT32 addr, UINT32 length);
void flash_page_program_auto(UINT8 *pBuf, UINT32 addr, UINT32 lenth);
void flash_page_read_extend(UINT8 *pBuf, UINT32 addr, UINT32 length);
uint8_t spim_nflash_all_x1(void);
#endif
