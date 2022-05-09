/***********************************************************************
 * Copyright (c)  2008 - 2016, Shanghai AisinoChip Co.,Ltd .
 * All rights reserved.
 * Filename    : at24cxx.h
 * Description : at24cxx driver header file
 * Author(s)   : Eric
 * version     : V1.0
 * Modify date : 2016-03-24
 ***********************************************************************/
#ifndef __AT24CXX_H__
#define __AT24CXX_H__
#include "common.h"

#define AT24C64			//256page  32B per page

#if defined(AT24C02)
	#define I2C_ONEBYTEADDR
	#define AT24_PAGE_SIZE    8
#elif defined(AT24C04) || defined(AT24C08) || defined(AT24C16)
	#define I2C_ONEBYTEADDR
	#define AT24_PAGE_SIZE    16
#elif defined(AT24C32) || defined(AT24C64)
	//#define I2C_TWOBYTEADDR
	#define AT24_PAGE_SIZE    32
#elif defined(AT24C128) || defined(AT24C256)
	//#define I2C_TWOBYTEADDR
	#define AT24_PAGE_SIZE    64
#endif




/************************************************************************
 * function   : at24cxx_writebytes
 * Description: at24cxx write bytes
 * input : 
 *         UINT16 memory_address: address
 *         UINT8* wr_buff: write buff
 *         UINT32 length: length
 * return: 
 ************************************************************************/
void at24cxx_write_bytes(UINT16 memory_address, UINT8 *wr_buff, UINT32 length);

/************************************************************************
* function   : at24cxx_readbytes
* Description: at24cxx read bytes
* input :
*         UINT16 memory_address: address
*         UINT8 *rd_buff: read data buff
*         UINT32 length: length
* return: 
************************************************************************/
void at24cxx_read_bytes(UINT16 memory_address, UINT8 *rd_buff, UINT32 length);


uint8_t i2c_test(void);
#endif

