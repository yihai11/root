/***********************************************************************
 * Copyright (c)  2008 - 2016, Shanghai AisinoChip Co.,Ltd .
 * All rights reserved.
 * Filename    : i2c.h
 * Description : i2c driver header file
 * Author(s)   : Eric
 * version     : V1.0
 * Modify date : 2016-03-24
 ***********************************************************************/
#ifndef __I2C_H__
#define __I2C_H__
#include "common.h"

//speed
//#define MASTER_I2C_SPEED 100000	   //Standard-mode
#define   MASTER_I2C_SPEED   400000  //Fast-mode
//#define MASTER_I2C_SPEED 1000000 //Fast-mode Plus


extern volatile UINT8 flag_i2c_read_done_int;
extern volatile UINT8 flag_i2c_write_done_int;
extern volatile UINT8 flag_i2c_fifo_int;

/************************************************************************
 * function   : i2c_init
 * Description: i2c initial
 * input : sclclk
 * return: none
 ************************************************************************/
void i2c_init(UINT32 sclclk);

/************************************************************************
 * function   : i2c_write_byte
 * Description: i2c write byte
 * input :
 *         UINT8 txd: byte of write
 * return: none
 ************************************************************************/
void i2c_write_byte(UINT8 txd);
/************************************************************************
 * function   : i2c_read_byte
 * Description: i2c read byte
 * input : none
 * return: UINT8 -- byte of read
 ************************************************************************/
UINT8 i2c_read_byte(void);
/************************************************************************
 * function   : i2c_write_withaddr
 * Description: i2c write with address
 * input :
 *         UINT8 slave_addr: slave address
 *         UINT8* txdata: tx data
 *         UINT8 datalen: data lenth
 *         UINT8 dostop:
 * return: none
 ************************************************************************/
void i2c_write_withaddr(UINT8 slave_addr, UINT8 *txdata, UINT8 datalen, UINT8 dostop);
/************************************************************************
 * function   : i2c_read_withaddr
 * Description: i2c read with address
 * input :
 *         UINT8 slave_addr: slave address
 *         UINT8* rxdata: rx data
 *         UINT8 datalen: data lenth
 * return: none
 ************************************************************************/
void i2c_read_withaddr(UINT8 slave_addr, UINT8 *rxdata, UINT8 datalen);

#endif

