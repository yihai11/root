/***********************************************************************
 * Copyright (c)  2008 - 2016, Shanghai AisinoChip Co.,Ltd .
 * All rights reserved.
 * Filename    : spi.h
 * Description : spi driver header file
 * Author(s)   : Eric
 * version     : V1.0
 * Modify date : 2016-03-24
 ***********************************************************************/
#ifndef _SPI_H_
#define _SPI_H_

#include  "common.h"

//#define SPI_MASTER

#define WORK_MODE_0  0
#define WORK_MODE_1  1
#define WORK_MODE_2  2
#define WORK_MODE_3  3

#define SPI_MASTER   1
#define SPI_SLAVER   0


void spi_init(UINT8 spi_index, UINT8 work_mode, UINT8 ismaster);

void chip_disable(UINT8 spi_index);
void chip_enable(UINT8 spi_index);

void chip_disable_with_cs(UINT8 spi_index, UINT8 cs_index);
void chip_enable_with_cs(UINT8 spi_index, UINT8 cs_index);

/************************************************************************
 * function   : spi_rx_bytes
 * Description: spi receive data by general mode
 * input :
 *         UINT8 spi_index: select spi number    SPIA,SPIB
 *         UINT8* rx_data: pointer to receive data buffer
 *         UINT32 len: length of bytes to receive
 * return: none
 ************************************************************************/
void spi_rx_bytes(UINT8 spi_index, UINT8 *rx_data, UINT32 len);
/************************************************************************
 * function   : spi_tx_bytes
 * Description: spi send data by general mode
 * input :
 *         UINT8 spi_index: spi number    SPIA,SPIB
 *         UINT8* tx_data: pointer to send data buffer
 *         UINT32 len: length of bytes to send
 * return: none
 ************************************************************************/
void spi_tx_bytes(UINT8 spi_index, UINT8 *tx_data, UINT32 len);


void spi_rx_bytes_with_cs(UINT8 spi_index, UINT8 cs_index, UINT8 *rx_data, UINT32 len);
void spi_tx_bytes_with_cs(UINT8 spi_index, UINT8 cs_index, UINT8 *tx_data, UINT32 len);

#endif

