/***********************************************************************
 * Copyright (c)  2020, beijing shudun Co.,Ltd .
 * All rights reserved.
 * Filename    : config.h
 * Description : config head file
 * Author(s)   : jaime
 * version     : V1.0
 * Modify date : 2020-07-06
 ***********************************************************************/

#ifndef	_USRCONFIG_H_
#define	_USRCONFIG_H_

//#define testsimuiic
#define	ENABLE	1
#define	DISABLE	0

#define testmim		DISABLE
#define	testspiflash DISABLE
#define	testeeprom	DISABLE
#define	testeflash	DISABLE

#define	RELEASE	 1
//#define MCU_VERSION		0x20200928
//#define ARM_FIRMWARE_VERSION		0x01000000//0x20201205

#define	VectTab	0x00			//eflash∆ ºµÿ÷∑
#define	APP_OFFSET	0x0000
#define	FPGA_DATA_TX_ADDR		1000
#define	FPGA_DATA_RX_ADDR		5000
#ifdef	testsimuiic
#include "simu_at24.h"
#endif

#endif
