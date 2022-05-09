/***********************************************************************
 * Copyright (c)  2008 - 2016, Shanghai AisinoChip Co.,Ltd .
 * All rights reserved.
 * Filename    : app.h
 * Description : application example header file
 * Author(s)   : Eric
 * version     : V1.0
 * Modify date : 2016-03-24
 ***********************************************************************/
#ifndef _DEMO_SPIFLASH_H_
#define _DEMO_SPIFLASH_H_
#include "common.h"

extern UINT32 g_data_buf[];
#define DATABUF             ((UINT8 *)g_data_buf)

void spim_test(void);

#endif

