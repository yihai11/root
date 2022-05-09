#ifndef _MAIN_H_
#define	_MAIN_H_

#include "gd25q256b.h"
#include "spi.h"
#include "sram.h"
#include "spiflash.h"
#include "i2c.h"
#include "at24cxx.h"
#include "SL811_usb.h"
#include "gpio.h"
#include "eflash.h"
#include "SL811.h"
#include "SL811disk.h"
#include "at24cxx.h"
#include "ukey_oper.h"
#include "diskio.h"
#include "ff.h"
#include "fatfs_file.h"
#include "misc.h"
#include "cipher.h"
#include "user_manage.h"
#include "devmanage.h"
#include "interface.h"
#include "spiflash_addr.h"
#include "fpga.h"
#include "fpga_sm3.h"

#define  RTOS

//OSœ‡πÿ head file
#ifdef	RTOS
#include "FreeRTOS.h"
#include "portable.h"
#include "task.h"
#include "queue.h"
#include "semphr.h"
#include "timers.h"

#endif

#include "test.h"

void SetVectorTable(uint32_t vecttab,uint32_t offset);

#endif
