#ifndef _MYFILE_H_
#define	_MYFILE_H_


#include "ff.h"
#include "diskio.h"
#include "SL811Disk.h"

#define FF_DEBUG
FRESULT FATFS_init(	BYTE drv);
void testfatfs(void);
void fpga_pro_fromusb(void);
void SaveDataFromUsb(void);
FRESULT FAT_init(USHORT mkfs_permission);
FRESULT USB_init(USHORT mkfs_permission);
void fpga_pro_fromflash(void);
#endif