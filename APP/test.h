#ifndef __TEST_H__
#define	__TEST_H__
#include "main.h"
#include "common.h"
#include <math.h>
#include "cephes.h"
#include "fatfs_file.h"
#include "ff.h"
#include "devmanage.h"
#include "SL811disk.h"
#include "at24cxx.h"
#include "eflash.h"
#include "spiflash.h"
#include "SL811.h"
#include "task.h"
#include "gd25q256b.h"
#include "sram.h"
#include "SL811_usb.h"
enum STATE
{
 START=0,
 RETRY,
 VALID,
 INVALID,
 END
};

FRESULT fatfs_write_test(	FIL* fp);
FRESULT fatfs_read_test(FIL* fp,void* buff);
FRESULT fatfs_test(FIL* fp,void* buff);
void power_on_test(MCUSelfCheck* test_result);
int power_on_testsm1FPGA(void);
int power_on_testsm1(void);
int mcu_testsm2enc(void);
int mcu_testsm2ver(void);
int mcu_testsm2exchange(void);
int power_on_testsm2mcu(void);
int power_on_testsm2enc(void);
int power_on_testsm2ver(void);
int power_on_testsm2exchange(void);
int power_on_testspiflash(void);
int power_on_testsram(void);
int power_on_testsm4(void);
int power_on_testsm4FPGA(void);
int power_on_testras(void);
int power_on_testshaX(void);
int power_on_testaes(void);
int power_on_testdes(void);
int power_on_testsm3(void);
int FPGAsetgetkey(void);
uint32_t mem_test(void);
int RandomCyclicalTest(void);

int security_task(void);
int eeprom_task(void);
int eflash_task(void);
int spiflash_task(void );
int MIM_task(void);
int USB_enum_task(void);
int SL811_task(void);
int FPGA_task(void);
void Run_Test_task(void);
void printTag(uint8_t state,uint8_t error,const char * str);
int mcu_testsm2_pair(SM2PublicKey *pkA, SM2PrivateKey *skA);
#endif
