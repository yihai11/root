/***********************************************************************
 * Copyright (c)  2020, beijing shudun Co.,Ltd .
 * All rights reserved.
 * Filename    : sram.h
 * Description : sram header file
 * Author(s)   : jaime
 * version     : V1.0
 * Modify date : 2020-7-6
 ***********************************************************************/
#ifndef _SRAM_H_
#define	_SRAM_H_

#include "ach512.h"
#include "common.h"

#define TFT_WATS                          (7 << 28)
#define TFT_WNTS                          (7 << 24)
#define TFT_RATS                          (7 << 20)
#define TFT_AATS                          (3 << 15)
#define TFT_RO                            (0 << 14)
#define TFT_PS_8B                         (3 << 12)
#define TFT_PS_16B                        (1 << 12)
#define TFT_PS_32B                        (0 << 12)
#define TFT_WWS                           (15 << 8)
#define TFT_RWS                           (15 << 4)
#define TFT_CDA                           (0 << 3)
#define TFT_CSEN                          (1 << 0)

#define SRAM_EXT_WATS                     (7 << 28)
#define SRAM_EXT_WNTS                     (7 << 24)
#define SRAM_EXT_RATS                     (7 << 20)
#define SRAM_EXT_AATS                     (3 << 15)
#define SRAM_EXT_RO                       (0 << 14)
#define SRAM_EXT_PS_8B                    (1 << 13)
#define SRAM_EXT_PS_16B                   (0 << 13)
#define SRAM_EXT_WWS                      (15 << 8)
#define SRAM_EXT_RWS                      (15 << 4)
#define SRAM_EXT_CDA                      (0 << 3)
#define SRAM_EXT_CSEN                     (1 << 0)

#define SRAM_EXT_CSDIS										(0 << 0)

//SRAM
#define MEM0_PORT32(addr)             (*(volatile UINT32*)(MIM_MEM_ADDR(EMEM0) + addr))
#define MEM0_PORT16(addr)             (*(volatile UINT16*)(MIM_MEM_ADDR(EMEM0) + addr))
#define MEM0_PORT8(addr)              (*(volatile UINT8* )(MIM_MEM_ADDR(EMEM0) + addr))
//FPGA
#define MEM1_PORT32(addr)             (*(volatile UINT32*)(MIM_MEM_ADDR(EMEM1) + addr))
#define MEM1_PORT16(addr)             (*(volatile UINT16*)(MIM_MEM_ADDR(EMEM1) + addr))
#define MEM1_PORT8(addr)              (*(volatile UINT8* )(MIM_MEM_ADDR(EMEM1) + addr))
//SL811HS
#define MEM2_ADD              				(*(volatile UINT8* )MIM_MEM_ADDR(EMEM2))
	
void mem_bus_init(void);
void sram_write16(uint32_t sram_addr,uint16_t *write_data,uint32_t length);
void sram_read8(uint32_t sram_addr,uint8_t *read_data,uint32_t length);

#endif
