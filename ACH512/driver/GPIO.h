/***********************************************************************
 * Copyright (c)  2008 - 2016, Shanghai AisinoChip Co.,Ltd .
 * All rights reserved.
 * Filename    : gpio.h
 * Description : gpio driver header file
 * Author(s)   : Eric
 * version     : V1.0
 * Modify date : 2016-03-24
 ***********************************************************************/
#ifndef __GPIO_H__
#define __GPIO_H__

#include  "common.h"
#define GPIO_KEY 30

#define BIT0	                    (1<<0)
#define BIT1	                    (1<<1)
#define BIT2	                    (1<<2)
#define BIT3	                    (1<<3)
#define BIT4	                    (1<<4)
#define BIT5	                    (1<<5)
#define BIT6	                    (1<<6)
#define BIT7	                    (1<<7)
#define BIT8	                    (1<<8)
#define BIT9	                    (1<<9)
#define BIT10	                    (1<<10)
#define BIT11	                    (1<<11)
#define BIT12	                    (1<<12)
#define BIT13	                    (1<<13)
#define BIT14	                    (1<<14)
#define BIT15	                    (1<<15)
#define BIT16	                    (1<<16)
#define BIT17	                    (1<<17)
#define BIT18	                    (1<<18)
#define BIT19	                    (1<<19)
#define BIT20	                    (1<<20)
#define BIT21	                    (1<<21)
#define BIT22	                    (1<<22)
#define BIT23	                    (1<<23)
#define BIT24	                    (1<<24)
#define BIT25	                    (1<<25)
#define BIT26	                    (1<<26)
#define BIT27	                    (1<<27)
#define BIT28	                    (1<<28)
#define BIT29	                    (1<<29)
#define BIT30	                    (1<<30)
#define BIT31	                    (1UL<<31)
#define BIT(num)                    (1UL<<(num))

#define GPIO_DIR_IN  	            0
#define GPIO_DIR_OUT  	            1
#define GPIO_IS_EDGE                0
#define GPIO_IS_LEVEL               1
#define GPIO_IBE_SINGLE             0
#define GPIO_IBE_DOUBLE             1
#define GPIO_IEV_DOWN_LOW	        0
#define GPIO_IEV_UP_HIGH            1


//清除安全序列
#define	RESTORE_PIN		63
//PFGA_PLL检测
#define FPGA_BACK1		41
#define FPGA_BACK2		29
#define FPGA_RST		32
//开盖检测
#define	DETECT_PIN		30
#define DETECT_FLAG		0xA5A5
extern volatile UINT8 flag_gpioa_int;
extern volatile UINT8 flag_gpiob_int;


/************************************************************************
 * function   : gpio_init
 * Description: gpio initial
 * input : none
 * return: none
 ************************************************************************/
void gpio_init(void);
void gpio_config(uint8_t gpio_pin,uint8_t direction);
void gpio_set(uint8_t gpio_pin);
void gpio_clr(uint8_t gpio_pin);
uint8_t gpio_state(uint8_t gpio_pin);
void Key_Configuration(void);

#endif

