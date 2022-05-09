/***********************************************************************
 * Copyright (c)  2020, beijing shudun Co.,Ltd .
 * All rights reserved.
 * Filename    : sram.c
 * Description : sram header file
 * Author(s)   : jaime
 * version     : V1.0
 * Modify date : 2020-7-6
 ***********************************************************************/
 #include "sram.h"
 #include "config.h"
 
 #define	PCIE
/************************************************************************
 * function   : mem_bus_init
 * Description: SRAM or NorFlash initial
 *              Region division register REG_MIM_SEG0 set tft storage area
 *              size. off-chip SRAM chip area form 0K to 256K.
 * input : none
 * return: none
 ************************************************************************/
void mem_bus_init(void)
{
	
//	//lt add
//	#define FPGA_EXT_WATS                     (0x3 << 28)
//	#define FPGA_EXT_WNTS                     (0x3 << 24)
//	#define FPGA_EXT_RATS                     (0x3 << 20)
//	#define FPGA_EXT_AATS                     (0x3 << 15)
//	#define FPGA_EXT_RO                       (0x0 << 14)
//	#define FPGA_EXT_PS_8B                    (0x1 << 13)
//	#define FPGA_EXT_PS_16B                   (0x0 << 13)
//	#define FPGA_EXT_WWS                      (0x7 << 8)
//	#define FPGA_EXT_RWS                      (0x7 << 4)
//	#define FPGA_EXT_CDA                      (0x0 << 3)
//	#define FPGA_EXT_CSEN                     (0x1 << 0)
//	//end add
	
#ifdef LOW_POWER
    enable_module(BIT_MIM); //enable MIM
#endif
	//init mim  gpio
	REG_MIM_TFTS  = 0x02;		//CS2 设置成TFT模式
	REG_SCU_MUXCTRLA = ((REG_SCU_MUXCTRLA & (~(0xfffff000))) | (0xAA66A000));	
	REG_SCU_MUXCTRLB = ((REG_SCU_MUXCTRLB & (~(0x03ffffff))) | (0x02AAAAAA));	//配置cs3管脚	
	REG_SCU_MUXCTRLC = ((REG_SCU_MUXCTRLC & (~(0xfffffC00))) | (0xAAAAA800));	
	REG_SCU_MUXCTRLD = ((REG_SCU_MUXCTRLD & (~(0x033ffff3))) | (0x022AAAA2));	//配置cs1管脚
	
	//CS0---SRAM    CS1---FPGA   CS3---SL811
	REG_MIM_CSCR0 = SRAM_EXT_WATS | SRAM_EXT_WNTS | SRAM_EXT_RATS |  SRAM_EXT_RO \
							| SRAM_EXT_PS_16B | SRAM_EXT_WWS  | SRAM_EXT_RWS  |  SRAM_EXT_CSEN;
	
	REG_MIM_CSCR1 = SRAM_EXT_WATS | SRAM_EXT_WNTS | SRAM_EXT_RATS |  SRAM_EXT_RO \
							| SRAM_EXT_PS_16B | SRAM_EXT_WWS  | SRAM_EXT_RWS  |  SRAM_EXT_CSEN;
	//lt add-----
	//REG_MIM_CSCR1 = FPGA_EXT_WATS | FPGA_EXT_WNTS | FPGA_EXT_RATS | FPGA_EXT_RO \
	//						| FPGA_EXT_PS_16B | FPGA_EXT_WWS | FPGA_EXT_RWS | FPGA_EXT_CSEN;	
	//end add----
	
	REG_MIM_CSCR3 = SRAM_EXT_WATS | SRAM_EXT_WNTS | SRAM_EXT_RATS |  SRAM_EXT_RO 
							| SRAM_EXT_PS_8B  | SRAM_EXT_WWS  | SRAM_EXT_RWS  |  SRAM_EXT_CSEN;
	}

//IS61WVV51216BLL  512K*16bit
//实际为 IS61WVV102416BLL   1024K*16Bit

/***********************************************************************
 * sram_write
 * 输入参数 ：sram_addr: sram中目标地址
 *						write_data: 待写入的数据
 *						length:	写入的数据长度
 * 返回值   ：无
 * 函数功能 ：向指定位置的sram中写入数据
 ***********************************************************************/
void sram_write16(uint32_t sram_addr,uint16_t *write_data,uint32_t length)
{
	//UINT16 *buff16;
	uint32_t i=0;
	//buff16 = (UINT16 *)write_data;
	for(i = 0; i < length; i++)
	{
		MEM0_PORT16(2 * i) = *(write_data+i);
	}
}

/***********************************************************************
 * sram_read8
 * 输入参数 ：sram_addr: sram中目标地址
 *						read_data: 读取的数据
 *						length:	读取的数据长度
 * 返回值   ：无
 * 函数功能 ：读取sram指定位置的数据
 ***********************************************************************/
void sram_read8(uint32_t sram_addr,uint8_t *read_data,uint32_t length)
{
	uint32_t i=0;

	for(i = 0; i < length; i++)
	{
		*(read_data+i) = MEM0_PORT8(i);
	}

}
