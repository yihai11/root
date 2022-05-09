/***********************************************************************
 * Copyright (c)  2008 - 2016, Shanghai AisinoChip Co.,Ltd .
 * All rights reserved.
 * Filename    : at24cxx.c
 * Description : at24cxx driver source file
 * Author(s)   : Eric
 * version     : V1.0
 * Modify date : 2016-03-24
 ***********************************************************************/
#include "at24cxx.h"
#include "i2c.h"
#define PRINT_E2P 2
void at24cxx_write_page(UINT16 memory_address, UINT8 *wr_buff, UINT8 length)
{
	UINT8 i, wrbuff[AT24_PAGE_SIZE + 2];

	wrbuff[0] = (UINT8)(memory_address >> 8);
	wrbuff[1] = (UINT8)memory_address;
	for(i = 0; i < length; i++)
	{
		wrbuff[i + 2] = wr_buff[i];
	}
#ifdef I2C_ONEBYTEADDR
    i2c_write_withaddr(0xa0 | (wrbuff[0] << 1), wrbuff + 1, length + 1, 1);
#else
    i2c_write_withaddr(0xa0, wrbuff, length + 2, 1);
#endif
}


/************************************************************************
 * function   : at24cxx_write_bytes
 * Description: at24cxx write bytes
 * input : 
 *         UINT16 memory_address: address
 *         UINT8* wr_buff: write buff
 *         UINT32 length: length
 * return: 
 ************************************************************************/
void at24cxx_write_bytes(UINT16 memory_address, UINT8 *wr_buff, UINT32 length)
{
    UINT32 len; //前面page不对齐的字节数

    len	= (AT24_PAGE_SIZE - memory_address % AT24_PAGE_SIZE); //前面的边界不对齐的部分

    //写完前面边界不对齐的部分数据
    if(len) //首页可以写的字节数
    {
        if(len > length)	  len = length; //首页不能写满
        at24cxx_write_page(memory_address, wr_buff, len);
        delay(200000); //at24cxx write page 需要5ms
        length -= len;
        memory_address += len;
        wr_buff += len;
    }

    while(length > AT24_PAGE_SIZE)//中间页
    {
        at24cxx_write_page(memory_address, wr_buff, AT24_PAGE_SIZE);
        delay(200000); //at24cxx write page 需要5ms
        length -= AT24_PAGE_SIZE;
        memory_address +=	AT24_PAGE_SIZE;
        wr_buff += AT24_PAGE_SIZE;
    }
    if(length)//尾页
    {
        at24cxx_write_page(memory_address, wr_buff, length);
        delay(200000); //at24cxx write page 需要5ms
    }
}


/************************************************************************
* function   : at24cxx_read_bytes
* Description: at24cxx read bytes
* input :
*         UINT16 memory_address: address
*         UINT8 *rd_buff: read data buff
*         INT32 length: length
* return: 
************************************************************************/
void at24cxx_read_bytes(UINT16 memory_address, UINT8 *rd_buff, UINT32 length)
{
    UINT8 wrbuff[2];
    wrbuff[0] = (UINT8)(memory_address >> 8);
    wrbuff[1] = (UINT8)memory_address; 

#ifdef I2C_ONEBYTEADDR
    i2c_write_withaddr(0xa0 | (wrbuff[0] << 1), wrbuff + 1, 1, 0);
    i2c_read_withaddr(0xa1 | (wrbuff[0] << 1), rd_buff, length);
#else
    i2c_write_withaddr(0xa0, wrbuff, 2, 0);
    i2c_read_withaddr(0xa1, rd_buff, length); 
#endif
    
}

uint8_t i2c_test(void)
{
	UINT8 i;
	UINT8 wr_buff[128], rd_buff[128];
	//print(PRINT_E2P,"\r\n-------E2PROM测试开始-------\r\n");
	i2c_init(MASTER_I2C_SPEED);

	for(i = 0; i < 128; i++)
	{
		wr_buff[i] = (UINT8)i;
	}
	//print(PRINT_E2P,"i2c write data\r\n");
	at24cxx_write_bytes(0x08, wr_buff, 128);

	//print(PRINT_E2P,"i2c read data\r\n");
	at24cxx_read_bytes(0x08, rd_buff, 128);

	for(i = 0; i < 128; i++)
	{
			
		if(wr_buff[i] != rd_buff[i])
		{
			print(PRINT_E2P,"test fail: \r\n"); 
            print(PRINT_E2P,"wr_buff[%d]= 0x%x,rd_buff[%d]= 0x%x \r\n", i, wr_buff[i], i, rd_buff[i]);
			return 1;
		}
	}

	//print(PRINT_E2P,"-EEPROM测试成功-\r\n");
	return 0;
}
