/***********************************************************************
 * Copyright (c)  2008 - 2016, Shanghai AisinoChip Co.,Ltd .
 * All rights reserved.
 * Filename    : app.c
 * Description : application example source file
 * Author(s)   : Eric
 * version     : V1.0
 * Modify date : 2016-03-24
 ***********************************************************************/
#include  "demo_spiflash.h"
#include  "spi.h"
#include  "gd25q16b.h"

UINT32 g_data_buf[1024];


#define write_buff  DATABUF
#define read_buff   (DATABUF+512)

//SPI 访问SPI NOR FLASH测试函数,包括单线写与单线读
void spim_nflash_x1(void)
{
	UINT16 id;
	UINT32 sector_cnt;
	UINT32 page_cnt;

	UINT32 addr;
	UINT32 i;

	printfS("---------SPIM X1 test start!-------\n");

	spi_init(SPI_MEM_COM, WORK_MODE_3, SPI_MASTER);

	id = read_id();

	printfS("Flas ID = 0x%x\n", id);
	if (id != 0xc814)
	{
		printfS("read ID is fail!\n");
		return;
	}

	sector_cnt = 0;
	page_cnt = 0;

	for (i = 0; i < PAGE_SIZE; i++)
	{
		write_buff[i] = i;
		read_buff[i] = 0;
	}

	addr = (sector_cnt << SECTOR_SHIFT);
	flash_erase_sector(addr);

	printfS("erase ok\n");

	for (page_cnt = 0; page_cnt < (BCH_SECTOR_SIZE / PAGE_SIZE); page_cnt++)
	{
		addr = (sector_cnt << SECTOR_SHIFT) | (page_cnt << PAGE_SHIFT);

		printfS("addr = %x\n", addr);

		flash_page_program_X1(write_buff, addr, PAGE_SIZE); //单线写操作

		flash_page_read_X1(read_buff, addr, PAGE_SIZE); //单线读

		for (i = 0; i < PAGE_SIZE; i++)
		{
			if (write_buff[i] != read_buff[i])
			{
				printfS("sector= %d,Page = %d Test Fail\n", sector_cnt, page_cnt);
				printfS("writebuff[%d]= 0x%x,readbuff[%d]= 0x%x \n", i, write_buff[i], i, read_buff[i]);
				return;
			}
		}
		printfS("sector= %d,Page = %d Test pass\n", sector_cnt, page_cnt);
	}
	printfS("---------SPIM X1 test finished!-------\n\n");
}

//SPI 访问SPI NOR FLASH测试函数,包括单线写与双线读
void spim_nflash_x2(void)
{
	UINT16 id;
	UINT32 sector_cnt;
	UINT32 page_cnt;
	UINT32 addr;
	UINT32 i;

	printfS("---------SPIM X2 test start!-------\n");

	spi_init(SPI_MEM_COM, WORK_MODE_3, SPI_MASTER);

	id = read_id();
	printfS("Flas ID = 0x%x\n", id);

	if (id != 0xc814)
	{
		printfS("read ID is fail!\n");
		return;
	}

	sector_cnt = 0;
	page_cnt = 0;

	for (i = 0; i < PAGE_SIZE; i++)
	{
		write_buff[i] = i;
		read_buff[i] = 0;
	}

	addr = (sector_cnt << SECTOR_SHIFT);
	flash_erase_sector(addr);
	printfS("erase ok\n");

	for (page_cnt = 0; page_cnt < (BCH_SECTOR_SIZE / PAGE_SIZE); page_cnt++)
	{
		addr = (sector_cnt << SECTOR_SHIFT) | (page_cnt << PAGE_SHIFT);
		printfS("addr = %x\n", addr);

		flash_page_program_X1(write_buff, addr, PAGE_SIZE); //单线写操作
		flash_page_read_X2(read_buff, addr, PAGE_SIZE); //双线读

		for (i = 0; i < PAGE_SIZE; i++)
		{
			if (write_buff[i] != read_buff[i])
			{
				printfS("sector= %d,Page = %d Test Fail\n", sector_cnt, page_cnt);
				printfS("writebuff[%d]= 0x%x,readbuff[%d]= 0x%x \n", i, write_buff[i], i, read_buff[i]);
				return;
			}
		}
		printfS("sector= %d,Page = %d Test pass\n", sector_cnt, page_cnt);
	}
	printfS("---------SPIM test finished!-------\n\n");
}

//SPI 访问SPI NOR FLASH测试函数,包括四线写与四线读
void spim_nflash_x4(void)
{
	UINT16 id;
	UINT32 sector_cnt;
	UINT32 page_cnt;
	UINT32 addr;
	UINT32 i;

	printfS("---------SPIM X4 test start!-------\n");

	spi_init(SPI_MEM_COM, WORK_MODE_3, SPI_MASTER);

	id = read_id();
	printfS("Flas ID = 0x%x\n", id);

	if (id != 0xc814)
	{
		printfS("read ID is fail!\n");
		return;
	}

	sector_cnt = 0;
	page_cnt = 0;

	for (i = 0; i < PAGE_SIZE; i++)
	{
		write_buff[i] = i;
		read_buff[i] = 0;
	}

	addr = (sector_cnt << SECTOR_SHIFT);
	flash_erase_sector(addr);
	printfS("erase ok\n");

	for (page_cnt = 0; page_cnt < (BCH_SECTOR_SIZE / PAGE_SIZE); page_cnt++)
	{
		addr = (sector_cnt << SECTOR_SHIFT) | (page_cnt << PAGE_SHIFT);
		printfS("addr = %x\n", addr);

		flash_page_program_X4(write_buff, addr, PAGE_SIZE); //四线写操作
		flash_page_read_X4(read_buff, addr, PAGE_SIZE); //四线读

		for (i = 0; i < PAGE_SIZE; i++)
		{
			if (write_buff[i] != read_buff[i])
			{
				printfS("sector= %d,Page = %d Test Fail\n", sector_cnt, page_cnt);
				printfS("writebuff[%d]= 0x%x,readbuff[%d]= 0x%x \n", i, write_buff[i], i, read_buff[i]);
				return;
			}
		}
		printfS("sector= %d,Page = %d Test pass\n", sector_cnt, page_cnt);
	}

	printfS("---------SPIM test finished!-------\n\n");
}

void spi_testid(void)
{
	UINT16 id;

	spi_init(SPI_MEM_COM, WORK_MODE_3, SPI_MASTER);
	id = read_id();
	printfS("Flas ID = 0x%x\n", id);

	if (id != 0xc814)
	{
		printfS("read ID is fail!\n");
		return;
	}

}

void spim_test(void)
{
	
	spi_testid();
	spim_nflash_x1(); //SPI 访问SPI NOR FLASH测试函数,单线写与单线读
	spim_nflash_x2(); //SPI 访问SPI NOR FLASH测试函数,单线写与双线读
	spim_nflash_x4(); //SPI 访问SPI NOR FLASH测试函数,四线写与四线读
}

