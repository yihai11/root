/***********************************************************************
 * Copyright (c)  2020, beijing shudun Co.,Ltd .
 * All rights reserved.
 * Filename    : spiflash.c
 * Description : spiflash source file
 * Author(s)   : jaime
 * version     : V1.0
 * Modify date : 2020-7-6
 ***********************************************************************/
#include  "spiflash.h"
#include  "spi.h"
#include  "gd25q256b.h"
#define PRINT_FLASH 2
#define SPIID		0xc818

#define 	PAGE_SIZE      256
#define		SEC_SIZE			4096

uint8_t GD25_BUFF[SEC_SIZE];//	 __attribute__((at(0x60100000)));


//文件系统用
void spiflash_read(UINT8 *pBuf, UINT32 addr, UINT32 length)
{
   flash_read(pBuf, addr, length);
}


//写spiflash  (支持自动分包，不可以跨高低16M地址)
void flash_page_program_auto(UINT8 *pBuf, UINT32 addr, UINT32 length)
{
	uint32_t i=0;
	if(addr>=0x1000000)		//extened addr
		HIGH_ARRAY_SELECTED;
	else
		LOW_ARRAY_SELECTED;
	for(;(length-i)>0;){
		if(length-i > 256){
			i+=256;
			flash_erase_sector(addr);
//			if(addr>=0x1000000)		//extened addr
//				HIGH_ARRAY_SELECTED;
//			else
//				LOW_ARRAY_SELECTED;
			flash_page_program(pBuf, addr, 256);
			addr+=256;
		}
		else{
			flash_erase_sector(addr);
			/*
			if(addr>=0x1000000)		//extened addr
				HIGH_ARRAY_SELECTED;
			else
				LOW_ARRAY_SELECTED;*/
			flash_page_program(pBuf, addr, length-i);
			i=length;
		}
	}
		LOW_ARRAY_SELECTED;
}


//读spiflash (支持高16M读)
void flash_page_read_extend(UINT8 *pBuf, UINT32 addr, UINT32 length)
{	
	if(addr>=0x1000000)		//extened addr		
		HIGH_ARRAY_SELECTED;
	flash_read(pBuf, addr, length);
	LOW_ARRAY_SELECTED;
}

int spi_testid(void)
{
	UINT16 id;
	//spi_init(SPI_MEM_COM, WORK_MODE_3, SPI_MASTER);
	//spi_init(SPI_MEM_COM, WORK_MODE_3, SPI_MASTER);
	id = read_id();
	//print(PRINT_TEST,"Flas ID = 0x%x \r\n", id);
	if (id != 0xc818){
		//print(PRINT_TEST,"read ID err\r\n");
		return -1;
	}
	return 0;
}

void fatfs_GD25_read(uint8_t* pBuffer,uint32_t ReadAddr,uint16_t NumByteToRead)
{
	uint16_t i =0;
	for(i=0;i <= (NumByteToRead-512);i+=512)
		spiflash_read(pBuffer+i, ReadAddr+i,512);
	if(NumByteToRead-i)
		spiflash_read(pBuffer+i, ReadAddr+i,NumByteToRead-i);
}
void fatfs_GD25_write(uint8_t* pBuffer,uint32_t WriteAddr,uint16_t NumByteToWrite)
{
	uint32_t sec_position = 0;
	uint16_t sec_offset = 0;
	uint16_t sec_remain =0 ;
 	uint16_t i=0;
	uint8_t * buff = GD25_BUFF;
	
 	sec_position=WriteAddr/SEC_SIZE;//扇区地址  
	sec_offset=WriteAddr%SEC_SIZE;//在扇区内的偏移
	sec_remain=4096-sec_offset;//扇区剩余空间大小   
 	if(NumByteToWrite<=sec_remain)
		sec_remain=NumByteToWrite;//不大于4096个字节
	
	while(1) 
	{	
		fatfs_GD25_read(buff,sec_position*4096,4096);//读出整个扇区的内容
		for(i=0;i<sec_remain;i++)//校验数据
			if(buff[sec_offset+i]!=0XFF)break;//需要擦除
		
//		if(i<sec_remain){			//需要擦除
//			
			flash_erase_sector(sec_position*4096);		//擦除这个扇区
			
			for(i=0;i<sec_remain;i++)	   		//复制
				buff[i+sec_offset]=pBuffer[i];	
//			memcpy(sec_offset+buff,pBuffer,sec_remain);
			flash_program(buff,sec_position*4096, 4096);
//			for(i=0;i<4096;i+=256){
////				if(sec_remain-i >= 256)
//					flash_page_program(buff+i,WriteAddr+i,256);
//				else
//					flash_page_program(buff+i,WriteAddr+i,sec_remain-i);
//			}
//		}
		
//		else								//无需擦除		
//			flash_program(buff,WriteAddr,sec_remain);
			
		if(NumByteToWrite==sec_remain)
			break;				//写入结束
		else{						//写入未结束
			sec_position++;	//扇区地址增1
			sec_offset=0;		//偏移位置为0 	 
			
		  pBuffer+=sec_remain;  				//指针偏移
			WriteAddr+=sec_remain;				//写地址偏移	   
		  NumByteToWrite-=sec_remain;		//字节数递减
			if(NumByteToWrite>4096)
				sec_remain=4096;						//下一扇区写不完
			else 
				sec_remain=NumByteToWrite;	//下一扇区可以写完
		}	 
	}
}
UINT32 g_data_buf[1024+512];
#define DATABUF             ((UINT8 *)g_data_buf)
#define write_buff  DATABUF
#define read_buff   (DATABUF+512)
#define temp_buff   (DATABUF+1024)
//SPI 访问SPI NOR FLASH测试函数,包括单线写与单线读

uint8_t spim_nflash_all_x1(void)
{
	UINT16 id;
	UINT32 sector_cnt;
	UINT32 page_cnt;

	UINT32 addr;
	UINT32 i;

	//spi_init(SPI_MEM_COM, WORK_MODE_3, SPI_MASTER);

	id = read_id();

	//printfS("Flas ID = 0x%x\r\n", id);
	if (id != 0xc818)
	{
		print(PRINT_FLASH,"read ID is fail!\r\n");
		return ID_ERROR;
	}

	
	for(sector_cnt = 0; sector_cnt<512; sector_cnt++)
	{
		if (sector_cnt != 0 && sector_cnt != 256 && sector_cnt != 511)
		{
			continue;
		}
			
		page_cnt = 0;

		for (i = 0; i < PAGE_SIZE; i++)
		{
			write_buff[i] = i;
			read_buff[i] = 0;
		}

		addr = (sector_cnt << SECTOR_SHIFT);
		flash_erase_sector(addr);

		//printfS("erase ok\r\n");

		for (page_cnt = 0; page_cnt < (BCH_SECTOR_SIZE / PAGE_SIZE); page_cnt++)
		{
			addr = (sector_cnt << SECTOR_SHIFT) | (page_cnt << PAGE_SHIFT);

			//printfS("addr = %x\r\n", addr);

			flash_page_read_X1(temp_buff, addr, PAGE_SIZE);  //备份数据
			flash_page_program(write_buff, addr, PAGE_SIZE); //单线写操作
			flash_page_read_X1(read_buff, addr, PAGE_SIZE);  //单线读
			flash_page_program(temp_buff, addr, PAGE_SIZE);  //恢复数据

			for (i = 0; i < PAGE_SIZE; i++)
			{
				if (write_buff[i] != read_buff[i])
				{
					print(PRINT_FLASH,"sector= %d,Page = %d Test Fail\r\n", sector_cnt, page_cnt);
					print(PRINT_FLASH,"writebuff[%d]= 0x%x,readbuff[%d]= 0x%x \r\n", i, write_buff[i], i, read_buff[i]);
					return WR_ERROR;
				}
			}
			//printf("sector= %d,Page = %d Test pass\r\n", sector_cnt, page_cnt);
		}
	}
	return 0;
}
