/***********************************************************************
 * Copyright (c)  2008 - 2016, Shanghai AisinoChip Co.,Ltd .
 * All rights reserved.
 * Filename    : eflash.c
 * Description : eflash driver source file
 * Author(s)   : Eric  
 * version     : V1.0
 * Modify date : 2016-03-24
 ***********************************************************************/
#include  "eflash.h"

#define PAGE_SIZE		            512

#define SN_BASE_ADDR      ( EFlashNVR2BaseAddr + 0x08 )  //SN base addr

#define LOT_ID_ADDR       ( EFlashNVR2BaseAddr + 0x08 )  //LOT ID
#define WAFER_ID_ADDR     ( EFlashNVR2BaseAddr + 0x0C )  //Wafer ID
#define DIE_LOC_Y_ADDR    ( EFlashNVR2BaseAddr + 0x10 )  //DIE LOC Y
#define DIE_LOC_X_ADDR    ( EFlashNVR2BaseAddr + 0x12 )  //DIE LOC X
#define DATE_DAY_ADDR     ( EFlashNVR2BaseAddr + 0x14 )  //DATE_DAY
#define DATE_MONTH_ADDR   ( EFlashNVR2BaseAddr + 0x15 )  //DATE_MONTH
#define DATE_YEAR_ADDR    ( EFlashNVR2BaseAddr + 0x16 )  //DATE_YEAR
#define SN_CRC_ADDR       ( EFlashNVR2BaseAddr + 0x18 )  //SN CRC value

#define PRINT_EFLASH 2
void	WriteIllegalMark(void)
{
	eflash_erase_page(ILLEGAlMARK_ADDR);
	eflash_write_word(ILLEGAlMARK_ADDR,ILLEGALMASK);
}
void eflash_erase_total_page(uint16_t start_page,uint16_t page_quantity)
{
	uint32_t	addr;
	uint16_t page_i=0;
	addr=EFlashMainBaseAddr+start_page*PAGE_SIZE;
	for(;page_i<page_quantity;page_i++){
		eflash_erase_page(addr);
		addr+=PAGE_SIZE;
	}
}
void eflash_write(uint32_t addr,uint8_t * data,uint32_t length)
{
//	uint32_t databuff[PAGE_SIZE/4];
//	uint32_t data_i=0;
	uint16_t startpage=0,pagequantity=0;
	//备份数据
//	for(;data_i<length;data_i++)
//		databuff[data_i]= eflash_read_word(addr+4*data_i);
	//擦除数据
	startpage=(addr- EFlashMainBaseAddr)/PAGE_SIZE;
	pagequantity=(addr+length+PAGE_SIZE-1)/PAGE_SIZE-startpage;		//+PAGE_SIZE-1 实现进一法
	eflash_erase_total_page(startpage,pagequantity);
	//新数据插入原数据
	//eflash_write_word(addr, );
//	addr-PAGE_SIZE*(startpage+1)
	//写入eflash
}


/*----------------------------SN--------------------------------*/
//CRC16-CCITT校验算法
#define CRC_INIT	0xffff	  //在CRC16-CCITT标准中reg_init = 0xffff
UINT16 do_crc(UINT32 addr, UINT32 len, UINT16 crc_init)
{
    UINT32 i, j;
    UINT16 crc_reg;      //reg for calculate CRC value
    UINT16 current;

    crc_reg = crc_init;  //initial value for CRC16-CCITT, GOOD_CRC = 0xf0b8
    for(i = 0; i < len; i++)
    {
        current = *(volatile UINT8 *)(addr + i);
        for(j = 0; j < 8; j++)
        {
            if((crc_reg ^ current) & 0x0001) crc_reg = (crc_reg >> 1) ^ 0x8408;  //CRC16-CCITT的生成多项式是	0x1021,将0x1021按位颠倒后为：0x8408
            else crc_reg >>= 1;
            current >>= 1;
        }
    }
    return crc_reg;
}

UINT16 check_crc_sn(void)
{
    UINT16 crc_value = 0;
    UINT16 crc_count = 0;
    UINT32 temp;
    temp = (*(volatile UINT32 *)(SN_CRC_ADDR));
    crc_value = temp & 0xFFFF;
    temp  = (~temp) >> 16;
    if(temp != crc_value)
    {
        return 0xFFFF;   //CRC 未写入
    }
    else
    {
        crc_count = do_crc(SN_BASE_ADDR, 16, CRC_INIT);
        if(crc_count == crc_value)    return 0;             //CRC OK
        else    return crc_count;     //CRC fail
    }

}

/************************************************************************
 * function   : read_sequence
 * Description: read unique SN（16bytes）
 * input :
 *         UINT8 * buff：SN buff pointer
                        buff[0:3]:   	LOT ID  
                        buff[4:7]:   	WaferID
                        buff[8:9]:   	DieLocY 
                        buff[10:11]: 	DieLocX 
                        buff[12]: 		Day
                        buff[13]:    	Month
						buff[14:15]:    Year      
 * return: 0：CRC pass， 
           1：CRC fail
 ************************************************************************/
UINT16 read_sequence(UINT8 *buff)
{
    UINT32 i = 0;
    UINT32 temp;
    UINT8 *p;
    p = (UINT8 *)SN_BASE_ADDR;
    for(i = 0; i < 16; i++)
    {
        *buff++ = *p++;
    }
    //check SN crc
    temp = check_crc_sn();
    return temp;
}

/************************************************************************
 * function   : read_UID
 * Description: read unique SN（8bytes）
 * input :
 *         UINT8 * buff：SN buff pointer
                        buff[0:3]:   LOT ID  BYTE0~3 
                        buff[4]:     WaferID BYTE0
                        buff[5]:	 DieLocY BYTE0
                        buff[6]:	 DieLocX BYTE0
                        buff[7]:	 Month       
 * return: 0：CRC pass， 
           1：CRC fail
 ************************************************************************/
UINT16 read_UID(UINT8 *buff)
{
    UINT32 temp = 0;
    temp =  (*(volatile UINT32 *)(LOT_ID_ADDR));
    buff[0] = temp;
    buff[1] = temp >> 8;
    buff[2] = temp >> 16;
    buff[3] = temp >> 24;

    temp =  (*(volatile UINT8 *)(WAFER_ID_ADDR));
    buff[4] = temp;

    temp =  (*(volatile UINT16 *)(DIE_LOC_Y_ADDR));
    buff[5] = temp;
    temp =  (*(volatile UINT16 *)(DIE_LOC_X_ADDR));
    buff[6] = temp;

    temp =  (*(volatile UINT8 *)(DATE_MONTH_ADDR));
    buff[7] = temp;

    //check SN crc
    temp = check_crc_sn();
    return temp;
}

// test code

void SN_test(void)
{
	UINT8 chip_sn[16];
	UINT8 chip_UID[8];
	UINT32 temp=0;

	print(PRINT_EFLASH,"-RD chip sn 16 bytes-\r\n");
	temp=read_sequence(chip_sn);   
	if(temp) print(PRINT_EFLASH,"SN CRC fail\r\n");

	print(PRINT_EFLASH,"SN(16bytes): \r\n");
//	printfB8(chip_sn,16);

	print(PRINT_EFLASH,"-end-\r\n");

	
	print(PRINT_EFLASH,"-RD chip UID 8 bytes-\r\n");
	temp=read_UID(chip_UID);
	if(temp) print(PRINT_EFLASH,"SN CRC fail\r\n");

	print(PRINT_EFLASH,"UID(8bytes): \r\n");
//	printfB8(chip_UID,8);

	print(PRINT_EFLASH,"-end-\r\n");


	print(PRINT_EFLASH,"LOT_ID  = A%d \r\n", chip_sn[0]+(chip_sn[1]<<8)+(chip_sn[2]<<16)+(chip_sn[3]<<24) );	
	print(PRINT_EFLASH,"WAFER_ID= %d \r\n", chip_sn[4]);
	print(PRINT_EFLASH,"DIE ADDR= (%d,%d) \r\n", chip_sn[10]+(chip_sn[11]<<8),chip_sn[8]+(chip_sn[9]<<8));
	print(PRINT_EFLASH,"DATE= %d.%d.%d \r\n", (chip_sn[14]+(chip_sn[15]<<8)),chip_sn[13], chip_sn[12] );
}


uint8_t  eflash_page_erase_test(UINT32 base_addr)
{
    UINT32 page, start_page, end_page, addr, i, result;

    start_page = 1;
    end_page = 2;

    for(page = start_page; page < end_page; page++)
    {
        addr = base_addr + page * PAGE_SIZE;

#ifdef ROM_DRIVER_FLASH
        eflash_erase_page(addr);//rom里面的页擦除没有返回值
#else
        if(eflash_erase_page(addr))//如果返回1，则擦除校验错误
        {
            print(PRINT_EFLASH,"page Erase Verify Err\r\n");
            return;
        }
#endif

        for(i = 0; i < (PAGE_SIZE / 4); i++)
        {
            result = eflash_read_word(addr);
            if(result != (*(volatile UINT32 *)(SM_FLASH_FF_VALUE_ADDR)))	//0xFF字节被加密
			//if(result != 0xffffffff)
            {
                print(PRINT_EFLASH,"page Erase Err: addr= 0x%x, res= 0x%x \r\n", addr, result);
                return 1;
            }
     
            addr += 4;
        }
		 //print(PRINT_EFLASH,"\r\npage Erase Pass, page = %d\r\n", page);
     }
		 return 0;
}       


void eflash_write_read_test(UINT32 base_addr, UINT32 value)
{
    UINT32 page, start_page, end_page, addr, i, result;

    print(PRINT_EFLASH,"write/read test value= 0x%x \r\n", value);

    start_page = 1000;
    end_page = 1024;

    for(page = start_page; page < end_page; page++)
    {
        addr = base_addr + page * PAGE_SIZE;
        eflash_erase_page(addr);
        for(i = 0; i < (PAGE_SIZE / 4); i++)
        {

#ifdef ROM_DRIVER_FLASH
            eflash_write_word(addr, value);
#else 
            if(eflash_write_word(addr, value))
            {
                print(PRINT_EFLASH,"write word ver Err\r\n");
                return; 
            }        
#endif

            result = eflash_read_word(addr);
            if(result != value)
            {
                print(PRINT_EFLASH,"WE/word err: addr= 0x%x, res 0x%x \r\n", addr, result);
                return;
            }
            result = eflash_read_halfword(addr);
            if(result != (value & 0xffff))
            {
                print(PRINT_EFLASH,"WE/halfword err: addr= 0x%x, res 0x%x \r\n", addr, result);
                return;
            }
            result = eflash_read_byte(addr);
            if(result != (value & 0xff))
            {
                print(PRINT_EFLASH,"WE/byte err: addr= 0x%x, res 0x%x \r\n", addr, result);
                return;
            }
            addr += 4;
        }
        print(PRINT_EFLASH,"WR Test Pass, page = %d\r\n", page);
    }
}


#ifndef ROM_DRIVER_FLASH
/************************************************************************
 * function   : eflash_write_word
 * Description: eflash write word
 * input : 
 *         UINT32 addr: address
 *         UINT32 value: value
 * return: 0--success   1--fail
 ************************************************************************/
UINT8 eflash_write_word(UINT32 addr, UINT32 value)
{

    UINT8 vf;
    REG_EFC_CTRL |= EFC_WRITE_MODE;
#ifdef EFLASH_VERIFY_EN
    REG_EFC_CTRL |= EFC_PROGRAM_VRI_EN;
#endif
    REG_EFC_SEC = 0x55AAAA55;
    *((volatile UINT32 *)(addr)) = value;
    while(!(REG_EFC_STATUS & 0x01));
    REG_EFC_CTRL &= ~EFC_WRITE_MODE;
    vf = 0;

#ifdef EFLASH_VERIFY_EN	
	while(!(REG_EFC_INTSTATUS & (0x01 << 4)));
	REG_EFC_INTSTATUS = (0x01 << 4);
    if(REG_EFC_INTSTATUS & (0x01 << 6)) //vf error
    {
        REG_EFC_INTSTATUS = (0x01 << 6);
        vf = 1;
    }
	REG_EFC_CTRL &= ~EFC_PROGRAM_VRI_EN;
#endif

    return vf;
}

/************************************************************************
 * function   : eflash_erase_page
 * Description: eflash erase page
 * input : 
 *         UINT32 page_addr: page address
 * return: 0--success   1--fail
 ************************************************************************/
UINT8 eflash_erase_page(UINT32 page_addr)
{
    UINT8 vf;

    REG_EFC_CTRL |= EFC_PAGE_ERASE_MODE;
    REG_EFC_SEC = 0x55AAAA55;
    *((volatile UINT32 *)(page_addr)) = 0;
    while(!(REG_EFC_STATUS & 0x01));
    REG_EFC_CTRL &= ~EFC_PAGE_ERASE_MODE;
    vf = 0;

#ifdef EFLASH_VERIFY_EN
    REG_EFC_ADCT = (page_addr) >> 2;
    REG_EFC_CTRL |= EFC_ERASE_VRI_EN;
    while(!(REG_EFC_INTSTATUS & (0x01 << 4)));
	REG_EFC_INTSTATUS = (0x01 << 4);
    if(REG_EFC_INTSTATUS & (0x01 << 3)) //vf error
    {
        REG_EFC_INTSTATUS = (0x01 << 3);
        vf = 1;
    }
#endif

    return vf;
}
#endif

