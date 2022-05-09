/***********************************************************************
 * Copyright (c)  2008 - 2016, Shanghai AisinoChip Co.,Ltd .
 * All rights reserved.
 * Filename    : i2c.c
 * Description : i2c driver source file
 * Author(s)   : Eric
 * version     : V1.0
 * Modify date : 2016-03-24
 ***********************************************************************/
#include  "i2c.h"

//使用的硬件iic，如果使用过程中出现不稳定现象更换成软件iic

volatile UINT8 flag_i2c_read_done_int;
volatile UINT8 flag_i2c_write_done_int;
volatile UINT8 flag_i2c_fifo_int;

void I2C_IRQHandler(void)
{

    UINT32 i2c_int_staus;
    i2c_int_staus = REG_I2C_INT_STAT;

    if((i2c_int_staus & 0x01) == 0x01)
    {
        //I2C_READ_DONE
        flag_i2c_read_done_int = 1;
        REG_I2C_INT_CLR = 0x01;
    }
    if((i2c_int_staus & 0x02) == 0x02)
    {
        //I2C_WRITE_DONE
        flag_i2c_write_done_int = 1;
        REG_I2C_INT_CLR = 0x02;
    }
    if((i2c_int_staus & 0x04) == 0x04)
    {
        //I2C_FIFO_OVERUNDERFLOW
        flag_i2c_fifo_int = 1;
        REG_I2C_INT_CLR = 0x04;
    }
    //	REG_I2C_INT_CLR = 0x07;
}
/************************************************************************
 * function   : i2c_init
 * Description: i2c initial
 * input : sclclk
 * return: none
 ************************************************************************/
void i2c_init(UINT32 sclclk)
{
#ifdef LOW_POWER
    enable_module(BIT_I2C); //enable I2C
#endif
    REG_SCU_MUXCTRLC = (REG_SCU_MUXCTRLC & ~(0x0f << 6)) | (0x05 << 6);//配置SDA，SCL复用管脚
	
    REG_I2C_CLK_DIV = PClock / (16 * sclclk) - 1;
    REG_I2C_FIFO_CTRL = 0x01; //clear the fifo status
    REG_I2C_CSR = 0;

    NVIC_ClearPendingIRQ(I2C_IRQn);
    NVIC_EnableIRQ(I2C_IRQn);

}

/************************************************************************
 * function   : i2c_write_byte
 * Description: i2c write byte
 * input :
 *         UINT8 txd: byte of write
 * return: none
 ************************************************************************/
void i2c_write_byte(UINT8 txd)
{

    REG_I2C_CSR = (1 << 10) | (1 << 12); //I2C_START_WR
    REG_I2C_FIFO = txd;    // write fifo
    while((REG_I2C_FIFO_CTRL & 0x02) != 0x02); //wait for fifo empty:FIFO_EMPTY
}
/************************************************************************
 * function   : i2c_read_byte
 * Description: i2c read byte
 * input : none
 * return: UINT8 -- byte of read
 ************************************************************************/
UINT8 i2c_read_byte(void)
{
    UINT8 rxd;
    REG_I2C_CSR = (1 << 8); //I2C_START_READ
    while(REG_I2C_FIFO_CTRL & 0x02); //wait for fifo not empty:FIFO_EMPTY
    rxd = REG_I2C_FIFO; //read fifo
    return rxd;
}
/************************************************************************
 * function   : i2c_write_withaddr
 * Description: i2c write with address
 * input :
 *         UINT8 slave_addr: slave address
 *         UINT8* txdata: tx data
 *         UINT8 datalen: data lenth
 *         UINT8 dostop:
 * return: none
 ************************************************************************/
void i2c_write_withaddr(UINT8 slave_addr, UINT8 *txdata, UINT8 datalen, UINT8 dostop)
{
    UINT8 i;
    REG_I2C_FIFO_CTRL = 0x01;
    REG_I2C_SLAVE_ADDR = slave_addr;

    REG_I2C_CSR =  ((1 << 10) | (datalen));
    if(dostop == 1)
    {
        REG_I2C_CSR |= (1 << 11);
    }
    REG_I2C_CSR |=  (1 << 12);

    for(i = 0; i < datalen; i++)
    {
        while((REG_I2C_FIFO_CTRL & 0x04) == 0x04); //wait fifo not full:FIFO_FULL
        REG_I2C_FIFO = txdata[i];
    }

    while((REG_I2C_INT_STAT_RAW & 0x02) != 0x02); //wait for write done
    REG_I2C_INT_CLR = 0x02;
    REG_I2C_CSR = 0;
}
/************************************************************************
 * function   : i2c_read_withaddr
 * Description: i2c read with address
 * input :
 *         UINT8 slave_addr: slave address
 *         UINT8* rxdata: rx data
 *         UINT8 datalen: data lenth
 * return: none
 ************************************************************************/
void i2c_read_withaddr(UINT8 slave_addr, UINT8 *rxdata, UINT8 datalen)
{
    UINT8 i;
    REG_I2C_FIFO_CTRL = 0x01;
    REG_I2C_SLAVE_ADDR = slave_addr;

    REG_I2C_CSR = (0x01 << 9) | (0x01 << 11) | datalen;

    for(i = 0; i < datalen; i++)
    {
        while((REG_I2C_FIFO_CTRL & 0x02) == 0x02); //wait for fifo not empty:FIFO EMPTY
        rxdata[i] = REG_I2C_FIFO;
    }
    while((REG_I2C_INT_STAT_RAW & 0x01) != 0x01); //wait for read done
    REG_I2C_INT_CLR = 0x01;
    REG_I2C_CSR = 0;
}
