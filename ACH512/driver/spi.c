/***********************************************************************
 * Copyright (c)  2008 - 2016, Shanghai AisinoChip Co.,Ltd .
 * All rights reserved.
 * Filename    : spi.c
 * Description : spi driver source file
 * Author(s)   : Eric
 * version     : V1.0
 * Modify date : 2016-03-24
 ***********************************************************************/
#include "spi.h"

#define DUMMY_DATA 0x88

// in this demo, spi interrupt is not used 
void SPIA_IRQHandler(void)
{
    if (REG_SPI_STATUS(SPIA) & (0x01 << 1)) //check batch_done flag
    {
        REG_SPI_STATUS(SPIA) |= (0x01 << 1); //clear batch_done flag
    }
}

// in this demo, spi interrupt is not used 
void SPIB_IRQHandler(void)
{
    if (REG_SPI_STATUS(SPIB) & (0x01 << 1)) //check batch_done flag
    {
        REG_SPI_STATUS(SPIB) |= (0x01 << 1); //clear batch_done flag
    }
}

/************************************************************************
 * function   : spi_init
 * Description: spi initial
 * input :
 *         UINT8 spi_index: select spi number     SPIA,SPIB
 *         UINT8 work_mode: select spi work mode  0,1,2,3
 *         UINT8 ismaster 1:master 0: slaver
 * return: none
 ************************************************************************/
void spi_init(UINT8 spi_index, UINT8 work_mode, UINT8 ismaster)
{
    if(spi_index == SPIA)
    {
#ifdef LOW_POWER
		enable_module(BIT_SPIA);
#endif		
			REG_SCU_MUXCTRLA &= ~(3 << 6);//cs先设为gpio
			REG_SCU_RESETCTRLA |= 1<<13;
			delay(10);
			REG_SCU_RESETCTRLA &= ~(1<<13);
			delay(10);
			NVIC_ClearPendingIRQ(SPIA_IRQn);
			NVIC_EnableIRQ(SPIA_IRQn);

    }
    else
    {
#ifdef LOW_POWER
		enable_module(BIT_SPIB);
#endif		
			REG_SCU_MUXCTRLA &= ~(3 << 28);//cs先设为gpio     
			REG_SCU_RESETCTRLA |= 1<<14;
			delay(10);
			REG_SCU_RESETCTRLA &= ~(1<<14);
			delay(10);			
			NVIC_ClearPendingIRQ(SPIB_IRQn);
			NVIC_EnableIRQ(SPIB_IRQn);

    }

    REG_SPI_CTL(spi_index) = work_mode << 2;

    if (ismaster == 1)
    {
        REG_SPI_CTL(spi_index) |= 1 << 0;//主机模式
        REG_SPI_BAUD(spi_index) = ((4 << 8) | 8); //110M/5*8

        REG_SPI_CTL(spi_index) |= 0x01; //设置为主机模式
        REG_SPI_OUT_EN(spi_index) = 0x01; //默认为单线模式
    }
    else
    {
        REG_SPI_CTL(spi_index) &= ~(1 << 0); //从机模式
        REG_SPI_CTL(spi_index) &= ~0x01; //设置为从机模式
        REG_SPI_OUT_EN(spi_index) = 0x02; //默认单线模式
        REG_SPI_STATUS(spi_index) = REG_SPI_STATUS(spi_index); //clear status
        REG_SPI_IE(spi_index) = 0x02;       //enable batch done int

        REG_SPI_TX_CTL(spi_index) = 0x02; //reset fifo
        REG_SPI_TX_CTL(spi_index) = 0x00;
        REG_SPI_RX_CTL(spi_index) = 0x02; //reset fifo
        REG_SPI_RX_CTL(spi_index) = 0x00;

        REG_SPI_BATCH(spi_index) = 1;
        REG_SPI_RX_CTL(spi_index) = 0x01; //rx_en
        REG_SPI_TX_CTL(spi_index) |= DUMMY_DATA << 8; //dummy = 0x88
    }
		
	if(spi_index == SPIA)
    {
        REG_SCU_MUXCTRLA = (REG_SCU_MUXCTRLA & ~(0xfff << 4)) | (0x551 << 4); //GPIO复用为SPIA
		delay(100);
		REG_SCU_MUXCTRLA = (REG_SCU_MUXCTRLA & ~(0x03 << 6)) | (0x01 << 6); //GPIO3配置为CS0
		REG_SCU_MUXCTRLD = (REG_SCU_MUXCTRLD & (~(0x03 << 28))) | (0x02 << 28);	//GPIO62配置为CS2	
    }
    else
    {
        REG_SCU_MUXCTRLA = (REG_SCU_MUXCTRLA & ~(0x0fUL << 28)) | (0x04 << 28);
        REG_SCU_MUXCTRLB = (REG_SCU_MUXCTRLB & ~(0xff << 0)) | (0x55 << 0); //GPIO复用为SPIB ,MISO和SWDIO复用，先确保可以从boot启动，否则jtag无法用
		delay(100);
		REG_SCU_MUXCTRLA = (REG_SCU_MUXCTRLA & ~(0x03UL << 28)) | (0x01 << 28);//GPIO14配置为CS
    }
}

void chip_disable(UINT8 spi_index)
{
    REG_SPI_CS(spi_index) = 0;
}
void chip_enable(UINT8 spi_index)
{
    REG_SPI_CS(spi_index) = 1;
}

void chip_disable_with_cs(UINT8 spi_index, UINT8 cs_index)
{
	UINT32 reg_value = REG_SPI_CS(spi_index);
    REG_SPI_CS(spi_index) = reg_value & (~(1 << cs_index));
}
void chip_enable_with_cs(UINT8 spi_index, UINT8 cs_index)
{
	UINT32 reg_value = REG_SPI_CS(spi_index);
	REG_SPI_CS(spi_index) = (reg_value & (~(1 << cs_index))) | (1 << cs_index);
}

/************************************************************************
 * function   : spi_rx_bytes
 * Description: spi receive data by general mode
 * input :
 *         UINT8 spi_index: select spi number    SPIA,SPIB
 *         UINT8* rx_data: pointer to receive data buffer
 *         UINT32 len: length of bytes to receive
 * return: none
 ************************************************************************/
void spi_rx_bytes(UINT8 spi_index, UINT8 *rx_data, UINT32 len)
{
    UINT32 i;

    REG_SPI_STATUS(spi_index) |= 0x01 << 1; //clear batch_done flag
    REG_SPI_BATCH(spi_index) = len;

    REG_SPI_RX_CTL(spi_index) |= 0x01; //rx work is enable

    if (REG_SPI_CTL(spi_index) & (0x01 << 0)) //主机模式
    {
        REG_SPI_CS(spi_index) = 1;
    }

    for (i = 0; i < len; i++)
    {
        while (REG_SPI_STATUS(spi_index) & 0x10); //wait rx fifo not empty:RX_FIFO_EMPTY
        *rx_data = (UINT8)REG_SPI_RX_DAT(spi_index);
        rx_data++;
    }

    while (!(REG_SPI_STATUS(spi_index) & 0x02)); //batch done
    REG_SPI_STATUS(spi_index) |= 0x02;

    REG_SPI_RX_CTL(spi_index) &= ~0x01; //close rx work
}
/************************************************************************
 * function   : spi_tx_bytes
 * Description: spi send data by general mode
 * input :
 *         UINT8 spi_index: spi number    SPIA,SPIB
 *         UINT8* tx_data: pointer to send data buffer
 *         UINT32 len: length of bytes to send
 * return: none
 ************************************************************************/
void spi_tx_bytes(UINT8 spi_index, UINT8 *tx_data, UINT32 len)
{
    UINT32 i;
    REG_SPI_STATUS(spi_index) |= 0x02; //clear batch_done flag
    REG_SPI_BATCH(spi_index) = len;

    REG_SPI_TX_CTL(spi_index) |= 0x01; //tx work is enable

    if (REG_SPI_CTL(spi_index) & (0x01 << 0)) //主机模式
    {
        REG_SPI_CS(spi_index) = 1;
    }
    else
    {
        REG_SPI_OUT_EN(spi_index) |= (1<<1);	//MISO dir:out	
    }	

    for (i = 0; i < len; i++)
    {
        while (REG_SPI_STATUS(spi_index) & 0x08); //wait tx fifo not full:TX_FIFO_FULL
        REG_SPI_TX_DAT(spi_index) = *tx_data;
        tx_data++;
    }

    while (!(REG_SPI_STATUS(spi_index) & 0x02)); //Batch_DONE
    REG_SPI_STATUS(spi_index) |= 0x02;

    REG_SPI_TX_CTL(spi_index) &= ~0x01; //close tx work

    if ( !(REG_SPI_CTL(spi_index) & 0x01) ) //从机模式
    {
//        REG_SPI_OUT_EN(spi_index) &= ~(1<<1);	//MISO dir:in,配成输入后,如果从机未准备好数据时从机不会发送dummy,此时主机收到的数据全为0xFF
    }	
}

void spi_rx_bytes_with_cs(UINT8 spi_index, UINT8 cs_index, UINT8 *rx_data, UINT32 len)
{
    UINT32 i;

    REG_SPI_STATUS(spi_index) |= 0x01 << 1; //clear batch_done flag
    REG_SPI_BATCH(spi_index) = len;

    REG_SPI_RX_CTL(spi_index) |= 0x01; //rx work is enable

    if (REG_SPI_CTL(spi_index) & (0x01 << 0)) //主机模式
    {
		chip_enable_with_cs(spi_index, cs_index);
    }

    for (i = 0; i < len; i++)
    {
        while (REG_SPI_STATUS(spi_index) & 0x10); //wait rx fifo not empty:RX_FIFO_EMPTY
        *rx_data = (UINT8)REG_SPI_RX_DAT(spi_index);
        rx_data++;
    }

    while (!(REG_SPI_STATUS(spi_index) & 0x02)); //batch done
    REG_SPI_STATUS(spi_index) |= 0x02;

    REG_SPI_RX_CTL(spi_index) &= ~0x01; //close rx work
}

void spi_tx_bytes_with_cs(UINT8 spi_index, UINT8 cs_index, UINT8 *tx_data, UINT32 len)
{
    UINT32 i;
    REG_SPI_STATUS(spi_index) |= 0x02; //clear batch_done flag
    REG_SPI_BATCH(spi_index) = len;

    REG_SPI_TX_CTL(spi_index) |= 0x01; //tx work is enable

    if (REG_SPI_CTL(spi_index) & (0x01 << 0)) //主机模式
    {
		chip_enable_with_cs(spi_index, cs_index);
    }
    else
    {
        REG_SPI_OUT_EN(spi_index) |= (1<<1);	//MISO dir:out	
    }	

    for (i = 0; i < len; i++)
    {
        while (REG_SPI_STATUS(spi_index) & 0x08); //wait tx fifo not full:TX_FIFO_FULL
        REG_SPI_TX_DAT(spi_index) = *tx_data;
        tx_data++;
    }

    while (!(REG_SPI_STATUS(spi_index) & 0x02)); //Batch_DONE
    REG_SPI_STATUS(spi_index) |= 0x02;

    REG_SPI_TX_CTL(spi_index) &= ~0x01; //close tx work

    if ( !(REG_SPI_CTL(spi_index) & 0x01) ) //从机模式
    {
//        REG_SPI_OUT_EN(spi_index) &= ~(1<<1);	//MISO dir:in,配成输入后,如果从机未准备好数据时从机不会发送dummy,此时主机收到的数据全为0xFF
    }
}
