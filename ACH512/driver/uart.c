/***********************************************************************
 * Copyright (c)  2008 - 2016, Shanghai AisinoChip Co.,Ltd .
 * All rights reserved.
 * Filename    : uart.c
 * Description : uart driver source file
 * Author(s)   : Eric  
 * version     : V1.0
 * Modify date : 2016-03-24
 ***********************************************************************/
#include "uart.h"
//#include "main.h"
#include "devmanage.h"
#include "FreeRTOS.h"
#include "queue.h"
#include "at24cxx.h"
#ifdef RTOS
extern xSemaphoreHandle	UARTMutexSemaphore;
#endif
#define PRINT_UART 2
volatile UINT8 tx_flag = 0;
volatile UINT8 rx_flag = 0;
volatile UINT8 rx_count = 0;
static UINT32 bug_i = BUG_START;
extern MCUSelfCheck DevSelfCheck;
UINT8 uart_rx_buf[10];
//xQueueHandle	uartQueue;

volatile UINT8 rx_time_out_flag = 0;
//volatile UINT32 uart_rx_buf[2000];
volatile UINT32 uart_length = 0;
volatile UINT8 *tx_ptr;
#ifdef CHECK
#define USART_REC_LEN 	2000
#else
#define USART_REC_LEN 	20
#endif
#define USART_ISR_FE		(1U << 7)
#define USART_ISR_PE		(1U << 8)
#define USART_ISR_BE		(1U << 9)
#define USART_ISR_OE		(1U << 10)
#define RESET						0
#define USART_ISR_RXI		(1U << 4)
#define USART_ISR_RXFE	(1U << 4)

typedef struct
{
	volatile uint8_t  UART_RX_BUF[USART_REC_LEN];     //接收缓冲,最大USART_REC_LEN个字节.
	uint16_t RxWrite;			            //接收缓冲区写指针 
	uint16_t RxRead;			            //接收缓冲区读指针
	uint16_t RxCount;			            //还未读取的新数据个数 
} uart_t;

static uart_t UART1;


//void UARTA_IRQHandler(void)
//{
//	UINT32 temp;
//	static portBASE_TYPE xHigherPriorityTaskWoken;
//	BaseType_t pdresult;
//	temp = REG_UART_RIS(UARTA);
//	//temp = REG_UART_MIS(UARTA);
//	if(temp & 0x10)       // Rx int
//	{
//		while((REG_UART_FR(UARTA) & 0x10) != 0x10)  //read the DR ential Rx fifo  empty
//		{
//			uart_rx_buf[rx_count] = REG_UART_DR(UARTA);
//			if(uart_rx_buf[rx_count]==0x0A){
//				pdresult=xQueueSendFromISR(uartQueue,uart_rx_buf,&xHigherPriorityTaskWoken);
//				memset(uart_rx_buf,0,10*sizeof(UINT8));
//				rx_count=0;
//				portYIELD_FROM_ISR(xHigherPriorityTaskWoken);
//			}
//			else{
//			 rx_count++;
//			 if(rx_count>9){
//					print(PRINT_UART,"reput\r\n");
//					at24cxx_read_bytes(UKEY_DATA_ADDR,(uint8_t*)&DevSelfCheck.des, 4);
//				  rx_count=0;
//			 }
//		 }
//		}
//	}
//	else if(temp & 0x20)  // Tx int
//	{
//		if((REG_UART_FR(UARTA) & 0x80) == 0x80)  //Tx fifo empty
//		{
//			tx_flag = 1;
//		}
//	}
//	else
//	{
//		REG_UART_ICR(UARTA) = 0xfff; //clear int
//	}
//}
void UARTA_IRQHandler(void)
{
	
	uint32_t isrflags   = REG_UART_RIS(UARTA);//READ_REG(UART1_Handler.Instance->ISR);
	uint32_t frits			= REG_UART_FR(UARTA);
  //uint32_t cr3its     = READ_REG(UART1_Handler.Instance->CR3);
  uint32_t errorflags;

// #if SYSTEM_SUPPORT_OS	 	//使用OS
// 	OSIntEnter();
// #endif
  errorflags = (isrflags & (uint32_t)(USART_ISR_PE | USART_ISR_FE | USART_ISR_BE | USART_ISR_OE));
  if (errorflags == RESET)
  {
		REG_UART_ICR(UARTA) |= (1 << 4);
    /* UART in mode Receiver ---------------------------------------------------*/
    if(((isrflags & USART_ISR_RXI) != RESET) && ((frits & USART_ISR_RXFE) == RESET))
    {
			UART1.UART_RX_BUF[UART1.RxWrite] = (uint8_t)(REG_UART_DR(UARTA));
			//printf("UART1.UART_RX_BUF[UART1.RxWrite] = %d \n",UART1.UART_RX_BUF[UART1.RxWrite]);
			if (++UART1.RxWrite >= USART_REC_LEN){
				UART1.RxWrite = 0;
				}
			if (UART1.RxCount < USART_REC_LEN){
				UART1.RxCount++;
			}else{   //丢弃旧数据
				UART1.RxRead++;
			}
			if (UART1.RxRead >= USART_REC_LEN){
				UART1.RxRead = 0;
			}
    }
  }
  else//exception interrupt handle
  {
  		//printf("uart err\r\n");
  	  /* UART parity error interrupt occurred -------------------------------------*/
  		if((isrflags & USART_ISR_PE) != RESET)
      {
        REG_UART_ICR(UARTA) = USART_ISR_PE;
      }
      /* UART frame error interrupt occurred --------------------------------------*/
  		if((isrflags & USART_ISR_FE) != RESET)
      {
        REG_UART_ICR(UARTA) = USART_ISR_FE;
      }
      /* UART noise error interrupt occurred --------------------------------------*/
      if((isrflags & USART_ISR_BE) != RESET)
      {
        REG_UART_ICR(UARTA) = USART_ISR_BE;
      }
      /* UART Over-Run interrupt occurred -----------------------------------------*/
      if((isrflags & USART_ISR_OE) != RESET)
      {
        REG_UART_ICR(UARTA) = USART_ISR_OE;
      }
			
	}
	NVIC_ClearPendingIRQ(UARTA_IRQn);//清除中断
}

void UARTB_IRQHandler(void)
{
	UINT32 temp;

	temp = REG_UART_RIS(UARTB);

	if(temp & 0x10)       // Rx int
	{
		while((REG_UART_FR(UARTB) & 0x10) != 0x10)  //read the DR ential Rx fifo  empty
		{
			uart_rx_buf[rx_count] = REG_UART_DR(UARTB);
			rx_count++;
			rx_flag = 1;
		}
	}
	else if(temp & 0x20)  // Tx int
	{
		if((REG_UART_FR(UARTB) & 0x80) == 0x80)  //Tx fifo empty
		{
			tx_flag = 1;
		}
	}
	else
	{
		REG_UART_ICR(UARTB) = 0xfff; //clear int
	}
}

/************************************************************************
 * function   : uart_set_baud_rate
 * Description: uart set baud rate
 * input : 
 *         UINT32 uart_index: Serial port number
 *         UINT32 cpu_mhz: cpu frequency
 *         UINT32 baud_rate: Series rate
 * return: none
 ************************************************************************/
void uart_set_baud_rate(UINT32 uart_index, UINT32 clk_hz, UINT32 baud_rate)
{
	UINT32 temp, divider, remainder, fraction;

	temp = 16 * baud_rate;
	divider = clk_hz / temp;
	remainder =	clk_hz % temp;
	temp = 1 + (128 * remainder) / temp;
	fraction = temp / 2;

	REG_UART_IBRD(uart_index) = divider + (fraction >> 6);
	REG_UART_FBRD(uart_index) = fraction & 0x3f;
}
/************************************************************************
 * function   : uart_init
 * Description: uart initial for uart_index, cpu_mhz, baud_rate
 * input : 
 *         UINT32 uart_index: Serial port number
 *         UINT32 baud_rate: Series rate
 * return: none
 ************************************************************************/
void uart_init(UINT32 uart_index, UINT32 baud_rate)
{
	UINT32 uart_clk_hz;

	if(uart_index == UARTA)
	{
#ifdef LOW_POWER
		enable_module(BIT_UARTA); //enable UARTA
#endif
		uart_clk_hz = PClock;
		REG_SCU_MUXCTRLA = ((REG_SCU_MUXCTRLA & (~(0x0f << 0)))) | (0x05 << 0); //复用成UARTA
		NVIC_ClearPendingIRQ(UARTA_IRQn);
		NVIC_EnableIRQ(UARTA_IRQn);
	}
	else
	{
#ifdef LOW_POWER
		enable_module(BIT_UARTB); //enable UARTB
#endif
		uart_clk_hz = SRCClock / (((REG_SCU_CLKDIV >> 24) & 0x0f) + 1); //默认为5分频
		REG_SCU_MUXCTRLC = ((REG_SCU_MUXCTRLC & (~(0x0f << 18)))) | (0x05 << 18); //复用成UARTB

#ifdef UARTB_USE_RTSMODE
		REG_SCU_MUXCTRLC = ((REG_SCU_MUXCTRLC & (~(0x03 << 24)))) | (0x01 << 24);
		REG_UART_CR(UARTB) |= (1 << 14);
#endif
#ifdef UARTB_USE_CTSMODE
		REG_SCU_MUXCTRLC = ((REG_SCU_MUXCTRLC & (~(0x03 << 22)))) | (0x01 << 22);
		REG_UART_CR(UARTB) |= (1 << 15);
#endif
		NVIC_ClearPendingIRQ(UARTB_IRQn);
		NVIC_EnableIRQ(UARTB_IRQn);
	}

	tx_flag = 0;
	rx_flag = 0;

	REG_UART_CR(uart_index) &= ~0x01;            //disable uart
	uart_set_baud_rate(uart_index, uart_clk_hz, baud_rate);

//	REG_UART_LCRH(uart_index) =	0x60; //8位数据位?1位停止位?无校验位?关闭FIFO功能
#ifdef UART_ENABLE_FIFO_MODE
	REG_UART_LCRH(uart_index) =	0x70; //8位数据位,1位停止位,无校验位,开启FIFO功能
	REG_UART_IFLS(uart_index) = 0x12; //FIFO发送和接收中断触发个数都为8
	REG_UART_IMSC(uart_index) = 0x50; //开启Rx_INT,Rx_TIMEOUT_INT
#else
	REG_UART_LCRH(uart_index) =	0x60; //8位数据位,1位停止位,无校验位,关闭FIFO功能
	REG_UART_IMSC(uart_index) = 0x10; //开启Rx_INT
#endif

	REG_UART_CR(uart_index) = 0x0301; //enable uart

//#ifdef UART_Tx_INT_MODE
//	REG_UART_IMSC(uart_index) = 0x030;  //enable Rx/Tx_INT,disable else int
//#else
//	REG_UART_IMSC(uart_index) = 0x010;  //enable Rx_INT,disable Tx_INT and else int
//#endif

	REG_UART_ICR(uart_index) = 0xfff; //clear int

	print(PRINT_UART,"Hz %d MHz\r\n", SystemCoreClock/1000000);
	print(PRINT_UART,"Slk= %d MHz, Plk= %d MHz\r\n", SRCClock/1000000, PClock/1000000);
	
}

/************************************************************************
 * function   : outbyte
 * Description: uart out byte
 * input : 
 *         UINT32 uart_index: Serial port number
 *         char c: out byte
 * return: none
 ************************************************************************/
void outbyte(UINT32 uart_index, char c)
{
	REG_UART_DR(uart_index) = c;

#ifdef UART_Tx_INT_MODE
	while(!tx_flag);
	tx_flag = 0;
#else
	while(REG_UART_FR(uart_index) & 0x08);  //wait for idle
#endif
}


struct __FILE  //please select UART NO( UARTA or UARTB)
{
	int handle;
	/* Add whatever you need here */
};
FILE __stdout;
FILE __stdin;

//该函数指向UARTA 并写入全局变量

int fputc(int ch, FILE *f)
{
	/* Place your implementation of fputc here */
	/* e.g. write a character to the USART */
	outbyte(DEBUG_UART, ch); //debug uart: UARTA or UARTB
#ifdef DEBUG
	if(BUG_DATA_EN){
		BUG_DATA[bug_i]=(UINT8) ch;
		if(bug_i<BUG_DATA_SIZE) bug_i++;
		else bug_i=BUG_START;
	}
#endif
	return ch;
}
/************************************************************************
 * function   : uart_send_bytes
 * Description: uart send bytes
 * input : 
 *         UINT32 uart_index: Serial port number
 *         UINT8* buff: out buffer
 *         UINT32 length: buffer length
 * return: none
 ************************************************************************/
int bsp_UartSend(UINT32 uart_index, UINT8 *buff, UINT32 length)
{
	UINT32 i;

	for(i = 0; i < length; i++)
	{
		outbyte(uart_index, *buff++);
	}
	return length;
}

/*
*********************************************************************************************************
*	函 数 名: bsp_UartReceive
*	功能说明: 从串口缓冲区读取1字节，非阻塞。无论有无数据均立即返回
*	形    参: _ucPort: 端口号(COM1 - COM6)
*			  _pByte: 接收到的数据存放在这个地址
*	返 回 值: 0 表示无数据, 1 表示读取到有效字节, -1表示异常
*********************************************************************************************************
*/
int bsp_UartReceive(uint16_t huart, uint8_t *_prbuff, uint16_t _usrlen)
{
	uint16_t i = 0;
	int   ret;
	
//    if(huart == NULL)
//	{
//	    return -1;
//	}
	if(huart == UARTA)//如果是串口1
	{
		if(0 == UART1.RxCount)//没有有效数据，返回错误
		{
			ret = 0;
			return ret;
		}
		if(_usrlen > UART1.RxCount)//需求的数据大于有效数据个数, 返回有效数据个数
		{
			for(i = 0; i < UART1.RxCount; i++)
			{
					*_prbuff = UART1.UART_RX_BUF[UART1.RxRead];
					if (++UART1.RxRead >= USART_REC_LEN)
					{
						UART1.RxRead = 0;
					}			
				_prbuff++;
			}
			UART1.RxCount -= i;
			ret = i;
		}
		else 
		{
			for(i = 0; i < _usrlen; i++)
			{
				*_prbuff = UART1.UART_RX_BUF[UART1.RxRead];
				if (++UART1.RxRead >= USART_REC_LEN)
				{
					UART1.RxRead = 0;
				}
				UART1.RxCount--;
				_prbuff++;
			}
			ret = i;
		}
	}
	return ret;
}

int uart_get_char(uint32_t port, char* ch)
{
	return bsp_UartReceive(0, (uint8_t*)ch, 1);
}

int uart_output(uint32_t port, const char*data, uint32_t len)
{
    if(len == 0)
      return -1;

    return bsp_UartSend(0, (uint8_t*)data, (uint16_t)len);
}
