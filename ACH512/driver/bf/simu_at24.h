#ifndef __SIMU_AT24_H
#define __SIMU_AT24_H
#include "simu_iic.h"   

#define AT24C01		127
#define AT24C02		255
#define AT24C04		511
#define AT24C08		1023
#define AT24C16		2047
#define AT24C32		4095
#define AT24C64	    8191
#define AT24C128	16383
#define AT24C256	32767  
//ALIENTEK STM32开发板使用的是24c02，所以定义EE_TYPE为AT24C02
#define EE_TYPE AT24C64
					  
u8 AT24CXX_ReadOneByte(uint16_t ReadAddr);							//指定地址读取一个字节
void AT24CXX_WriteOneByte(uint16_t WriteAddr,u8 DataToWrite);		//指定地址写入一个字节
void AT24CXX_Write(uint16_t WriteAddr,u8 *pBuffer,uint16_t NumToWrite);	//从指定地址开始写入指定长度的数据
void AT24CXX_Read(uint16_t ReadAddr,u8 *pBuffer,uint16_t NumToRead);   	//从指定地址开始读出指定长度的数据
u8 AT24CXX_Check(void);  //检查器件
void AT24CXX_Init(void); //初始化IIC

void delay_us(uint16_t z);
void delay_ms(uint16_t z);
#endif
















