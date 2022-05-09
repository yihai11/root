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
//ALIENTEK STM32������ʹ�õ���24c02�����Զ���EE_TYPEΪAT24C02
#define EE_TYPE AT24C64
					  
u8 AT24CXX_ReadOneByte(uint16_t ReadAddr);							//ָ����ַ��ȡһ���ֽ�
void AT24CXX_WriteOneByte(uint16_t WriteAddr,u8 DataToWrite);		//ָ����ַд��һ���ֽ�
void AT24CXX_Write(uint16_t WriteAddr,u8 *pBuffer,uint16_t NumToWrite);	//��ָ����ַ��ʼд��ָ�����ȵ�����
void AT24CXX_Read(uint16_t ReadAddr,u8 *pBuffer,uint16_t NumToRead);   	//��ָ����ַ��ʼ����ָ�����ȵ�����
u8 AT24CXX_Check(void);  //�������
void AT24CXX_Init(void); //��ʼ��IIC

void delay_us(uint16_t z);
void delay_ms(uint16_t z);
#endif
















