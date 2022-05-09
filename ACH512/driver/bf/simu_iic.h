#ifndef __SIMU_IIC_H
#define __SIMU_IIC_H
//#include "sys.h"
#include "common.h"
#include "GPIO.h"

#define u8  uint8_t
//IO��������
#define SDA_IN()  gpio_config(11,0)
#define SDA_OUT() gpio_config(11,1)

#define IIC_SCL_ON	gpio_set(9)
#define IIC_SCL_OFF	gpio_clr(9)

#define IIC_SDA_ON	gpio_set(11)
#define IIC_SDA_OFF	gpio_clr(11)

#define	READ_SDA		( REG_GPIO_IDATA(GPIOA)>>11 & 0x01 )


//IIC���в�������
void IIC_Init(void);                //��ʼ��IIC��IO��				 
void IIC_Start(void);				//����IIC��ʼ�ź�
void IIC_Stop(void);	  			//����IICֹͣ�ź�
void IIC_Send_Byte(u8 txd);			//IIC����һ���ֽ�
u8 IIC_Read_Byte(unsigned char ack);//IIC��ȡһ���ֽ�
u8 IIC_Wait_Ack(void); 				//IIC�ȴ�ACK�ź�
void IIC_Ack(void);					//IIC����ACK�ź�
void IIC_NAck(void);				//IIC������ACK�ź�

void IIC_Write_One_Byte(u8 daddr,u8 addr,u8 data);
u8 IIC_Read_One_Byte(u8 daddr,u8 addr);	  
#endif
















