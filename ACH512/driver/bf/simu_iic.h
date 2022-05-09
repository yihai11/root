#ifndef __SIMU_IIC_H
#define __SIMU_IIC_H
//#include "sys.h"
#include "common.h"
#include "GPIO.h"

#define u8  uint8_t
//IO方向设置
#define SDA_IN()  gpio_config(11,0)
#define SDA_OUT() gpio_config(11,1)

#define IIC_SCL_ON	gpio_set(9)
#define IIC_SCL_OFF	gpio_clr(9)

#define IIC_SDA_ON	gpio_set(11)
#define IIC_SDA_OFF	gpio_clr(11)

#define	READ_SDA		( REG_GPIO_IDATA(GPIOA)>>11 & 0x01 )


//IIC所有操作函数
void IIC_Init(void);                //初始化IIC的IO口				 
void IIC_Start(void);				//发送IIC开始信号
void IIC_Stop(void);	  			//发送IIC停止信号
void IIC_Send_Byte(u8 txd);			//IIC发送一个字节
u8 IIC_Read_Byte(unsigned char ack);//IIC读取一个字节
u8 IIC_Wait_Ack(void); 				//IIC等待ACK信号
void IIC_Ack(void);					//IIC发送ACK信号
void IIC_NAck(void);				//IIC不发送ACK信号

void IIC_Write_One_Byte(u8 daddr,u8 addr,u8 data);
u8 IIC_Read_One_Byte(u8 daddr,u8 addr);	  
#endif
















