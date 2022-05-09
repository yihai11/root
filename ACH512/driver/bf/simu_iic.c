/***********************************************************************
 * Copyright (c)  2020, beijing shudun Co.,Ltd .
 * All rights reserved.
 * Filename    : simuiic.c
 * Description : simuiic source file
 * Author(s)   : jaime
 * version     : V1.0
 * Modify date : 2020-07-10
 ***********************************************************************/
 
#include "simu_iic.h"

//��ʼ��IIC
void IIC_Init(void)
{				
//����swio �� swck	
 	gpio_config(9,1);
	gpio_config(11,1);
	gpio_set(9);
	gpio_set(11);
}
//����IIC��ʼ�ź�
void IIC_Start(void)
{
	SDA_OUT();     //sda�����
	IIC_SDA_ON;
	IIC_SCL_ON;  	  
	delay_us(4);
 	IIC_SDA_OFF;//START:when CLK is high,DATA change form high to low 
	delay_us(4);
	IIC_SCL_OFF ;//ǯסI2C���ߣ�׼�����ͻ�������� 
}	  
//����IICֹͣ�ź�
void IIC_Stop(void)
{
	SDA_OUT();//sda�����
	IIC_SCL_OFF;
	IIC_SDA_OFF;//STOP:when CLK is high DATA change form low to high
 	delay_us(4);
	IIC_SCL_ON;
	IIC_SDA_ON;//����I2C���߽����ź�
	delay_us(4);							   	
}
//�ȴ�Ӧ���źŵ���
//����ֵ��1������Ӧ��ʧ��
//        0������Ӧ��ɹ�
u8 IIC_Wait_Ack(void)
{
	u8 ucErrTime=0;
	SDA_IN();      //SDA����Ϊ����  
	IIC_SDA_ON;delay_us(1);	   
	IIC_SCL_ON;delay_us(1);	 
	while(READ_SDA)
	{
		ucErrTime++;
		if(ucErrTime>250)
		{
			IIC_Stop();
			return 1;
		}
	}
	IIC_SCL_OFF;//ʱ�����0 	   
	return 0;  
} 
//����ACKӦ��
void IIC_Ack(void)
{
	IIC_SCL_OFF;
	SDA_OUT();
	IIC_SDA_OFF;
	delay_us(2);
	IIC_SCL_ON;
	delay_us(2);
	IIC_SCL_OFF;
}
//������ACKӦ��		    
void IIC_NAck(void)
{
	IIC_SCL_OFF;
	SDA_OUT();
	IIC_SDA_ON;
	delay_us(2);
	IIC_SCL_ON;
	delay_us(2);
	IIC_SCL_OFF;
}					 				     
//IIC����һ���ֽ�
//���شӻ�����Ӧ��
//1����Ӧ��
//0����Ӧ��			  
void IIC_Send_Byte(u8 txd)
{                        
    u8 t;   
	SDA_OUT(); 	    
    IIC_SCL_OFF;//����ʱ�ӿ�ʼ���ݴ���
    for(t=0;t<8;t++)
    {              
			if((txd&0x80)>>7)
				IIC_SDA_ON;
			else
				IIC_SDA_OFF;
			txd<<=1; 	  
			delay_us(2);   //��TEA5767��������ʱ���Ǳ����
			IIC_SCL_ON;
			delay_us(2); 
			IIC_SCL_OFF;	
			delay_us(2);
    }	 
} 	    
//��1���ֽڣ�ack=1ʱ������ACK��ack=0������nACK   
u8 IIC_Read_Byte(unsigned char ack)
{
	unsigned char i,receive=0;
	SDA_IN();//SDA����Ϊ����
    for(i=0;i<8;i++ )
	{
        IIC_SCL_OFF; 
        delay_us(2);
				IIC_SCL_ON;
        receive<<=1;
        if(READ_SDA)receive++;   
		delay_us(1); 
    }					 
    if (!ack)
        IIC_NAck();//����nACK
    else
        IIC_Ack(); //����ACK   
    return receive;
}


