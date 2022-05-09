/***********************************************************************
 * Copyright (c)  2008 - 2016, Shanghai AisinoChip Co.,Ltd .
 * All rights reserved.
 * Filename    : gpio.c
 * Description : gpio driver source file
 * Author(s)   : Eric
 * version     : V1.0
 * Modify date : 2016-03-24
 ***********************************************************************/
#include "gpio.h"
#include "main.h"
#include "SL811_usb.h"
#include "config.h"
#include "fpga.h"
#include "pwm.h"
#include "devmanage.h"
#define PRINT_GPIO 2

volatile UINT8 flag_gpioa_int = 0;
volatile UINT8 flag_gpiob_int = 0;

#define EFCS		3

extern FlashData eFlash;
extern xSemaphoreHandle	USBInsertSemaphore;

//返回开盖功能状态
uint16_t DETECT_ENABLE(void)
{
	return(eFlash.DATA_STATUS >>16); //!0xA5A5 关闭开盖功能，0xA5A5 开启开盖功能
}
void all_pin_config(void)
{
	REG_SCU_MUXCTRLA=0;
	REG_SCU_MUXCTRLB=0;
	REG_SCU_MUXCTRLC=0;
	REG_SCU_MUXCTRLD=0;
	REG_SCU_PUCRA =0; 
	REG_SCU_PUCRB =0;
	REG_GPIO_DIR(GPIOA)=0xFFFFFFFF;
	REG_GPIO_DIR(GPIOB)=0xFFFFFFFF;
	REG_GPIO_CLR(GPIOA)=0xFFFFFFFF;
	REG_GPIO_CLR(GPIOB)=0xFFFFFFFF;


	//spi flash cs 拉高
	//gpio_config(3,1);
	//gpio_set(EFCS);
}
void Enter_LE_Model(void)
{
	all_pin_config();
	SystemCoreClockUpdate6M();
	REG_SCU_CTRLA=0xFFFFFFFF;			//禁用全部功能
	//REG_SCU_RESETCTRLA=0;
	//REG_SCU_WAKEUPCTRL|=3<<7;	//poweroff  and  PD mode 
	REG_SCU_WAKEUPCTRL|=3<<7;		//power down 模式
}
void GPIOA_IRQHandler(void)
{
		uint32_t status=0 ;
		uint32_t mask,pinstate;
		mask = 0x01<<DETECT_PIN;
		status = REG_GPIO_MIS(GPIOA)&mask;
		pinstate = REG_GPIO_IDATA(GPIOA)&mask;
//		led_display(LED_0,HZ_1,LED_OFF);
//		led_display(LED_1,HZ_1,LED_BL);
		NVIC_DisableIRQ(GPIOA_IRQn);
		//print(PRINT_GPIO,"GPIOA IRQ\r\n");
		delay_ms(3);
		if(status && (!pinstate)){
			//print(PRINT_GPIO,"shield opened\r\n");
			//portENTER_CRITICAL();
#ifdef DETECT
//////		if(DETECT_ENABLE() == DETECT_FLAG){  //生产工具配置使能
			SystemCoreClockUpdate6M();
			//delay_ms(110);
			//REG_SCU_CTRLA=~0x10400010;			//保留了串口,EFC,GPIO功能
			REG_SCU_CTRLA=~0x18400912;			//保留了串口,EFC,GPIO,timer,cache,SM3,ROM功能
			//REG_SCU_CTRLA=~0x00000010;			//保留了EFC功能

				WriteIllegalMark();

			//led_display(LED_1,HZ_1,LED_ON);

//		if(ILLEGALMASK == eflash_read_word(ILLEGAlMARK_ADDR))
//			print(PRINT_GPIO,"write ok!!!\r\n");
			eFlash.DEV_STATE = DestroyStatus;
			if(0!=(FPGA_REG(FPGA_ARG_REG_ADDR)&0x0100) && !fpga_handshake())
				mcutodriver_LOGINSTATUS();//上报当前状态
			Enter_LE_Model();
			while(1);
//////		}
		//portEXIT_CRITICAL(); 
#endif
	}
		REG_GPIO_IC(GPIOA) = status;
}

void GPIOB_IRQHandler(void)
{
		uint32_t status=0 ;
		uint32_t mask,pinstate;
		mask = 0x01<<(FPGA_RST-32);
		status = REG_GPIO_MIS(GPIOB)&mask;
		pinstate = REG_GPIO_IDATA(GPIOB)&mask;
		NVIC_DisableIRQ(GPIOB_IRQn);
		//print(PRINT_GPIO,"GPIOB IRQ\r\n");
		delay_ms(3);
		if(status && (!pinstate)){
			FPGA_FLAG = FPGA_RESET;
			fpga_int_clear();
			led_display(LED_1,HZ_1,LED_OFF);//绿灯熄灭，FPGA复位
			//portENTER_CRITICAL();
		}
		
		REG_GPIO_IC(GPIOB) = status;
		NVIC_EnableIRQ(GPIOB_IRQn);
//		while(1);
}
/****************************************
void GPIOB_IRQHandler(void)
{
    UINT32 status;
		static portBASE_TYPE xHigherPriorityTaskWoken;
		BaseType_t pdresult;	
		uint32_t mask,pinstate;
		print(PRINT_GPIO,"gpioB interrupt\r\n");
		mask= 0x01<<17;//GPIO49
		status = REG_GPIO_MIS(GPIOB);
		pinstate=REG_GPIO_IDATA(GPIOB);
		if((status&mask)&&(pinstate&mask)){
			sl811_reg_write(IntStatus,INT_CLEAR); //清除中断状态，否则下次拔插不会中断
			print(PRINT_GPIO,"U口介质状态改变\r\n");
			pdresult=xSemaphoreGiveFromISR(USBInsertSemaphore,&xHigherPriorityTaskWoken);
		}
		REG_GPIO_IC(GPIOB) |= (0x01<<17);
		//sl811_reg_write(IntStatus,INT_CLEAR);
		print(PRINT_GPIO,"清除中断标志\r\n");
		//REG_GPIO_IEN(GPIOB) |= 	(0x01<<17);
	  portYIELD_FROM_ISR(xHigherPriorityTaskWoken);
}
**********************************************/

/************************************************************************
 * function   : gpio_init
 * Description: gpio initial
 * input : none
 * return: none
 ************************************************************************/
void gpio_init(void)
{

#ifdef LOW_POWER
    enable_module(BIT_GPIO); //enable GPIO
#endif
#ifdef DETECT
    NVIC_ClearPendingIRQ(GPIOA_IRQn);
    NVIC_EnableIRQ(GPIOA_IRQn);
#endif
#ifndef CHECK
    NVIC_ClearPendingIRQ(GPIOB_IRQn);
    NVIC_EnableIRQ(GPIOB_IRQn);
#endif
}



/************************************************************************
 * function   : gpio_config
 * Description: gpio config function
 * input : gpio_pin	：the number of the gpio(0-63)
 *				 direction: PIN_OUTPUT(1)  PIN_INPUT(0)
 * return: none
 ************************************************************************/
void gpio_config(uint8_t gpio_pin,uint8_t direction)
{

    if(gpio_pin <= 15){
			REG_SCU_MUXCTRLA &= ~(0x03 << (gpio_pin * 2));	//设置对应管脚功能为gpio
			if(direction)
				REG_GPIO_DIR(GPIOA) |= 1 << gpio_pin; 				//配置gpio为输出
			else
				REG_GPIO_DIR(GPIOA) &= ~(0x01 << gpio_pin); 	//配置gpio为输入
		}
		
		else if(( gpio_pin>15 ) && ( gpio_pin <= 31)){
			REG_SCU_MUXCTRLB &= ~(0x03 << ((gpio_pin-16)*2));
			if(direction)
				REG_GPIO_DIR(GPIOA) |= 1 << gpio_pin; 
			else
				REG_GPIO_DIR(GPIOA) &= ~(0x01 << gpio_pin); 
		}
		
		else if(( gpio_pin>31 )&&(gpio_pin <= 47)){
			REG_SCU_MUXCTRLC &= ~(0x03 << ((gpio_pin-32) * 2));
			if(direction)
				REG_GPIO_DIR(GPIOB) |= 1 << (gpio_pin-32); 
			else
				REG_GPIO_DIR(GPIOB) &= ~(0x01 << (gpio_pin-32)); 
		}
		
		else if(( gpio_pin>47 )&&(gpio_pin <= 63)){
			REG_SCU_MUXCTRLD &= ~(0x03 << ((gpio_pin-48) * 2));
			if(direction)
				REG_GPIO_DIR(GPIOB) |= 1 << (gpio_pin-32); 
			else
				REG_GPIO_DIR(GPIOB) &= ~(0x01 << (gpio_pin-32)); 
		}
			
}
/************************************************************************
 * function   : gpio_set
 * Description: gpio set function
 * input : gpio_pin	：the number of the gpio
 * return: none
 ************************************************************************/
void gpio_set(uint8_t gpio_pin)
{
//	uint8_t state=0;
	//	通过读REG_GPIO_ODATA(GPIOx)值获取GPIO状态  
	if(gpio_pin <= 31)
		REG_GPIO_SET(GPIOA) |= 1<< gpio_pin;
	else if(gpio_pin <= 63)
		REG_GPIO_SET(GPIOB) |= 1<< (gpio_pin-32);
	
	/*
	if(gpio_pin<32)
		state=((REG_GPIO_ODATA(GPIOA)>>gpio_pin) & 0x01);
	else
		state=((REG_GPIO_ODATA(GPIOB)>>(gpio_pin-32)) & 0x01);
	*/
	//print(PRINT_GPIO,"the pin%d state is %d \r\n",gpio_pin,state);
}

/************************************************************************
 * function   : gpio_clr
 * Description: gpio clr function
 * input : gpio_pin	：the number of the gpio
 * return: none
 ************************************************************************/
void gpio_clr(uint8_t gpio_pin)
{
//	uint8_t state=0;
	//	通过读REG_GPIO_ODATA(GPIOx)值获取GPIO状态  
	if(gpio_pin <= 31)
		REG_GPIO_CLR(GPIOA) |= 1<< gpio_pin;	 
	else if(gpio_pin <= 63)
		REG_GPIO_CLR(GPIOB) |= 1<< (gpio_pin-32);
	/*
	if(gpio_pin<32)
		state=((REG_GPIO_ODATA(GPIOA)>>gpio_pin) & 0x01);
	else
		state=((REG_GPIO_ODATA(GPIOB)>>(gpio_pin-32)) & 0x01);
	delay_ms(10);
	*/
	//print(PRINT_GPIO,"the pin%d state is %d \r\n",gpio_pin,state);
}
uint8_t gpio_state(uint8_t gpio_pin)
{
	uint8_t state=0;
	if(gpio_pin<32)
		state = (uint8_t)((REG_GPIO_IDATA(GPIOA)>>gpio_pin) & 0x01);
	else
		state = (uint8_t)((REG_GPIO_IDATA(GPIOB) >> (gpio_pin-32)) &0x01);
	return state;
}

//set gpio nvic 
//mode bit0：0 边沿触发；1 电平触发
//		 bit1：0 低电平触发；1 高电平触发
void gpio_nvic(uint32_t pin_num,uint8_t INTIO,uint8_t mode)
{
	if(INTIO==GPIOB)
		pin_num -=32;
	REG_GPIO_IEN(INTIO) &=  ~(0x01<<pin_num);	//禁止中断
	if(0==(mode&0x01)){
		REG_GPIO_IS(INTIO)  &=  ~(0x01<<pin_num);	//0= 边沿检测；1= 电平检测。
		REG_GPIO_IBE(INTIO) &=  ~(0x01<<pin_num);	//单边沿触发
	}
	else
		REG_GPIO_IS(INTIO)  |=   (0x01<<pin_num);	//0= 边沿检测；1= 电平检测。
	
	if(0==(mode&0x02))
		REG_GPIO_IEV(INTIO) &=  ~(0x01<<pin_num);	//低电平触发
	else
		REG_GPIO_IEV(INTIO) |=   (0x01<<pin_num);	//高电平触发
	
	REG_GPIO_IC(INTIO)  |=   (0x01<<pin_num);	//清除中断状态
	REG_GPIO_IEN(INTIO) |=   (0x01<<pin_num);	//使能中断
}

void Key_Configuration(void){
//	uint8_t gpiogroup=0;
	
	//DETECT管脚初始化
	REG_SCU_PUCRA &= ~(0x01<<DETECT_PIN);//detect 脚取消上拉
	gpio_config(DETECT_PIN,0);
	
	//FPGA_RST管脚初始化
	//REG_SCU_PUCRB &= ~(0x01<<(FPGA_RST-32));//rst 脚取消上拉
	gpio_config(FPGA_RST,0);
	
#ifdef DETECT
	gpio_nvic(DETECT_PIN,GPIOA,0x01);
#endif
	gpio_nvic(FPGA_RST,GPIOB,0x01);
	
	/*  //bootloader中执行
	gpio_config(62,0);
	REG_GPIO_IEN(GPIOB) &= ~(0x01<<30);		//失能中断
	REG_GPIO_IS(GPIOB)  &= ~(0x01<<30);		//边缘检测
	REG_GPIO_IBE(GPIOB) &= ~(0x01<<30);		//单边沿触发
	REG_GPIO_IEV(GPIOB) |= 	(0x01<<30);		//上升沿触发
	REG_GPIO_IC(GPIOB)  |= 	(0x01<<30);		//清除中断状态
	REG_GPIO_IEN(GPIOB) |= 	(0x01<<30);		//使能中断
	*/
	
	//SL811中断管脚初始化
//	gpio_config(49,0);							//U口中断必须要在sl811_init之后配置
//	REG_SCU_PUCRB &= ~(0x01<<17);
//	REG_GPIO_IEN(GPIOB) &= 	~(0x01<<17);		//失能中断
//	//REG_GPIO_IS(GPIOB) |= 0x01<<17;		//电平检测
//	REG_GPIO_IS(GPIOB)  &= ~(0x01<<17);		//边缘检测
//	REG_GPIO_IBE(GPIOB) &= ~(0x01<<17);		//单边沿触发
//	//REG_GPIO_IBE(GPIOB) |= 0x01<<17;
//	//REG_GPIO_IEV(GPIOB) |=  (0x01<<17);		//上升沿触发
//	REG_GPIO_IC(GPIOB)  |=  (0x01<<17);		//清除中断状态
//	REG_GPIO_IEN(GPIOB) |=  (0x01<<17);		//使能中断
	
}
