/***********************************************************************
 * Copyright (c)  2020, beijing shudun Co.,Ltd .
 * All rights reserved.
 * Filename    : config.h
 * Description : config header file
 * Author(s)   : Jamie 
 * version     : V1.0
 * Modify date : 2020-07-24
 ***********************************************************************/
#ifndef __CONFIG_H__
#define __CONFIG_H__
/*--------------------------------配置内容--------------------------------------*/

/************1.超高速密码卡4片D1***************/

/*****************************************/

/************2.调试进入工作态*************/
//#define DG_login
/*****************************************/

/************3.启用开盖检测***************/
//#define DETECT
/*****************************************/

/************6.工装测试版本***************/
//#define CHECK
/*****************************************/

/************5.固件版本*******************/
#define ARM_FIRMWARE_VERSION		 0x01000800  // 例如：0x01000300  代表1.0.3版本  低位00保留  
#define MCU_V_NAME							"HSPCM_MCU_V"  //1.2.7.20210707"
/*****************************************/

/*----------------------------------------------------------------------*/

#define HSMD1_400M 0x00001020
#define HSMD1_375M 0x0000101e
#define HSMD1_350M 0x0000101c
#define HSMD1_HZ HSMD1_375M

#define RAN_CHIP_NUM ((HSMD1)? 6 : 3)

#define NEW 1
/*****************************************/
extern char HSMD1_CHIP1_VAILD;  //0x01:表示芯片使能，0表示芯片无效
extern char HSMD1_CHIP2_VAILD;
extern char HSMD1_CHIP3_VAILD;
//#if(defined HSMD1_4)||(defined CHECK)
extern char HSMD1_CHIP4_VAILD;

extern char HSMD1; //(HSMD1_CHIP1_VAILD | HSMD1_CHIP2_VAILD<<1 | HSMD1_CHIP3_VAILD<<2 | HSMD1_CHIP4_VAILD<<3)
/*****************************************/

/************6.日志记录功能*******************/
//#define DEBUG                              //print调试日志接口使能
/*****************************************/

#define DEBUG_UART UARTA 
//#ifdef DEBUG
//#define printfS     printf
//#define printfB8    printf_buff_byte
//#define printfB32   printf_buff_word


//#else
//#define	printfS(format, ...)	     ((void)0)
//#define	printfB8(buff, byte_len)	 ((void)0)
//#define	printfB32(buff, word_len)	 ((void)0)
//#endif

/*--------------- 时钟设置 ----------------------- */
#define FCLK 110  //配置core时钟/HCLK ,可配置为：6 12 30 48 50 60 70 80 90 100 110 等 (uint:MHz)
  
/*--------------- uart设置 ----------------------- */
//通信格式采用：8位数据位，1位停止位，无校验位

#define UART_BAUD_RATE	115200
//#define UART_Tx_INT_MODE   // Tx采用中断方式  （程序中Rx始终采用中断方式）
//#define UARTB_USE_CTSMODE    //CTS mode
//#define UARTB_USE_RTSMODE	 //RTS mode

#endif
