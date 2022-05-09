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
/*--------------------------------��������--------------------------------------*/

/************1.���������뿨4ƬD1***************/

/*****************************************/

/************2.���Խ��빤��̬*************/
//#define DG_login
/*****************************************/

/************3.���ÿ��Ǽ��***************/
//#define DETECT
/*****************************************/

/************6.��װ���԰汾***************/
//#define CHECK
/*****************************************/

/************5.�̼��汾*******************/
#define ARM_FIRMWARE_VERSION		 0x01000800  // ���磺0x01000300  ����1.0.3�汾  ��λ00����  
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
extern char HSMD1_CHIP1_VAILD;  //0x01:��ʾоƬʹ�ܣ�0��ʾоƬ��Ч
extern char HSMD1_CHIP2_VAILD;
extern char HSMD1_CHIP3_VAILD;
//#if(defined HSMD1_4)||(defined CHECK)
extern char HSMD1_CHIP4_VAILD;

extern char HSMD1; //(HSMD1_CHIP1_VAILD | HSMD1_CHIP2_VAILD<<1 | HSMD1_CHIP3_VAILD<<2 | HSMD1_CHIP4_VAILD<<3)
/*****************************************/

/************6.��־��¼����*******************/
//#define DEBUG                              //print������־�ӿ�ʹ��
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

/*--------------- ʱ������ ----------------------- */
#define FCLK 110  //����coreʱ��/HCLK ,������Ϊ��6 12 30 48 50 60 70 80 90 100 110 �� (uint:MHz)
  
/*--------------- uart���� ----------------------- */
//ͨ�Ÿ�ʽ���ã�8λ����λ��1λֹͣλ����У��λ

#define UART_BAUD_RATE	115200
//#define UART_Tx_INT_MODE   // Tx�����жϷ�ʽ  ��������Rxʼ�ղ����жϷ�ʽ��
//#define UARTB_USE_CTSMODE    //CTS mode
//#define UARTB_USE_RTSMODE	 //RTS mode

#endif
