/****************************************Copyright (c)****************************************************
**
**--------------File Info---------------------------------------------------------------------------------
** File name:               SL811Disk.c
** Descriptions:            The SL811 Disk application function
**
**--------------------------------------------------------------------------------------------------------
** Created by:              AVRman
** Created date:            2011-4-13
** Version:                 v1.0
** Descriptions:            The original version
**
**--------------------------------------------------------------------------------------------------------
** Modified by:             
** Modified date:           
** Version:                 
** Descriptions:            
**
*********************************************************************************************************/

/* Includes ------------------------------------------------------------------*/
#include "SL811_usb.h"
#include "SL811Disk.h"
//#include "main.h"
#include "SKFError.h"
#include "SKFInterface.h"
#include "ukey_oper.h"
#include "SL811_usb.h"
#include "user_manage.h"
/* Private define ------------------------------------------------------------*/
#define SL811_DISK
extern USBDev g_usb_dev;
extern xQueueHandle	UkeyQueue;
extern xSemaphoreHandle	UkeyInsertSemaphore;
/*******************************************************************************
* Function Name  : delay_ms
* Description    : Delay Time
* Input          : - cnt: Delay Time
* Output         : None
* Return         : None
* Return         : None
* Attention		 : None
*******************************************************************************/
static void delay_ms(uint16_t ms)    
{ 
	uint16_t i,j; 
	for( i = 0; i < ms; i++ )
	{ 
		for( j = 0; j < 9210; j++ );
	}
}

/*******************************************************************************
* Function Name  : sl811_disk_init
* Description    : None
* Input          : None
* Output         : None
* Return         : None
* Return         : None
* Attention		 : None
*******************************************************************************/
void asci_print( uint8_t car )
{
	uint8_t temp;
	temp = ( car >> 4 ) + 0x30;
	if(temp > '9')
	{
		temp += 7;
	}	
	/* Place your implementation of fputc here */
	/* e.g. write a character to the USART */
	//USART_SendData(USART1, temp);
	print(PRINT_811USB,"%c",temp);
	
	/* Loop until the end of transmission 
	while (USART_GetFlagStatus(USART1, USART_FLAG_TC) == RESET)
	{}
	*/
	temp = ( car & 0x0F ) + 0x30;
	if(temp > '9')
	{
		temp += 7;
	}	
	/* Place your implementation of fputc here */
	/* e.g. write a character to the USART */
	//USART_SendData(USART1, temp);
	print(PRINT_811USB,"%c",temp);
	/* Loop until the end of transmission 
	while (USART_GetFlagStatus(USART1, USART_FLAG_TC) == RESET)
	{}*/
}

int sl811_disk_init(void)
{
	int rtval;
	//for test
	DevDesc dev_desc;
	CfgDesc cfg_desc;
	uint8_t desc_buff[128];

	uint8_t repeat=0;
	uint8_t	repeat_times=0;
	//BYTE random_buff[256 + 128];
	
	//sl811_soc_init();
	 //SL811_MemTest();
	while( sl811_reg_read(0x0D) & 0x40 ){
		repeat_times++;
		print(PRINT_811USB," No USB reg %x\r\n",sl811_reg_read(0x0D));
		//vTaskDelay(500);
		delay_ms(500);
		if(repeat_times>5){
			repeat_times=0;
			gpio_clr(34);
			delay_ms(50);
			gpio_set(34);
			return NO_DEVICE;
		}
	}
	print(PRINT_811USB,"USB CON \r\n");

	while( ( sl811_reg_read(0x0D) & 0x80 ) == 0 )
	{
#ifdef SL811_DISK
		print(PRINT_811USB,"USB Low\r\n");
#endif
		repeat++;
		delay_ms(10);
		if(repeat>5)
			return NOT_FULL_SPEED;		/* return error if low speed detected */
	}
#ifdef SL811_DISK
	print(PRINT_811USB,"USB Full\r\n");
#endif
	
	
	usb_detect_init();
	usb_reset_dev();

#if 1
	//for my file test
	//delay_ms(100);

#if 1
	memset(&g_usb_dev, 0, sizeof(USBDev));
	g_usb_dev.is_attached = 1;
	
	//获取前八个字节的描述符
	rtval = usb_get_desc(DEVICE_DESC, 0, 0x08, (uint8_t *)&dev_desc);
	if (rtval)
	{
		print(PRINT_811USB,"USB G desc %d\r\n", rtval);
		return rtval;
	}
	else
	{
		print(PRINT_811USB,"Maxb Size0 %d\r\n", dev_desc.bMaxPacketSize0);
		g_usb_dev.ctrlEP_payload = dev_desc.bMaxPacketSize0;
	}
		
	//配置地址
	rtval = usb_set_address(DEF_USB_ADDR);
	if (rtval)
	{
		print(PRINT_811USB,"USB S desc err\r\n");
		return rtval;
	}
	else
	{
		print(PRINT_811USB,"USB dev.Addr 0x%x\r\n", g_usb_dev.USB_Addr);
	}
	//获取全部设备描述符
	rtval = usb_get_desc(DEVICE_DESC, 0, sizeof(DevDesc), (uint8_t *)&dev_desc);
	if (rtval)
	{
		print(PRINT_811USB,"USB gdesc err\r\n");
		return rtval;
	}
	else
	{
		print(PRINT_811USB,"USB gdesc all OK\r\n");
		if (dev_desc.bNumConfigurations != 1)
		{
			print(PRINT_811USB,"bNumCon %d, > 1\r\n", dev_desc.bNumConfigurations); //> 1 not supported!
		}
	}
	//获取配置描述符
	rtval = usb_get_desc(CONFIG_DESC, 0, sizeof(CfgDesc), (uint8_t *)&cfg_desc);
	if (rtval)
	{
		print(PRINT_811USB,"USB gdesc 1st time err\r\n");
		return rtval;
	}
	else
	{
		print(PRINT_811USB,"USB gdesc OK!!!\r\n");
//		print(PRINT_811USB,"cfg_desc.bNumIntf is %d\r\n", cfg_desc.bNumIntf);
//		print(PRINT_811USB,"cfg_desc.wLength is %d\r\n", cfg_desc.wLength);
//		print(PRINT_811USB,"cfg_desc.bNumIntf is %d\r\n", cfg_desc.bNumIntf);
	}
	//获取第二遍配置描述符？
	rtval = usb_get_desc(CONFIG_DESC, 0, cfg_desc.wLength, desc_buff);	
	if (rtval)
	{
		print(PRINT_811USB,"USB gdesc 2nd time err\r\n");
		return rtval;
	}
	else
	{
		//print(PRINT_811USB,"desc_buff is \r\n");
		//printf_buff_byte(desc_buff, cfg_desc.wLength);
	}
	rtval = parse_interface_endpoint(desc_buff, cfg_desc.wLength);
	if (rtval)
	{
		print(PRINT_811USB,"par_IF_EP er\r\n");
		return rtval;
	}
	else
	{
		print(PRINT_811USB,"par_IF_EP ok\r\n");
		print(PRINT_811USB,"g_usb_dev.inface_num %d\r\n", g_usb_dev.inface_num);
		print(PRINT_811USB,"g_usb_dev.ums_index %d\r\n", g_usb_dev.ums_index);
//		print(PRINT_811USB,"bInterfaceClass is %d\r\n", g_usb_dev.usb_interfaces[g_usb_dev.ums_index].bInterfaceClass);
//		print(PRINT_811USB,"bInterfaceSubClass is %d\r\n", g_usb_dev.usb_interfaces[g_usb_dev.ums_index].bInterfaceSubClass);
//		print(PRINT_811USB,"bInterfaceProtocol is %d\r\n", g_usb_dev.usb_interfaces[g_usb_dev.ums_index].bInterfaceProtocol);
//		print(PRINT_811USB,"bEndpointNum is %d\r\n", g_usb_dev.usb_interfaces[g_usb_dev.ums_index].bEndpointNum);
//		print(PRINT_811USB,"bEndpointAddr[0] is %d\r\n", g_usb_dev.usb_interfaces[g_usb_dev.ums_index].bEndpointAddr[0]);
//		print(PRINT_811USB,"bEndpointAddr[1] is %d\r\n", g_usb_dev.usb_interfaces[g_usb_dev.ums_index].bEndpointAddr[1]);
	}
	
	rtval = usb_set_config(cfg_desc.bNumIntf);
	if (rtval)
	{
		print(PRINT_811USB,"usb_s_conf err\r\n");
		return rtval;
	}
	else
	{
		print(PRINT_811USB,"usb_s_conf OK\r\n");
	}
	g_usb_dev.is_enumed = 1;
#endif
	
	rtval = usb_ums_init();
	if (rtval)
	{
		print(PRINT_811USB,"usb_u_init err\r\n");
		return rtval;
	}
	else
	{
		print(PRINT_811USB,"usb_u_init OK\r\n");
	}
	

	return 0;
#endif
}

///*********************************************************************************************************
//      END FILE
//*********************************************************************************************************/
