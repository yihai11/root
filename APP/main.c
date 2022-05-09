/***********************************************************************
 * Copyright (c)  2020, beijing shudun Co.,Ltd .
 * All rights reserved.
 * Filename    : main.c
 * Description : main source file
 * Author(s)   : jaime
 * version     : V1.0
 * Modify date : 2020-07-06
 ***********************************************************************/
 
#include "common.h"
#include "main.h"
#include "usrconfig.h"
#include "hsm2_init.h"
#include "hsmd1_init.h"
#include "cipher.h"
#include "pwm.h"  //pwh机制控制LED闪烁
#include "lwshell.h"
#include "uart.h"
#include "config.h"
#define USBINSERT		1
#define	USBDETACH		0
#define	SYSRESTORE	0
#define	ILLEGALOPENED	1


//任务优先级
#define START_TASK_PRIO				4

//最大32
#define USB_TASK_PRIO					9
#define UART_TASK_PRIO				8
#define INTERFACE_TASK_PRIO		6
#define IDLE_TASK_PRIO				7
	
//任务堆栈大小	
#define START_STK_SIZE			512
#define IDLE_STK_SIZE				128
#define UART_STK_SIZE				2048
#define	USB_STK_SIZE				512
#define	INTERFACE_STK_SIZE		8192


TaskHandle_t StartTask_Handler;
TaskHandle_t IdleTask_Handler;
TaskHandle_t UARTTask_Handler;
TaskHandle_t USBTask_Handler;
TaskHandle_t InterfaceTask_Handler;

//extern xQueueHandle	uartQueue;			//队列句柄
//xQueueHandle	UkeyQueue;

xSemaphoreHandle	USBMutexSemaphore;		//USB互斥量句柄
xSemaphoreHandle	UARTMutexSemaphore;
xSemaphoreHandle	USBInsertSemaphore;
xSemaphoreHandle	UkeyInsertSemaphore;
xSemaphoreHandle	BreakSemaphore;

TimerHandle_t		SelfCheckTimerHandle;	//定时器句柄
//uint8_t *main_test_malloc = NULL;
extern FlashData eFlash;
MCUSelfCheck DevSelfCheck;
uint8_t UkeyState=0;
uint8_t UkeyStateflag=0;
uint8_t LED_FLAG = 0;					//位0：0：初始化中，1：初始化完成  红灯亮，绿灯亮
															//位1：0：自检正常，1：自检失败    红灯灭，绿灯亮
															//位2：0：未登录，  1：用户登录    红灯灭，绿灯闪
															//位3：0：FPGA正常，1：FPGA故障    红灯慢闪，绿灯亮
extern uint8_t ArgFlag;
extern unsigned char null_array[MAINKEY_LEN];		//空数组
//外部SRAM地址范围为  0x6000 0000		---   0x6010 0000	
//新做的板子外部SRAM为16BitS (1m * 16 Bits)		
FATFS fs[_VOLUMES]; //__attribute__ ((at(0x60000000))); //逻辑磁盘工作区.	外部sram 分配2K空间
FIL file;		//文件1
//任务函数
static void start_task(void *pvParameters);
static void Idle_task(void *pvParameters);
static void UART_task(void *pvParameters);
static void USB_task(void * pvParameters);
static void Interface_task(void *pvParameters);
extern 	void	Enter_LE_Model(void);

extern HeapRegion_t xHeapRegions[];

void * UKeyMalloc(UINT32 size){
	return pvPortMalloc(size);
}

void UKeyFree(void *memory){
	vPortFree(memory);
}

void Task_Printf(char *s){
//	xQueueSend(uartQueue,s,portMAX_DELAY);
}

typedef struct SwUChar //声明两个字节的位域。
{ //Bit0x用于接收要转换的字节，Bit1x用于储存转换后的字节
	unsigned char Bit00 :1;
	unsigned char Bit01 :1;
	unsigned char Bit02 :1;
	unsigned char Bit03 :1;
	unsigned char Bit04 :1;
	unsigned char Bit05 :1;
	unsigned char Bit06 :1;
	unsigned char Bit07 :1;

	unsigned char Bit10 :1;
	unsigned char Bit11 :1;
	unsigned char Bit12 :1;
	unsigned char Bit13 :1;
	unsigned char Bit14 :1;
	unsigned char Bit15 :1;
	unsigned char Bit16 :1;
	unsigned char Bit17 :1;

} SwUChar_def;

typedef union LHUchar //定义联合体，声明一个两位数组。
{ //ch[0]与Bit0x对应，ch[1]与Bit1x对应
	unsigned char ch[2];
	SwUChar_def SwUChar1;
} LHUchar_def;

LHUchar_def LHUchar1; //需提前声明，占用两个字节

unsigned char swap_uchar(unsigned char x) //直接调用即可
{
	LHUchar1.ch[0] = x;
	LHUchar1.SwUChar1.Bit10 = LHUchar1.SwUChar1.Bit07;
	LHUchar1.SwUChar1.Bit11 = LHUchar1.SwUChar1.Bit06;
	LHUchar1.SwUChar1.Bit12 = LHUchar1.SwUChar1.Bit05;
	LHUchar1.SwUChar1.Bit13 = LHUchar1.SwUChar1.Bit04;
	LHUchar1.SwUChar1.Bit14 = LHUchar1.SwUChar1.Bit03;
	LHUchar1.SwUChar1.Bit15 = LHUchar1.SwUChar1.Bit02;
	LHUchar1.SwUChar1.Bit16 = LHUchar1.SwUChar1.Bit01;
	LHUchar1.SwUChar1.Bit17 = LHUchar1.SwUChar1.Bit00;
	return LHUchar1.ch[1];
}

//周期自检任务线程
static void SelfcheckCallback(TimerHandle_t xTimer){
	
}
/*********************************/
//ArgFlag bit0: 0-MCU_SM2 1-FPGA_SM2
//				bit1: 1510配置
//				bit2: 0-MCU_SM1 1-FPGA_SM1
//				bit3: 0-MCU_SM3 1-FPGA_SM1
//				bit4: 0-MCU_SM4 1-FPGA_SM1
//				bit5: fpga核心数
//
/*********************************/
static void Run_Config_task(void){
	//FPGA算法状态寄存器
	uint8_t hw_ver,hw_chip,hw_type;
	
	#ifndef CHECK
	fpga_init_ready();
	print(PRINT_COM,"ver_f %x\r\n",fpga_get_ver());
	FPGA_REG(FPGA_LED_CONTR_ADDR) = 0x8000;//设置FPGA常亮
	while(0==(FPGA_REG(FPGA_ARG_REG_ADDR)&0x0100));//等待FPGA的Link信号
	FPGA_REG(FPGA_LED_CONTR_ADDR) = 0x0000;//设置FPGA闪烁周期：（0x-000+1）*2
#endif
	if(FPGA_RESET==FPGA_FLAG){	//复位操作
		FPGA_FLAG=FPGA_NORMAL;
	}
	
	ArgFlag = (FPGA_REG(FPGA_ARG_REG_ADDR))&0x00FF;
	ArgFlag = ArgFlag & 0xF9;				//FPGA 不支持SM1,1510时的配置算法
	hw_type = FPGA_REG(FPGA_CARD_TYPE_ADDR) << 2;
	hw_type = swap_uchar(hw_type);
	hw_ver  = hw_type & (0x7<<3);
	print(PRINT_COM,"hw_ver %x\r\n",hw_ver);
	hw_chip = hw_type & 0x7;
	print(PRINT_COM,"hw_chip %x\r\n",hw_chip);
	switch(hw_ver){
		case FPGA_HS:
			if(hw_chip & FPGA_SM2)
				ArgFlag = ArgFlag & 0xFE;     //使用MCU的SM2算法
			break;
		case FPGA_HP:
			HSMD1_CHIP1_VAILD = (hw_chip >= 0);
			HSMD1_CHIP2_VAILD = (hw_chip >= 1);
			HSMD1_CHIP3_VAILD = (hw_chip >= 2);
			HSMD1_CHIP4_VAILD = (hw_chip >= 3);
			break;
		case FPGA_TS:
			if(hw_chip & FPGA_S10A)
				print(PRINT_COM,"ArgFlag ERR!!! %x\r\n",ArgFlag);
				ArgFlag = ArgFlag & 0xFE;     //使用MCU的SM2算法
			break;
		default:
			while(1){
				delay_ms(1000);
				print(PRINT_COM,"F_TYPE %x\r\n",FPGA_REG(FPGA_CARD_TYPE_ADDR));
				print(PRINT_COM,"hw_ver %x\r\n",hw_ver);
			}
			break;
	}
	HSMD1 = (HSMD1_CHIP1_VAILD | HSMD1_CHIP2_VAILD<<1 | HSMD1_CHIP3_VAILD<<2 | HSMD1_CHIP4_VAILD<<3);
	if(HSMD1)
		ArgFlag = ArgFlag | 0x01;     //使用FPGA的HSMD1
	if(!HSMD1){
		//printf("SM3SM4_STATUS %x\n",(FPGA_REG(FPGA_SM3SM4_STATUS_ADDR)&0xFF00) >> 8);
		if(((FPGA_REG(FPGA_SM3SM4_STATUS_ADDR)&0xFF00) >> 8)>16){
			ArgFlag = ArgFlag | 0x20;  //sm4核心数>16  bit6置1；
		}
	}
	print(PRINT_COM,"F_TYPE %x\r\n",FPGA_REG(FPGA_CARD_TYPE_ADDR));
	print(PRINT_COM,"AF %x\r\n",ArgFlag);
	if((FPGA_REG(FPGA_MCU_DRIVER_READ)&0x0001) != 0){    //驱动若已经加载,向驱动发送当前设备状态
		mcutodriver_LOGINSTATUS();
	}else{
		*(unsigned short *)FPGA_MCU_DRIVER_WRITE = (0x0001<<(eFlash.DEV_STATE));
	}
}

void fpga_init(void)
{

	if(!HSMD1){
		fpga_hsm2_init();
		print(PRINT_COM,"sm2 INI ok\r\n");
	}
	else{
		fpga_hsmd1_init();
		print(PRINT_COM,"smd1 INI ok\r\n");
	}
}


static void Interface_task(void *pvParameters)
{

	uint8_t dt[4096]={0};
	uint16_t *pdt = (uint16_t *)dt;
	FPGAHeader * FH = (FPGAHeader *)dt;
	int32_t tmpL=0;
//	Run_Config_task();
#ifndef CHECK
	Run_Test_task();
#else
#ifdef DEBUG
	uint32_t heap_init = xPortGetFreeHeapSize();
	memcpy((char*)dt,"Heap:",5);
	sprintf((char*)dt+5,"%d",heap_init);
	memcpy(BUG_DATA,dt,10);
	memset(dt,0,10);
#endif
#endif
	print(PRINT_COM,"InFace task run\r\n");
	for(;;){
		//print(PRINT_COM,"fpga_rst state is %d.\r\n",gpio_state(FPGA_RST));
		//vTaskDelay(500);
		while(fpga_receive_data()){ //接受区有新数据
#if 1
			pdt = (uint16_t *)dt;
			//读取FPGA头
			*pdt = *(uint16_t *)FPGA_DATA_READ_ADDR;   pdt++;//读取源和目的
			if(FH->src > FPGA_DATA_HOST_DMA1 || FH->dst != FPGA_DATA_ARM){
				continue;
			}
			*pdt = *(uint16_t *)FPGA_DATA_READ_ADDR;   pdt++;//读取校验值
			if(FH->mark != 0xD6FA){
				continue;
			}
			*pdt = *(uint16_t *)FPGA_DATA_READ_ADDR;   pdt++;//读取包长度
			//计算剩余数据长度
			tmpL = FH->pkglen - 6;
			if(tmpL > 4090 || tmpL < 26){
				continue;
			}
			//读剩余数据	
			while(tmpL > 0){
				*pdt = *(uint16_t *)FPGA_DATA_READ_ADDR; pdt++;
				tmpL -= 2;
			}
			fpga_read_finish();
			Inter_MCU_CMD(dt);
			memset(dt,0,4096);
			
#endif
		}
		//如果fpga需要复位，软重启mcu
		if(FPGA_RESET==FPGA_FLAG){
			FPGA_FLAG=FPGA_NORMAL;
			delay_ms(10);
			NVIC_SystemReset();
//			fpga_init();
//			if(eFlash.DEV_STATE == WorkStatus||eFlash.DEV_STATE == ManagementStatus)
//			{
//				UserLogout();
//				eFlash.DEV_STATE = ReadyStatus;
//				mcutodriver_LOGINSTATUS();
//			}
//			Run_Test_task();
		}
	}
}


static void Idle_task(void *pvParameters){
	print(PRINT_COM,"idl task run\r\n");
	for(;;){
		vTaskDelay(1000);
	}
}
	
static void USB_task(void *pvParameters){
//	void *Handle =NULL;
//	void * hApplication;
	char count = 0;
//	uint32_t Interface_HighWater;
//	uint8_t error=0;
//	BaseType_t er=pdFALSE;
	print(PRINT_COM,"usb task run\r\n");
	for(;;){
		//轮询模式
		xSemaphoreTake(USBMutexSemaphore, portMAX_DELAY);
		if(!Slave_Detach()){
			//print(PRINT_COM,"UKey exist\r\n");
			if(!UkeyStateflag){
				while(count < 3){ //枚举不成功，尝试3次
					if(sl811_disk_init()){
							count++;
					}else{
							UkeyState=1;
							print(PRINT_COM,"UKey IN\r\n");
							break;
					}
				}
				UkeyStateflag = 1;
				count = 0;
			}
		}
		else{
			//print(PRINT_COM,"UKry not exist\r\n");
			if(UkeyStateflag){
				print(PRINT_COM,"UKey RM\r\n");
				UkeyState=0;
				UkeyStateflag=0;
				if(eFlash.DEV_STATE == WorkStatus){	//UK被拔出 退出工作态
					UserLogout();
					eFlash.DEV_STATE = ReadyStatus;
					mcutodriver_LOGINSTATUS();
				}
				sl811_os_init();
			}
		}
		xSemaphoreGive(USBMutexSemaphore);
		vTaskDelay(500);
		//vTaskDelay(10);
//		Interface_HighWater=uxTaskGetStackHighWaterMark( UARTTask_Handler );
//		print(PRINT_COM,"The Inface_HW is %d\r\n",Interface_HighWater);
		//print(PRINT_COM,"Heap is %d\r\n",xPortGetFreeHeapSize());
	}
}
#ifdef CHECK
static void UART_task(void *pvParameters){
	print(PRINT_COM,"uart task run\r\n");
	uint16_t hearttimes=0;
	uint8_t uart_buff[10]={0};
//	uartQueue = xQueueCreate( 10, sizeof(uint8_t));
//	if(!uartQueue) print(PRINT_COM,"Que creat err\r\n");
	for(;;){
//		xQueueReceive(uartQueue,&uart_buff,portMAX_DELAY);
		//print(PRINT_COM,"%s\r\n",uart_buff);
		//dug_printf(BUG_DATA,2048);
		//print(PRINT_COM,"Heap:%d\r\n",xPortGetFreeHeapSize());
		vTaskDelay(500);
		console_run(uart_get_char, uart_output, (uint32_t)UARTA);

	}
}
#endif	
//开始任务任务函数
static void start_task(void *pvParameters){
    taskENTER_CRITICAL();           //进入临界区
		//创建信号量
		USBMutexSemaphore=xSemaphoreCreateMutex();
		BreakSemaphore=xSemaphoreCreateBinary();

		xSemaphoreGive(USBMutexSemaphore);

		SelfCheckTimerHandle= xTimerCreate((const char* const) "SelfCheckSoftewareTimer",
									(TickType_t)60000/portTICK_PERIOD_MS,			//60S
									(UBaseType_t)pdTRUE,
									(void *)1,
									(TimerCallbackFunction_t)SelfcheckCallback);
									
		xTaskCreate((TaskFunction_t )Idle_task,
                (const char*    )"Idle_task",
                (uint16_t       )IDLE_STK_SIZE,
                (void*          )NULL,
                (UBaseType_t    )IDLE_TASK_PRIO,
                (TaskHandle_t*  )&IdleTask_Handler);
								
		xTaskCreate((TaskFunction_t )USB_task,
                (const char*    )"USB_task",
                (uint16_t       )USB_STK_SIZE,
                (void*          )NULL,
                (UBaseType_t    )USB_TASK_PRIO,
                (TaskHandle_t*  )&USBTask_Handler);
#ifndef CHECK
		xTaskCreate((TaskFunction_t )Interface_task,
                (const char*    )"fpga_rec_task",   
                (uint16_t       )INTERFACE_STK_SIZE,
                (void*          )NULL,
                (UBaseType_t    )INTERFACE_TASK_PRIO,
                (TaskHandle_t*  )&InterfaceTask_Handler); 
#else
	   xTaskCreate((TaskFunction_t )UART_task,     
                (const char*    )"UART_task",   
                (uint16_t       )UART_STK_SIZE,
                (void*          )NULL,
                (UBaseType_t    )UART_TASK_PRIO,
                (TaskHandle_t*  )&UARTTask_Handler); 
#endif
    vTaskDelete(StartTask_Handler); //删除开始任务
    taskEXIT_CRITICAL();            //退出临界区
}


void NVIC_Configuration(void){
	NVIC_InitTypeDef NVIC_InitStructure;
	NVIC_PriorityGroupConfig(NVIC_PriorityGroup_3);		//ACH512寄存器只使用了3bit(MSB)
#ifdef DETECT
	NVIC_InitStructure.NVIC_IRQChannel = GPIOA_IRQn;
	NVIC_InitStructure.NVIC_IRQChannelPreemptionPriority = configLIBRARY_LOWEST_INTERRUPT_PRIORITY;//configLIBRARY_MAX_SYSCALL_INTERRUPT_PRIORITY-1;
	NVIC_InitStructure.NVIC_IRQChannelSubPriority =0;
	NVIC_InitStructure.NVIC_IRQChannelCmd = ENABLE;
	NVIC_Init(&NVIC_InitStructure);
#endif
#ifndef CHECK
	NVIC_InitStructure.NVIC_IRQChannel = GPIOB_IRQn;
	NVIC_InitStructure.NVIC_IRQChannelPreemptionPriority = configLIBRARY_LOWEST_INTERRUPT_PRIORITY;
	NVIC_InitStructure.NVIC_IRQChannelSubPriority = 0;
	NVIC_InitStructure.NVIC_IRQChannelCmd = ENABLE;
	NVIC_Init(&NVIC_InitStructure);
#endif
	NVIC_InitStructure.NVIC_IRQChannel = UARTA_IRQn;
	NVIC_InitStructure.NVIC_IRQChannelPreemptionPriority = configLIBRARY_LOWEST_INTERRUPT_PRIORITY;
	NVIC_InitStructure.NVIC_IRQChannelSubPriority = 0;
	NVIC_InitStructure.NVIC_IRQChannelCmd = ENABLE;
	NVIC_Init(&NVIC_InitStructure);
}
void NVIC_Config_detect(void){
	NVIC_InitTypeDef NVIC_InitStructure;
	NVIC_PriorityGroupConfig(NVIC_PriorityGroup_3);		//ACH512寄存器只使用了3bit(MSB)
	NVIC_InitStructure.NVIC_IRQChannel = GPIOA_IRQn;
	NVIC_InitStructure.NVIC_IRQChannelPreemptionPriority = configLIBRARY_LOWEST_INTERRUPT_PRIORITY;//configLIBRARY_MAX_SYSCALL_INTERRUPT_PRIORITY-1;
	NVIC_InitStructure.NVIC_IRQChannelSubPriority =0;
	NVIC_InitStructure.NVIC_IRQChannelCmd = ENABLE;
	NVIC_Init(&NVIC_InitStructure);
	NVIC_InitStructure.NVIC_IRQChannel = UARTA_IRQn;
	NVIC_InitStructure.NVIC_IRQChannelPreemptionPriority = configLIBRARY_LOWEST_INTERRUPT_PRIORITY;
	NVIC_InitStructure.NVIC_IRQChannelSubPriority = 0;
	NVIC_InitStructure.NVIC_IRQChannelCmd = ENABLE;
	NVIC_Init(&NVIC_InitStructure);
}
void SecurityInit(void){
//	REG_SCU_PUCRA &= ~(0x01<<DETECT_PIN);			//detect 脚取消上拉
//	gpio_config(DETECT_PIN,0);				//detect 设置输入
	gpio_config(RESTORE_PIN,0);				//erase 设置输入
	
	if(gpio_state(RESTORE_PIN) == SYSRESTORE){
		cleanmcu_toboot();
		//NVIC_SystemReset();//	REG_SCU_RESETCTRLA|=0x04;
		while(1);
	}
#ifdef DETECT
	while(ILLEGALMASK == eflash_read_word(ILLEGAlMARK_ADDR)){
		//print(PRINT_COM,"the state is destroystatus!\r\n");
		eflash_erase_page(ILLEGAlMARK_ADDR);
		eFlash.DEV_STATE = DestroyStatus;
		led_display(LED_0,HZ_1,LED_BL);
//		led_display(LED_1,HZ_1,LED_OFF);
		if(0!=((FPGA_REG(FPGA_ARG_REG_ADDR)&0x0100) && !fpga_handshake()))
			mcutodriver_LOGINSTATUS();
			go_to_factory();
		//cleanmcu_toboot();
		//NVIC_SystemReset();
		while(1);
	}
#endif
}

//硬件外设初始化
void HardwareInit(void){
	char ver[30]={0};
#ifdef DETECT
	//低功耗自毁检测
	SystemInit(6);		// 6mhz coreclk
//	SystemCoreClockUpdate6M();
//	delay_ms(55);
	Key_Configuration();
	NVIC_Config_detect();
	delay_ms(55);
#endif
	//正常初始化
	SystemInit(FCLK);									// 110mhz coreclk
	uart_init(DEBUG_UART, UART_BAUD_RATE);	//UARTA 115200
	spi_init(SPI_MEM_COM, WORK_MODE_3, SPI_MASTER);
	mem_bus_init();
	SecurityInit();
//////sl811_init();
	sl811_soc_init();
	led_display(LED_0,HZ_1,LED_ON);//红灯亮起，mcu运行
	delay_ms(3000);//等待fpga启动
	Key_Configuration();		//必须sl811初始化后再初始化中断
	NVIC_Configuration();
	gpio_init();
	get_version(ver,ARM_FIRMWARE_VERSION);
	print(PRINT_COM,"ver_m %s\r\n",ver);
	//AT24CXX_Init();		//eeprom复用swd/sck 初始化后无法调试
	i2c_init(MASTER_I2C_SPEED);			//eeprom初始化
	print(PRINT_COM,"-mcu INI ok-\r\n");
	led_display(LED_1,HZ_1,LED_ON);//绿灯亮起，mcu初始化完成
	Run_Config_task();
	fpga_init();	//初始化fpga
	print(PRINT_COM,"-fpga INI ok-\r\n");
}


uint8_t FS_Init(void){
	uint8_t res=0;
	res=f_mount(&fs[1],"1:",1);	//挂载外部flash
	//print(PRINT_COM"mou err %d \r\n",res);
	if(res == 0x0D){						//无文件系统
		print(PRINT_COM,"no fs flash\r\n");
#if 0 //!RELEASE
		res=f_mkfs("1:",0,0);			//创建文件系统(只需要出厂态下创建)
		print(PRINT_COM,"mkfs state is %d\r\n",res);
		if(res!=FR_OK)
		{
			print(PRINT_COM,"fatal error,make fatfs error ,error code is %d\r\n",res);
			while(1);
		}
#endif
	}
	return res;
}
void check_peripheral(void){
	
}
//软件配置初始化
extern uint8_t SESSIONKEY[SKEYNUM * (SKEYSIZE + 2)];
void ConfigInit(void){
	//使用heap5时初始化内存池
	//vPortDefineHeapRegions((const HeapRegion_t *)xHeapRegions);
	//设备信息初始化
	GetFlashData();
	memset((uint8_t *)RSA_KEYPAIR_INFO_ADDR, 0, RSA_KEYPAIR_NUM * 2+2);
	memset((uint8_t *)SESSIONKEY, 0, SKEYNUM);
	memset((uint8_t *)KEK_INFO_ADDR, 0, KEK_NUM);
	memset((uint8_t *)SM2_KEYPAIR_INFO_ADDR, 0, SM2_KEYPAIR_NUM * 2+2);
	memset(null_array, 0, MAINKEY_LEN);
}

/***********************************************************************
 * main主函数
 * 输入参数 ：无
 * 返回值   ：无
 * 函数功能 ：主程序入口函数，各个模块初始化以及各个模块分支子函数的轮询
 ***********************************************************************/
int main(void)
{
	//SetVectorTable();
	//SecurityInit();
	HardwareInit();
#ifndef CHECK
		ConfigInit();
//	clear_fs();
//	FS_config();
	if(FS_Init()){
		print(PRINT_COM,"FS_Init err\r\n");
		while(1);
	}
#endif
	print(PRINT_COM,"creat task \r\n");
	led_display(LED_1,HZ_1,LED_ON);//绿灯亮起，mcu运行
	xTaskCreate((TaskFunction_t )start_task,            //任务函数
							(const char*    )"start_task",          //任务名称
							(uint16_t       )START_STK_SIZE,        //任务堆栈大小
							(void*          )NULL,                  //传递给任务函数的参数
							(UBaseType_t    )START_TASK_PRIO,       //任务优先级
							(TaskHandle_t*  )&StartTask_Handler);   //任务句柄
	print(PRINT_COM,"sche start\r\n");
  vTaskStartScheduler();          									  //开启任务调度
  while(1);

}
void HardFault_Handler(void)
{
	while(1);
}
//App程序向量偏移
void SetVectorTable(uint32_t vecttab,uint32_t offset){
	SCB->VTOR = vecttab | ( offset & (uint32_t)0x1FFFFF80);
}
