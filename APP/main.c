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
#include "pwm.h"  //pwh���ƿ���LED��˸
#include "lwshell.h"
#include "uart.h"
#include "config.h"
#define USBINSERT		1
#define	USBDETACH		0
#define	SYSRESTORE	0
#define	ILLEGALOPENED	1


//�������ȼ�
#define START_TASK_PRIO				4

//���32
#define USB_TASK_PRIO					9
#define UART_TASK_PRIO				8
#define INTERFACE_TASK_PRIO		6
#define IDLE_TASK_PRIO				7
	
//�����ջ��С	
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

//extern xQueueHandle	uartQueue;			//���о��
//xQueueHandle	UkeyQueue;

xSemaphoreHandle	USBMutexSemaphore;		//USB���������
xSemaphoreHandle	UARTMutexSemaphore;
xSemaphoreHandle	USBInsertSemaphore;
xSemaphoreHandle	UkeyInsertSemaphore;
xSemaphoreHandle	BreakSemaphore;

TimerHandle_t		SelfCheckTimerHandle;	//��ʱ�����
//uint8_t *main_test_malloc = NULL;
extern FlashData eFlash;
MCUSelfCheck DevSelfCheck;
uint8_t UkeyState=0;
uint8_t UkeyStateflag=0;
uint8_t LED_FLAG = 0;					//λ0��0����ʼ���У�1����ʼ�����  ��������̵���
															//λ1��0���Լ�������1���Լ�ʧ��    ������̵���
															//λ2��0��δ��¼��  1���û���¼    ������̵���
															//λ3��0��FPGA������1��FPGA����    ����������̵���
extern uint8_t ArgFlag;
extern unsigned char null_array[MAINKEY_LEN];		//������
//�ⲿSRAM��ַ��ΧΪ  0x6000 0000		---   0x6010 0000	
//�����İ����ⲿSRAMΪ16BitS (1m * 16 Bits)		
FATFS fs[_VOLUMES]; //__attribute__ ((at(0x60000000))); //�߼����̹�����.	�ⲿsram ����2K�ռ�
FIL file;		//�ļ�1
//������
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

typedef struct SwUChar //���������ֽڵ�λ��
{ //Bit0x���ڽ���Ҫת�����ֽڣ�Bit1x���ڴ���ת������ֽ�
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

typedef union LHUchar //���������壬����һ����λ���顣
{ //ch[0]��Bit0x��Ӧ��ch[1]��Bit1x��Ӧ
	unsigned char ch[2];
	SwUChar_def SwUChar1;
} LHUchar_def;

LHUchar_def LHUchar1; //����ǰ������ռ�������ֽ�

unsigned char swap_uchar(unsigned char x) //ֱ�ӵ��ü���
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

//�����Լ������߳�
static void SelfcheckCallback(TimerHandle_t xTimer){
	
}
/*********************************/
//ArgFlag bit0: 0-MCU_SM2 1-FPGA_SM2
//				bit1: 1510����
//				bit2: 0-MCU_SM1 1-FPGA_SM1
//				bit3: 0-MCU_SM3 1-FPGA_SM1
//				bit4: 0-MCU_SM4 1-FPGA_SM1
//				bit5: fpga������
//
/*********************************/
static void Run_Config_task(void){
	//FPGA�㷨״̬�Ĵ���
	uint8_t hw_ver,hw_chip,hw_type;
	
	#ifndef CHECK
	fpga_init_ready();
	print(PRINT_COM,"ver_f %x\r\n",fpga_get_ver());
	FPGA_REG(FPGA_LED_CONTR_ADDR) = 0x8000;//����FPGA����
	while(0==(FPGA_REG(FPGA_ARG_REG_ADDR)&0x0100));//�ȴ�FPGA��Link�ź�
	FPGA_REG(FPGA_LED_CONTR_ADDR) = 0x0000;//����FPGA��˸���ڣ���0x-000+1��*2
#endif
	if(FPGA_RESET==FPGA_FLAG){	//��λ����
		FPGA_FLAG=FPGA_NORMAL;
	}
	
	ArgFlag = (FPGA_REG(FPGA_ARG_REG_ADDR))&0x00FF;
	ArgFlag = ArgFlag & 0xF9;				//FPGA ��֧��SM1,1510ʱ�������㷨
	hw_type = FPGA_REG(FPGA_CARD_TYPE_ADDR) << 2;
	hw_type = swap_uchar(hw_type);
	hw_ver  = hw_type & (0x7<<3);
	print(PRINT_COM,"hw_ver %x\r\n",hw_ver);
	hw_chip = hw_type & 0x7;
	print(PRINT_COM,"hw_chip %x\r\n",hw_chip);
	switch(hw_ver){
		case FPGA_HS:
			if(hw_chip & FPGA_SM2)
				ArgFlag = ArgFlag & 0xFE;     //ʹ��MCU��SM2�㷨
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
				ArgFlag = ArgFlag & 0xFE;     //ʹ��MCU��SM2�㷨
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
		ArgFlag = ArgFlag | 0x01;     //ʹ��FPGA��HSMD1
	if(!HSMD1){
		//printf("SM3SM4_STATUS %x\n",(FPGA_REG(FPGA_SM3SM4_STATUS_ADDR)&0xFF00) >> 8);
		if(((FPGA_REG(FPGA_SM3SM4_STATUS_ADDR)&0xFF00) >> 8)>16){
			ArgFlag = ArgFlag | 0x20;  //sm4������>16  bit6��1��
		}
	}
	print(PRINT_COM,"F_TYPE %x\r\n",FPGA_REG(FPGA_CARD_TYPE_ADDR));
	print(PRINT_COM,"AF %x\r\n",ArgFlag);
	if((FPGA_REG(FPGA_MCU_DRIVER_READ)&0x0001) != 0){    //�������Ѿ�����,���������͵�ǰ�豸״̬
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
		while(fpga_receive_data()){ //��������������
#if 1
			pdt = (uint16_t *)dt;
			//��ȡFPGAͷ
			*pdt = *(uint16_t *)FPGA_DATA_READ_ADDR;   pdt++;//��ȡԴ��Ŀ��
			if(FH->src > FPGA_DATA_HOST_DMA1 || FH->dst != FPGA_DATA_ARM){
				continue;
			}
			*pdt = *(uint16_t *)FPGA_DATA_READ_ADDR;   pdt++;//��ȡУ��ֵ
			if(FH->mark != 0xD6FA){
				continue;
			}
			*pdt = *(uint16_t *)FPGA_DATA_READ_ADDR;   pdt++;//��ȡ������
			//����ʣ�����ݳ���
			tmpL = FH->pkglen - 6;
			if(tmpL > 4090 || tmpL < 26){
				continue;
			}
			//��ʣ������	
			while(tmpL > 0){
				*pdt = *(uint16_t *)FPGA_DATA_READ_ADDR; pdt++;
				tmpL -= 2;
			}
			fpga_read_finish();
			Inter_MCU_CMD(dt);
			memset(dt,0,4096);
			
#endif
		}
		//���fpga��Ҫ��λ��������mcu
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
		//��ѯģʽ
		xSemaphoreTake(USBMutexSemaphore, portMAX_DELAY);
		if(!Slave_Detach()){
			//print(PRINT_COM,"UKey exist\r\n");
			if(!UkeyStateflag){
				while(count < 3){ //ö�ٲ��ɹ�������3��
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
				if(eFlash.DEV_STATE == WorkStatus){	//UK���γ� �˳�����̬
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
//��ʼ����������
static void start_task(void *pvParameters){
    taskENTER_CRITICAL();           //�����ٽ���
		//�����ź���
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
    vTaskDelete(StartTask_Handler); //ɾ����ʼ����
    taskEXIT_CRITICAL();            //�˳��ٽ���
}


void NVIC_Configuration(void){
	NVIC_InitTypeDef NVIC_InitStructure;
	NVIC_PriorityGroupConfig(NVIC_PriorityGroup_3);		//ACH512�Ĵ���ֻʹ����3bit(MSB)
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
	NVIC_PriorityGroupConfig(NVIC_PriorityGroup_3);		//ACH512�Ĵ���ֻʹ����3bit(MSB)
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
//	REG_SCU_PUCRA &= ~(0x01<<DETECT_PIN);			//detect ��ȡ������
//	gpio_config(DETECT_PIN,0);				//detect ��������
	gpio_config(RESTORE_PIN,0);				//erase ��������
	
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

//Ӳ�������ʼ��
void HardwareInit(void){
	char ver[30]={0};
#ifdef DETECT
	//�͹����Իټ��
	SystemInit(6);		// 6mhz coreclk
//	SystemCoreClockUpdate6M();
//	delay_ms(55);
	Key_Configuration();
	NVIC_Config_detect();
	delay_ms(55);
#endif
	//������ʼ��
	SystemInit(FCLK);									// 110mhz coreclk
	uart_init(DEBUG_UART, UART_BAUD_RATE);	//UARTA 115200
	spi_init(SPI_MEM_COM, WORK_MODE_3, SPI_MASTER);
	mem_bus_init();
	SecurityInit();
//////sl811_init();
	sl811_soc_init();
	led_display(LED_0,HZ_1,LED_ON);//�������mcu����
	delay_ms(3000);//�ȴ�fpga����
	Key_Configuration();		//����sl811��ʼ�����ٳ�ʼ���ж�
	NVIC_Configuration();
	gpio_init();
	get_version(ver,ARM_FIRMWARE_VERSION);
	print(PRINT_COM,"ver_m %s\r\n",ver);
	//AT24CXX_Init();		//eeprom����swd/sck ��ʼ�����޷�����
	i2c_init(MASTER_I2C_SPEED);			//eeprom��ʼ��
	print(PRINT_COM,"-mcu INI ok-\r\n");
	led_display(LED_1,HZ_1,LED_ON);//�̵�����mcu��ʼ�����
	Run_Config_task();
	fpga_init();	//��ʼ��fpga
	print(PRINT_COM,"-fpga INI ok-\r\n");
}


uint8_t FS_Init(void){
	uint8_t res=0;
	res=f_mount(&fs[1],"1:",1);	//�����ⲿflash
	//print(PRINT_COM"mou err %d \r\n",res);
	if(res == 0x0D){						//���ļ�ϵͳ
		print(PRINT_COM,"no fs flash\r\n");
#if 0 //!RELEASE
		res=f_mkfs("1:",0,0);			//�����ļ�ϵͳ(ֻ��Ҫ����̬�´���)
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
//������ó�ʼ��
extern uint8_t SESSIONKEY[SKEYNUM * (SKEYSIZE + 2)];
void ConfigInit(void){
	//ʹ��heap5ʱ��ʼ���ڴ��
	//vPortDefineHeapRegions((const HeapRegion_t *)xHeapRegions);
	//�豸��Ϣ��ʼ��
	GetFlashData();
	memset((uint8_t *)RSA_KEYPAIR_INFO_ADDR, 0, RSA_KEYPAIR_NUM * 2+2);
	memset((uint8_t *)SESSIONKEY, 0, SKEYNUM);
	memset((uint8_t *)KEK_INFO_ADDR, 0, KEK_NUM);
	memset((uint8_t *)SM2_KEYPAIR_INFO_ADDR, 0, SM2_KEYPAIR_NUM * 2+2);
	memset(null_array, 0, MAINKEY_LEN);
}

/***********************************************************************
 * main������
 * ������� ����
 * ����ֵ   ����
 * �������� ����������ں���������ģ���ʼ���Լ�����ģ���֧�Ӻ�������ѯ
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
	led_display(LED_1,HZ_1,LED_ON);//�̵�����mcu����
	xTaskCreate((TaskFunction_t )start_task,            //������
							(const char*    )"start_task",          //��������
							(uint16_t       )START_STK_SIZE,        //�����ջ��С
							(void*          )NULL,                  //���ݸ��������Ĳ���
							(UBaseType_t    )START_TASK_PRIO,       //�������ȼ�
							(TaskHandle_t*  )&StartTask_Handler);   //������
	print(PRINT_COM,"sche start\r\n");
  vTaskStartScheduler();          									  //�����������
  while(1);

}
void HardFault_Handler(void)
{
	while(1);
}
//App��������ƫ��
void SetVectorTable(uint32_t vecttab,uint32_t offset){
	SCB->VTOR = vecttab | ( offset & (uint32_t)0x1FFFFF80);
}
