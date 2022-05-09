#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include "test.h"
//#include <lib_ascii.h>
//#include <ucos_ii.h>
//#include "common/list.h"
//#include "common/PosixError.h"
#include "uart.h"
#include "lwshell.h"
#include "eflash.h"
#include "ukey_oper.h"
#include "config.h"
#include "fpga_sm2.h"

#ifdef CHECK
uint32_t   stopServe_time = 0;
extern uint16_t Hardware_Error;
extern bool uploadLogPeriodFlag;
extern float debugMode;
extern bool alarmFlag;
extern uint8_t UkeyStateflag;
extern xSemaphoreHandle	USBMutexSemaphore;
/*
 * TODO:
 *  dynamically register & unregister command
 *  then lwshell will becomes a real common component
 */
//#define NFUN
#define ARRAY_SIZE(array)   (sizeof(array)/sizeof(array[0]))
extern uint32_t log_cbhd;
extern int uart_output(uint32_t param, const char*data, uint32_t len);
extern uint8_t ArgFlag;

int htoi(const char s[]);

#define     MAX_CONSOLE_DEVICE  4
#define     MAX_LINE_DATA       128
#define     MAX_PATH_LEN        256

#define     MAX_ARGS            8
#define     ERROR_FAILED        1


typedef struct context
{   
	const   char* cmd;    
	const   char* comment;
}cmdhelp;

struct cmd_handler
{
    const   char* cmd;
    const   char* comment;
    void*   opt;
    int     (*handler)(const char* args[], write_func_t output_func, uint32_t param);
};

typedef struct
{
    write_func_t    func;
    uint32_t        param;
} out_put_t;

struct output
{
    write_func_t func;
    uint32_t    dev;
};

static int help(const char* args[], write_func_t output, uint32_t param);
static int ls(const char* args[], write_func_t output, uint32_t param);
static int hardware_test(const char* args[], write_func_t output, uint32_t param);
static int alg_test(const char* args[], write_func_t output, uint32_t param);
static int change_menu(const char* args[], write_func_t output, uint32_t param);
static int return_boot(const char* args[], write_func_t output, uint32_t param);
static int function(const char* args[], write_func_t output, uint32_t param);

static cmdhelp ht_cmds[] =
{
	
	{NULL,NULL}
	

};
#define MENU(x) (x << 8)
//菜单项
#define BACK_MEUN			0x00
#define MAIN_MEUN			0x01
#define HARD_MEUN			0x02
#define ALG_MEUN			0x03


//0级菜单
#define ALL_LINK			0x01 | MENU(MAIN_MEUN)
#define USB_LINK			0x04 | MENU(MAIN_MEUN)
#define RE_BOOT				0x05 | MENU(MAIN_MEUN)
#define NEW_FUN				0x06 | MENU(MAIN_MEUN)

//1级菜单
#define HARD_TEST			0x01 | MENU(HARD_MEUN)
#define SPI_TEST			0x02 | MENU(HARD_MEUN)
#define EEPROM_TEST		0x03 | MENU(HARD_MEUN)
#define EFLASH_TEST		0x04 | MENU(HARD_MEUN)
#define SRAM_TEST			0x05 | MENU(HARD_MEUN)
#define SL811_TEST		0x06 | MENU(HARD_MEUN)

#define USB_TEST			0x07 | MENU(HARD_MEUN)
#define FPGA_TEST			0x08 | MENU(HARD_MEUN)



//2级菜单
#define ALG_TEST			0x01 | MENU(ALG_MEUN)
#define SM1_TEST			0x02 | MENU(ALG_MEUN)
#define SM2_TEST			0x03 | MENU(ALG_MEUN)
#define SM3_TEST			0x04 | MENU(ALG_MEUN)
#define SM4_TEST			0x05 | MENU(ALG_MEUN)
#define RAN_TEST			0x06 | MENU(ALG_MEUN)
#define RAS_TEST			0x07 | MENU(ALG_MEUN)
#define SHA1_TEST			0x08 | MENU(ALG_MEUN)
#define AES_TEST			0x09 | MENU(ALG_MEUN)
#define DES_TEST			0x10 | MENU(ALG_MEUN)
#define FPGA_KEY			0x11 | MENU(ALG_MEUN)


static int cmd_menu = MAIN_MEUN;
static struct cmd_handler cmds_0[] =
{ 
		{"1",					"(全部测试)	ALL_TEST", 		ht_cmds,	&change_menu},
		{"2",					"(硬件测试)	HARD_TEST", 	ht_cmds,	&help},
		{"3",					"(算法测试)	ALG_TEST", 		ht_cmds,	&help},
		{"4",					"(Ukey测试)	UKEY_TEST",		ht_cmds,	&change_menu},
		{"5",					"(boot加载)	RE_BOOT",			ht_cmds,	&return_boot},
#ifdef NFUN
		{"6",					"(新功能测试)	NEW_FUN",			ht_cmds,	&function},
#endif

		{NULL,NULL,NULL,NULL},
};

static struct cmd_handler cmds_1[] =
{
		{"0",					"(退出)		QUIT", 				ht_cmds,	&hardware_test},
		{"1",					"(全部硬件测试)	HARD_TEST", 	ht_cmds,	&hardware_test},
		{"2",					"(SPI测试)		SPI_TEST", 		ht_cmds,	&hardware_test},
		{"3",					"(E2PROM测试)	EEPROM_TEST",	ht_cmds,	&hardware_test},
		{"4",					"(EFLASH测试)	EFLASH_TEST",	ht_cmds,	&hardware_test},
		{"5",					"(SRAM测试)		SRAM_TEST",		ht_cmds,	&hardware_test},
		{"6",					"(SL811测试)	SL811_TEST",	ht_cmds,	&hardware_test},
		{"7",					"(UKEY测试)		USB_TEST",		ht_cmds,	&hardware_test},
		{"8",					"(FPGA测试)		FPGA_TEST",		ht_cmds,	&hardware_test},
		{NULL,NULL,NULL,NULL},
};

static struct cmd_handler cmds_2[] =
{
		{"0",				"(退出)		QUIT", 				ht_cmds,	&hardware_test},
		{"1",				"(全部算法测试)	HARD_TEST", 	ht_cmds,	&alg_test},
		{"2",	 			"(SM1测试)		SM1_TEST", 		ht_cmds,	&alg_test},
		{"3",	 			"(SM2测试)		SM2_TEST",		ht_cmds,	&alg_test},
		{"4",	 			"(SM3测试)		SM3_TEST",		ht_cmds,	&alg_test},
		{"5",	 			"(SM4测试)		SM4_TEST",		ht_cmds,	&alg_test},
		{"6",	 			"(随机数测试)	RAN_TEST",		ht_cmds,	&alg_test},
		{"7",	 			"(RAS测试)		RAS_TEST",		ht_cmds,	&alg_test},
		{"8",	 			"(SHA1测试)		SHA1_TEST",		ht_cmds,	&alg_test},
		{"9",	 			"(AES测试)		AES_TEST",		ht_cmds,	&alg_test},
		{"10",			"(DES测试)		DES_TEST",		ht_cmds,	&alg_test},
		{"11",			"(FPGA_KEY测试)	KEY_TEST",	ht_cmds,	&alg_test},
		{NULL,NULL,NULL,NULL},
};

static int function(const char* args[], write_func_t output, uint32_t param)
{
//	uint16_t index_use = 0,index_in = 0;

//	index_use = 1;
//	index_in  = 2;
//	uint8_t *ECC_data = pvPortMalloc(sizeof(EnvelopedECCKey)+16);

//	importkeypair1(index_use,index_in, ECC_data);
//	vPortFree(ECC_data);
	
	return 0;
}
static int help(const char* args[], write_func_t output, uint32_t param)
{
    //output(param, "builtin commands:\r\n", 0);
		cmdhelp *t_opt;
		uint16_t i;
		struct cmd_handler *cmd_p;
		switch (cmd_menu){
			case MAIN_MEUN:
				cmd_p = cmds_0;
				break;
			case HARD_MEUN:
				cmd_p = cmds_1;
				break;
			case ALG_MEUN:
				cmd_p = cmds_2;
				break;
			default:
				cmd_p = cmds_0;
				break;
		}
		output(param, "\r\n", 2);
		output(param, "*********************************", 30);
		output(param, "\r\n", 2);
    for(i=0; cmd_p[i].cmd != NULL; i++)
    {
			output(param, "No.", 3);
			output(param, cmd_p[i].cmd, strlen(cmd_p[i].cmd));
			output(param, ":", 1);
			output(param, " ", 1); 
			output(param, cmd_p[i].comment, strlen(cmd_p[i].comment));
			output(param, "\r\n", 2);
		}
		output(param, "*********************************", 30);
		output(param, "\r\n", 2);
    return 0;
}




static int hardware_test(const char* args[], write_func_t output, uint32_t param)
{
	//printf("check with %s \n",__FUNCTION__);
	//printf("arg0 = %s",args[0]);
	uint32_t arg;
	uint8_t test_all_sign=0;
	uint8_t state=0;
	uint8_t ret_v,count;
	char Opera_Pin[16]={0};
	void *  UkeyHandle;
	void * hApplication;
	
	arg = htoi(args[0]);
	arg |= MENU(cmd_menu);
	switch(arg){
	case HARD_TEST:
		test_all_sign=1;

	case SPI_TEST:
		//printTag(START,state,"SPIFLASH");
		state = spiflash_task();
		printTag(END,state,"SPIFLASH");
		if(!test_all_sign)
			break;
		
	case EEPROM_TEST:
		//printTag(START,state,"E2PROM");
		state = eeprom_task();
		printTag(END,state,"E2PROM");
		if(!test_all_sign)
			break;
		
	case EFLASH_TEST:
		//printTag(START,state,"EFLASH");
		state = eflash_task();
		printTag(END,state,"EFLASH");
		if(!test_all_sign)
			break;
		
	case SRAM_TEST:
		//printTag(START,state,"SRAM");
		state = MIM_task();
		printTag(END,state,"SRAM");
		if(!test_all_sign)
			break;
		
	case SL811_TEST:
		//printTag(START,state,"SL811");
		state = SL811_task();
		printTag(END,state,"SL811");
		if(!test_all_sign)
			break;
	
	case FPGA_TEST:
		//printTag(START,state,"FPGA");
		state = FPGA_task();
	printTag(END,state,"FPGA");
/****************Ukey test*********************/
//xSemaphoreTake(USBMutexSemaphore, portMAX_DELAY);
//	memset(Opera_Pin,1,16);

//	for(uint16_t i=0;i<1000;i++ ){
//		Ukey_Connect(&UkeyHandle);
//		ret_v = Ukey_DevAuth(UkeyHandle);
//		if(0 != ret_v){
//			 printf("Ukey_DevAuth fail,res is 0x%x\r\n",ret_v);
////			 //SKF_DisConnectDev(UkeyHandle);
////		   //UkeyHandle = NULL;
//		}
//		state = Ukey_Creat_User(0,Opera_Pin, UkeyHandle,&hApplication);
//		//vTaskDelay(2000);
//		SKF_DisConnectDev(UkeyHandle);
//		printTag(END,state,"creatUser");
//		sl811_os_init();
//		if(!Slave_Detach()){
//			//printf("Ukey exist\r\n");
//			if(UkeyStateflag){
//				while(count < 3){ //枚举不成功，尝试3次
//					//vTaskDelay(2000);
//					printf("Ukey retry\r\n");
//					if(sl811_disk_init()) count++;
//					else break;
//				}
//			}
//		}
//		else{
//			//sl811_os_init();
//		}
//		DeleteApplication();
//		//vTaskDelay(1000);
//	}
//				
//xSemaphoreGive(USBMutexSemaphore);
/****************Ukey test*********************/
		if(!test_all_sign)
			break;
		
	
	case USB_TEST:
	if(!test_all_sign){
		//printTag(START,state,"USB");
		state = USB_enum_task();
		printTag(END,state,"USB");
		break;
	}

	default:
		if(test_all_sign){
			//printTag(END,state,"END");
			if(state)
				printf("错误代码为：%d\r\n",state);
		}
		test_all_sign=0;
	}
return state;
}

static int alg_test(const char* args[], write_func_t output, uint32_t param)
{
	//printf("check with %s \n",__FUNCTION__);
	//printf("arg0 = %s",args[0]);
	uint8_t test_all_sign=0;
	MCUSelfCheck* test_result;
	uint8_t state = 0;
	uint32_t arg,temp = 0;

//ArgFlag = *(uint8_t *)FPGA_ARG_REG_ADDR;
	arg = htoi(args[0]);
	arg |= MENU(cmd_menu);
	fpga_init();
	switch(arg){
	case ALG_TEST:
			test_all_sign=1;
	case SM1_TEST:
			if((ArgFlag&0x04) == 0){
				test_result->sm1FPGA = 2;
				printTag(INVALID,state,"SM1_FPGA");
			}
			else{
				//sm1测试FPGA
				printf("FPGA SM1 alg valid !\r\n");
				state = power_on_testsm1FPGA();
				printTag(END,state,"SM1_FPGA");
				if(state){
					test_result->sm1FPGA = 1;
				}
			}
			//sm1测试MCU
			state = power_on_testsm1();
			printTag(END,state,"SM1_MCU");
			if(state){
				test_result->sm1MCU = 1;
			}
			if(!test_all_sign) break;
			
	case SM2_TEST:
			//查看SM2算法
			if((ArgFlag&0x01) == 0){
				test_result->sm2enc = 2;
				test_result->sm2ver = 2;
				test_result->sm2exchange = 2;
				printTag(INVALID,state,"SM2_FPGA");
			}
			else{
				//sm2加密测试
				for(uint8_t i =0; i<HSM2_NUM; i++){
					state = power_on_testsm2enc();
				if(HSMD1)
					if(state) printf("The err hsmd1 is %d",HSMD1_NUM);
				}
				printTag(END,state,"SM2_FPGA_加解密");
				if(state){
					test_result->sm2enc = 1;
				}
				//sm2签名测试
				//printf("test channel = %x\r\n",FPGA_DATA_SM2_HSM2+i);
				for(uint8_t i =0; i<HSM2_NUM; i++){
					state = power_on_testsm2ver();
				if(HSMD1)
					if(state) printf("The err hsmd1 is %d",HSMD1_NUM);
				}
				printTag(END,state,"SM2_FPGA_签&验");
				if(state){
					test_result->sm2ver = 1;
				}
				 
			if(!HSMD1){
				//sm2密钥交换测试
				state = power_on_testsm2exchange();
				printTag(END,state,"SM2_MCU_密钥交换");
				if(state){
					test_result->sm2exchange = 1;
				}
			}
			}
				//sm2测试 mcu
			state = power_on_testsm2mcu();
			printTag(END,state,"SM2_MCU");
			if(state){
				test_result->sm2mcu = 1;
			}
			if(!test_all_sign) break;
	case SM3_TEST:
			//查看SM3算法
			if((ArgFlag&0x08) == 0){
				test_result->sm3FPGA = 2;
				printTag(INVALID,state,"SM3_FPGA");
			}
			else{
				//sm3 FPGA
				state = FPGA_SM3_test();
				printTag(END,state,"SM3_FPGA");
				if(state){
					test_result->sm3FPGA = 1;
				}
			}
			//sm3 MCU
			state = power_on_testsm3();
			printTag(END,state,"SM3_MCU");
			if(state){
				test_result->sm3MCU = 1;
			}	
			if(!test_all_sign) break;
	case SM4_TEST:
	
			//查看SM4算法
			if((ArgFlag&0x10) == 0){
				test_result->sm4FPGA = 2;
				printTag(INVALID,state,"SM4_FPGA");
			}
			else{
				//sm4测试 FPGA
				state = power_on_testsm4FPGA();
				printTag(END,state,"SM4_FPGA");
				if(state){
					test_result->sm4FPGA = 1;
				}
			}
			//sm4测试
			state = power_on_testsm4();
			printTag(END,state,"SM4_MCU");
			if(state){
				test_result-> sm4MCU = 1;
			}
			if(!test_all_sign) break;
	case RAN_TEST:	
			//随机性检测
			state = RandomCyclicalTest();
			printTag(END,state,"RAN");
			if(state)
				test_result->Randomcheck = 1;
			//printTag(END,state,"END");
			if(!test_all_sign) break;
	case RAS_TEST:
			//ras
			state = power_on_testras();
			printTag(END,state,"RAS");
			if(state){
				test_result->ras = 1;
			}
			if(!test_all_sign) break;
	case SHA1_TEST:
			//sha1_sha256
			state = power_on_testshaX();
			printTag(END,state,"SHA1");
			if(state){
				test_result->sha = 1;
			}
			if(!test_all_sign) break;
	case AES_TEST:
			//aes
			state = power_on_testaes();
			printTag(END,state,"AES");
			if(state){
				test_result->aes = 1;
			}
			if(!test_all_sign) break;
	case DES_TEST:
			//des
			state = power_on_testdes();
			printTag(END,state,"DES");
			if(state)
				test_result->des = 1;
			if(!test_all_sign) break;
	
	case FPGA_KEY:
			//key
			state = FPGAsetgetkey();
			printTag(END,state,"KEY");
			if(state)
				;
			if(!test_all_sign) break;
	}
return state;
}
static int change_menu(const char* args[], write_func_t output, uint32_t param)
{
		uint32_t arg;
	uint8_t state=0;
	const char* do_cmd;
	int res,temp;
	temp = cmd_menu;
	arg = htoi(args[0]);
	arg |= MENU(cmd_menu);
	switch(arg){
	case ALL_LINK:
		cmd_menu = HARD_MEUN;  //切换菜单
		do_cmd = "1";          //发命令
		res=hardware_test(&do_cmd, uart_output, UARTA);
		cmd_menu = ALG_MEUN;
		do_cmd = "1";
		res=alg_test(&do_cmd, uart_output,UARTA);
		cmd_menu =temp;
		break;
	
	case USB_LINK:
		cmd_menu = HARD_MEUN;
		do_cmd = "7";
		res=hardware_test(&do_cmd, uart_output, UARTA);
		cmd_menu =temp;
		break;

	}
		return res;
}
static int return_boot(const char* args[], write_func_t output, uint32_t param)
{
	printf("Are you sure return the mcu to factory state ? 1:yes	2:no \r\n");
	char cmd[3]={0};
	while(!uart_get_char(UARTA,cmd));
	if(memcmp(cmd,"1",1)) return 0;
	printf("------恢复出厂!!!------\r\n");
	return_to_boot();
	printf("------重新启动!!!------\r\n");
	NVIC_SystemReset();
	return 0;
}


static int reset(const char* args[], write_func_t output, uint32_t param)
{
    output(param, "system reset...\r\n", 0);

    return 0;
}


extern float detY0;
extern float detTheta0;

static int sysinfo(const char* args[], write_func_t output, uint32_t param)
{
	return 0;
}
int tolower(int c)
{
	if (c >= 'A' && c <= 'Z')
	{
		return c + 'a' - 'A';
	}
	else
	{
		return c;
	}
}

int htoi(const char s[])
{
	int i;
	int n = 0;
	if (s[0] == '0' && (s[1]=='x' || s[1]=='X'))
	{
		i = 2;
	}
	else
	{
		i = 0;
	}
	for (; (s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'z') || (s[i] >='A' && s[i] <= 'Z');++i)
	{
		if (tolower(s[i]) > '9')
		{
			n = 16 * n + (10 + tolower(s[i]) - 'a');
		}
		else
		{
			n = 16 * n + (tolower(s[i]) - '0');
		}
	}
	return n;
}

static void show_config_item(const char* name, uint32_t type, const char* val, uint32_t param)
{
    struct output *out = (struct output*)param;


    out->func(out->dev, name, 0);
    out->func(out->dev, " = ", 3);
    out->func(out->dev, val, 0);
    out->func(out->dev, "\r\n", 2);
}

static int set(const char* args[], write_func_t output, uint32_t param)
{
    char    val[32];
    int     err;
//    struct output out = {output, param};

    if( (args[0] == NULL) || (args[0][0] == 0) )
    {
//        list_config(show_config_item, (uint32_t)&out);
        return 0;
    }
    else if( (args[1] == NULL) || (args[1][0] == 0) )
    {
//        err = read_config(args[0], val, sizeof(val));
        if( (err != 0) && (output != NULL) )
        {
            output(param, "data not found\r\n", 0);
            return 0;
        }

        if(output != NULL)
        {
            output(param, args[0], 0);
            output(param, " = ", 3);
            output(param, val, 0);
            output(param, "\r\n", 2);
        }
    }
    else
    {
//        err = write_config(args[0], args[1]);
        if( (err < 0) && (output != NULL) )
            output(param, "data not found\r\n", 0);
        else if ( (err == 1) && (output != NULL) )
            output(param, "to make it work, a reset is needed\r\n", 0);
    }

    return 0;
}


static int logReg(const char* args[], write_func_t output, uint32_t param)
{
	if (log_cbhd == 0)
	{
		//log_cbhd = log_register_outputcb(uart_output, (uint32_t)&UART1_Handler);
	}
	else
	{
		//log_unregister_outputcb(log_cbhd);
	}

    return 0;
}

//extern FATFS fs;

static int nandFormat(const char* args[], write_func_t output, uint32_t param)
{
  printf("format start, waiting 50s\r\n");
  //bsp_W25QXX_EraseChip();
  printf("format finish\r\n");
  return 0;
}

#define MAX_FNAME_LEN       63

//FRESULT f_deldir(const TCHAR *path)
//{
//  FRESULT res;
#if 0
  DIR   dir;     /* 文件夹对象 */ //36  bytes
  FILINFO fno;   /* 文件属性 */   //32  bytes
  TCHAR file[MAX_FNAME_LEN + 2] = {0};
#if _USE_LFN
  TCHAR lname[MAX_FNAME_LEN + 2] = {0};
#endif

#if _USE_LFN
  fno.lfsize = MAX_FNAME_LEN;
  fno.lfname = lname;    //必须赋初值
#endif
  //打开文件夹
  res = f_opendir(&dir, path);

  //持续读取文件夹内容
  while((res == FR_OK) && (FR_OK == f_readdir(&dir, &fno)))
  {
    //若是"."或".."文件夹，跳过
    if(0 == strlen(fno.fname))          break;      //若读到的文件名为空
    if(0 == strcmp(fno.fname, "."))     continue;   //若读到的文件名为当前文件夹
    if(0 == strcmp(fno.fname, ".."))    continue;   //若读到的文件名为上一级文件夹

    memset(file, 0, sizeof(file));
#if _USE_LFN
    if(fno.lfname[0] != 0)
      sprintf((char*)file, "%s/%s", path, (*fno.lfname) ? fno.lfname : fno.fname);
    else
#endif
      sprintf((char*)file, "%s/%s", path, fno.fname);

    if (fno.fattrib & AM_DIR)
    {//若是文件夹，递归删除
      res = f_deldir(file);
    }
    else
    {//若是文件，直接删除
      res = f_unlink(file);
    }
  }

  //删除本身
  if(res == FR_OK)    res = f_unlink(path);
#endif
//  return res;
//}


static int pwd(const char* args[], write_func_t output, uint32_t param)
{
    char    buf[128];

    if(output == NULL)
//        return -PERR_EINVAL;

//    f_getcwd(buf, sizeof(buf));

    output(param, buf, 0);
    output(param, "\r\n", 2);

    return 0;
}


/*cmd running programme*/
static struct cmd_handler* get_cmd_handler(const char* cmd)
{
  int i,swi = 0;
	static struct cmd_handler *cmd_p;

	//转换菜单，cmd_0,cmd_1,cmd_2
	if(cmd[0] < '0' ||cmd[0] > '9') return NULL;
	swi = cmd_menu;
	if(MAIN_MEUN == cmd_menu){
		switch(atoi(cmd)){
			case HARD_MEUN :
				cmd_menu = HARD_MEUN;
				break;
			case ALG_MEUN :
				cmd_menu = ALG_MEUN;
				break;
			default:
				cmd_menu = MAIN_MEUN;
		}
	}
	else if(BACK_MEUN == atoi(cmd)){
		cmd_menu = MAIN_MEUN;
	}
	swi = (swi == cmd_menu? 0 : 1);
	switch (cmd_menu){
		case MAIN_MEUN:
			cmd_p = cmds_0;
			break;
		case HARD_MEUN:
			cmd_p = cmds_1;
			break;
		case ALG_MEUN:
			cmd_p = cmds_2;
			break;
 		default:
			cmd_p = cmds_0;
			break;
		}
		if(!swi){
			for(i=0; cmd_p[i].cmd != NULL; i++)
			{
					//printf("cmd%d = %s/n",i,cmd_p[i].cmd);
					if(strcmp(cmd, cmd_p[i].cmd) == 0)
					{
							return &cmd_p[i];
					}
			}
		}
	return NULL;
}

static int exec_cmd_builtin(const char*cmd, const char *args[], write_func_t write_func, uint32_t dev)
{
    struct cmd_handler *hd;

    hd = get_cmd_handler(cmd);
    if(hd == NULL)
    {
        if(write_func)
					//write_func(dev, "Invalid command.\r\n", 0);
					help(args, write_func, dev);
        return 0;
    }
    hd->handler(args, write_func, dev);
		help(args, write_func, dev);
    return 0;
}

static int exec(const char *args[], write_func_t write_func, uint32_t dev)
{
    const char    *cmd = args[0];

#if 0
    printf("exec: ");
    for(int i=0; (args[i] != NULL) && (i<MAX_ARGS); i++)
        printf("%s, ", args[i]);
    printf("\r\n");
#endif
    return exec_cmd_builtin(cmd, &args[0], write_func, dev);
}

#define IS_SEPARATOR(c) ((c==' ') || (c=='\t'))

static int  split_line(char *data, const char*args[], uint32_t max_num)
{
    int i=0;
    int cnt = 0;

    while(i<max_num)
    {
        if( (data[cnt] == '\n') || (data[cnt] == '\r') || (data[cnt] == '\0') )
            break;

        while(IS_SEPARATOR(data[cnt]))
          cnt++;

        if( (data[cnt] == '\n') || (data[cnt] == '\r') || (data[cnt] == '\0') )
          break;

        args[i++] = &data[cnt];

        while( !IS_SEPARATOR(data[cnt]) && (data[cnt]!='\n') && (data[cnt]!='\r') && (data[cnt] != '\0') )
            cnt++;

        if( (data[cnt] == '\n') || (data[cnt] == '\r') || (data[cnt] == '\0') )
          break;

        data[cnt++] = '\0';   //
    }

    if(i<max_num)
      args[i] = NULL;

    return i;
}

static void parse_and_exec(char *data, write_func_t write_func, uint32_t dev)
{
    const char *args[MAX_ARGS] = {NULL};
    int n;

    n = split_line(data, args, MAX_ARGS);

    if(n <= 0) args[0] = "hp";
    exec(args, write_func, dev);
}

static void print_prompt(write_func_t write_func, uint32_t dev)
{
    const char prompt[] = "> ";

    write_func(dev, prompt, sizeof(prompt)-1);

}

void console_run(read_ch_func_t readch_func, write_func_t write_func, uint32_t dev)
{
    char        data[128] = {0};
    uint32_t    cnt = 0;
    int         len;
    int         err = 0;
    bool        damaged = false;
    char        ch;
    const char crnl[2] = "\r\n";

    print_prompt(write_func, dev);
    do
    {
        len = readch_func(dev, &ch);
        if(len == 1)
        {
            if(ch == 8) //backspace
            {
                if(cnt >= 1)
                {
                  write_func(dev, &ch, 1);
                  ch = ' ';
                  write_func(dev, &ch, 1);
                  ch = 8;
                  write_func(dev, &ch, 1);
                  data[cnt--] = 0;
                }
                continue;
            }
            else if(!isprint(ch) && (ch != '\r') && (ch != '\n') )
            {
                //write_func(dev, &ch, 1);
                memset(data, 0, cnt);
                cnt = 0;
                write_func(dev, crnl, sizeof(crnl));
                print_prompt(write_func, dev);
                continue;
            }
            else if(ch == '\r')
            {
                write_func(dev, crnl, 2);
            }

            write_func(dev, &ch, 1);
            data[cnt++] = ch;

            if( (data[cnt-1] == '\r') || (data[cnt-1] == '\n') )
            {
                if( (!damaged) && (cnt >= 1) )
                {
                    data[cnt-1] = '\0';
                    parse_and_exec(data, write_func, dev);
                }
                else
                    damaged = false;

                memset(data, 0, cnt);
                cnt = 0;

                //write_func(dev, crnl, sizeof(crnl));
                print_prompt(write_func, dev);
            }
            else if(cnt == sizeof(data))
            {
                damaged = true;
                cnt = 0;
            }
        }
        else
//            OSTimeDly(MS_TO_TICKS(50));
        vTaskDelay(50);
        if(len < 0)
            err = len;

    }while(!err);
}
#define MAX_CMD_LEN 64
void system_cmd(const char* cmd)
{
    char tmp_cmd[MAX_CMD_LEN];
    int l;

    if((l=strlen(cmd)) >= MAX_CMD_LEN)
        return;
    else
    {
        memcpy(tmp_cmd, cmd, l);
        tmp_cmd[l] = 0;
    }

    parse_and_exec(tmp_cmd, NULL, 0);
}
#endif
