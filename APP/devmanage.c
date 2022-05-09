#include "devmanage.h"
#include "shamir.h"
#include "fpga_sm4.h"
#include "interface.h"
#include "FreeRTOS.h"
#include "spiflash.h"
#include "spiflash_addr.h"
#include "fpga_sm3.h"
#include "eflash.h"
#include "semphr.h"
#include "fatfs_file.h"

#define PRINT_DEV 2
DeviceStateStr DevStatus = FactoryStatus;		// 密码卡运行期间的状态标志

extern FlashData eFlash;
//extern uint8_t admin_num;
#define IS_NOT_STATUS(status)	((status)!=devstatus)
#define IS_STATUS(status)	((status)==devstatus)

#define MAINKEY_PART_COUNT	2 			 // 主密钥分量数量

unsigned char main_key[MAINKEY_LEN] = {0};			//主密钥
unsigned char main_key_mcu[MAINKEY_LEN];	//mcu内部存储主密钥分量
//unsigned char main_key_ukey[MAINKEY_LEN];	//ukey中主密钥分量

unsigned char null_array[MAINKEY_LEN];

unsigned char back_key[MAINKEY_LEN];
//unsigned char back_key_part[3][MAINKEY_LEN];

//unsigned char **mainkey_part = NULL; // 主密钥分量 0为设备分量 1为用户分量
//unsigned char * backkey_part[3]; // 备份密钥分量	
unsigned int adminTotalNum = DEF_ADMIN_TOTAL_NUM;	  // 管理员总数量
unsigned int adminAccessNum = DEF_ADMIN_ACCESS_NUM; // 最少认理员数量
//unsigned char user_mainkey_part[2][MAINKEY_LEN];


// 密钥恢复状态下密钥使用缓冲区
unsigned char *mainkey_ex = NULL;	 // 保护密钥
unsigned char *backkey_ex = NULL;	 // 备份保护密钥
unsigned char *authkey_ex = NULL;  // 管理员身份认证密钥
unsigned char *authkeyO_ex= NULL;  // 操作员身份认证密钥
SM2KeyPair *mgtkeypair_ex = NULL;  // 设备管理密钥 
// 密钥恢复状态密钥分量
unsigned char **mainkey_part_ex = NULL; // 主密钥分量 0为设备分量 1为用户分量
unsigned char **backkey_part_ex = NULL; // 备份密钥分量
unsigned int adminTotalNum_ex = DEF_ADMIN_TOTAL_NUM;	 // 管理员总数量
unsigned int adminAccessNum_ex = DEF_ADMIN_ACCESS_NUM; // 最少认证的管理员数量
unsigned int adminNowNum_ex = 0;   									   // 当前管理员数量
unsigned char *adminLogindex_ex = NULL;                 // 防止管理员重复登录设置的记录索引
unsigned char user_mainkey_part_ex[2][MAINKEY_LEN];


//上电获取设备状态信息
void GetFlashData(void)
{
	uint16_t i=0;
	uint32_t *data_p=NULL;
	data_p=pvPortMalloc(sizeof(FlashData));
	
	for(;i<(sizeof(FlashData)/4);i++){
		data_p[i]=eflash_read_word(EFLASH_DATA_ADDR+i*4);
	}
	if(data_p[0]== (*(volatile UINT32 *)(SM_FLASH_FF_VALUE_ADDR))){
		//eflah中无数据
		print(PRINT_DEV,"first power\r\n");
#if 1
		clear_fs();
		FS_config();				//初次上电配置文件系统
#endif				
		memset(&eFlash,0,sizeof(eFlash));
		eFlash.DATA_STATUS = 0x0001; //关闭开盖保护，首次已经上电
		eFlash.DEV_STATE=FactoryStatus;
		WriteFlashData();

	}else{
		memcpy(&eFlash,data_p,sizeof(FlashData));
	}
	vPortFree(data_p);
}
void Update_DevState(DeviceStateStr state)
{
	//uint16_t sta = 0x0001;
	eFlash.DEV_STATE = state;
		//设置设备状态寄存器
	*(unsigned short *)FPGA_MCU_DRIVER_WRITE = (0x0001<<(eFlash.DEV_STATE));
}

DeviceStateStr Get_DevState(void)
{
	DeviceStateStr status;
	status = eFlash.DEV_STATE;
	return status;
} 



void Get_DEVICESTATUS(MCUSelfCheck *status)
{
	//Sm1234状态
	//status->Dev_State = eFlash.DEV_STATE;
	
}
	
void data_xor(uint8_t *source1,uint8_t *source2, uint8_t *result, uint16_t datalen)
{
	uint16_t i=0;
	for(;i<datalen;i++)
		*(result+i) = *(source1+i) ^ *(source2+i);
}
void ReadeFlashData(FlashData * user_data_temp)
{
	uint16_t i=0;
	uint8_t *data_p=(uint8_t *)user_data_temp;
	
	for(;i<(sizeof(FlashData)/4);i++){
		*(uint32_t *)data_p=eflash_read_word(EFLASH_DATA_ADDR+i*4);
	}
}

void WriteFlashData(void)
{
	uint16_t i=0;
	uint32_t btr=0;
//	FlashData  data_temp;
//	ReadeFlashData(&data_temp);
	uint8_t *str=(uint8_t *)&eFlash;
	
//添加完整性校验校验码。
	GenUserKeyCheck(str,sizeof(FlashData)-32,&btr);

	eflash_erase_page(EFLASH_DATA_ADDR);
	for(;i < sizeof(FlashData);i+=4){
		eflash_write_word(EFLASH_DATA_ADDR+i,*(uint32_t *)str);
		str+=4;
	}
}

int writeOperData(int index, char *PIN, int PINlen, unsigned char *R2, unsigned char *authkey){
		BaseType_t er=pdFALSE;
		//er=xSemaphoreTake(UkeyInsertSemaphore,portMAX_DELAY);			//更新为一个超时时间
}

int clean_usr_eflash(void){
	memset(&eFlash,0,sizeof(FlashData));
	WriteFlashData();
	return 0;
}

//return to boot
int cleanmcu_toboot(void){
	clean_usr_eflash();
	//clear_filedir_file("1:/kek");				//清除KEK密钥文件
	//clear_filedir_file("1:/cipher");		//清除用户密钥对密钥文件
	//clear_fs_file();										//清除用户文件
	clear_fs();													//清除文件
	UserLogout();
	BackUpAdminQuit();
	return_to_boot();
	return 0;
}

//恢复出厂态
int go_to_factory(void){
	uint16_t res;
	uint16_t ECC_n=0,RAS1024_n=0,RAS2048_n=0,KEK_n=0;
	clean_usr_eflash();
	*(unsigned short *)FPGA_MCU_DRIVER_WRITE = 0x0001;
	eFlash.ADMINNUM = 0;
	
//	res = (query_ciph(&ECC_n,&RAS1024_n,&RAS2048_n) || query_kek(&KEK_n));
//	if((ECC_n+RAS1024_n+RAS2048_n+KEK_n) <= 10){
//		clear_filedir_file("1:/kek");   		//清除KEK密钥文件
//		clear_filedir_file("1:/cipher");   	//清除用户密钥对密钥文件
//		clear_fs_file();        						//清除用户文件
//	}
//	else{
		clear_fs();						//清除文件
		FS_config();
//	}
	UserLogout();
	BackUpAdminQuit();
	return 0;
}
