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
DeviceStateStr DevStatus = FactoryStatus;		// ���뿨�����ڼ��״̬��־

extern FlashData eFlash;
//extern uint8_t admin_num;
#define IS_NOT_STATUS(status)	((status)!=devstatus)
#define IS_STATUS(status)	((status)==devstatus)

#define MAINKEY_PART_COUNT	2 			 // ����Կ��������

unsigned char main_key[MAINKEY_LEN] = {0};			//����Կ
unsigned char main_key_mcu[MAINKEY_LEN];	//mcu�ڲ��洢����Կ����
//unsigned char main_key_ukey[MAINKEY_LEN];	//ukey������Կ����

unsigned char null_array[MAINKEY_LEN];

unsigned char back_key[MAINKEY_LEN];
//unsigned char back_key_part[3][MAINKEY_LEN];

//unsigned char **mainkey_part = NULL; // ����Կ���� 0Ϊ�豸���� 1Ϊ�û�����
//unsigned char * backkey_part[3]; // ������Կ����	
unsigned int adminTotalNum = DEF_ADMIN_TOTAL_NUM;	  // ����Ա������
unsigned int adminAccessNum = DEF_ADMIN_ACCESS_NUM; // ��������Ա����
//unsigned char user_mainkey_part[2][MAINKEY_LEN];


// ��Կ�ָ�״̬����Կʹ�û�����
unsigned char *mainkey_ex = NULL;	 // ������Կ
unsigned char *backkey_ex = NULL;	 // ���ݱ�����Կ
unsigned char *authkey_ex = NULL;  // ����Ա�����֤��Կ
unsigned char *authkeyO_ex= NULL;  // ����Ա�����֤��Կ
SM2KeyPair *mgtkeypair_ex = NULL;  // �豸������Կ 
// ��Կ�ָ�״̬��Կ����
unsigned char **mainkey_part_ex = NULL; // ����Կ���� 0Ϊ�豸���� 1Ϊ�û�����
unsigned char **backkey_part_ex = NULL; // ������Կ����
unsigned int adminTotalNum_ex = DEF_ADMIN_TOTAL_NUM;	 // ����Ա������
unsigned int adminAccessNum_ex = DEF_ADMIN_ACCESS_NUM; // ������֤�Ĺ���Ա����
unsigned int adminNowNum_ex = 0;   									   // ��ǰ����Ա����
unsigned char *adminLogindex_ex = NULL;                 // ��ֹ����Ա�ظ���¼���õļ�¼����
unsigned char user_mainkey_part_ex[2][MAINKEY_LEN];


//�ϵ��ȡ�豸״̬��Ϣ
void GetFlashData(void)
{
	uint16_t i=0;
	uint32_t *data_p=NULL;
	data_p=pvPortMalloc(sizeof(FlashData));
	
	for(;i<(sizeof(FlashData)/4);i++){
		data_p[i]=eflash_read_word(EFLASH_DATA_ADDR+i*4);
	}
	if(data_p[0]== (*(volatile UINT32 *)(SM_FLASH_FF_VALUE_ADDR))){
		//eflah��������
		print(PRINT_DEV,"first power\r\n");
#if 1
		clear_fs();
		FS_config();				//�����ϵ������ļ�ϵͳ
#endif				
		memset(&eFlash,0,sizeof(eFlash));
		eFlash.DATA_STATUS = 0x0001; //�رտ��Ǳ������״��Ѿ��ϵ�
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
		//�����豸״̬�Ĵ���
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
	//Sm1234״̬
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
	
//���������У��У���롣
	GenUserKeyCheck(str,sizeof(FlashData)-32,&btr);

	eflash_erase_page(EFLASH_DATA_ADDR);
	for(;i < sizeof(FlashData);i+=4){
		eflash_write_word(EFLASH_DATA_ADDR+i,*(uint32_t *)str);
		str+=4;
	}
}

int writeOperData(int index, char *PIN, int PINlen, unsigned char *R2, unsigned char *authkey){
		BaseType_t er=pdFALSE;
		//er=xSemaphoreTake(UkeyInsertSemaphore,portMAX_DELAY);			//����Ϊһ����ʱʱ��
}

int clean_usr_eflash(void){
	memset(&eFlash,0,sizeof(FlashData));
	WriteFlashData();
	return 0;
}

//return to boot
int cleanmcu_toboot(void){
	clean_usr_eflash();
	//clear_filedir_file("1:/kek");				//���KEK��Կ�ļ�
	//clear_filedir_file("1:/cipher");		//����û���Կ����Կ�ļ�
	//clear_fs_file();										//����û��ļ�
	clear_fs();													//����ļ�
	UserLogout();
	BackUpAdminQuit();
	return_to_boot();
	return 0;
}

//�ָ�����̬
int go_to_factory(void){
	uint16_t res;
	uint16_t ECC_n=0,RAS1024_n=0,RAS2048_n=0,KEK_n=0;
	clean_usr_eflash();
	*(unsigned short *)FPGA_MCU_DRIVER_WRITE = 0x0001;
	eFlash.ADMINNUM = 0;
	
//	res = (query_ciph(&ECC_n,&RAS1024_n,&RAS2048_n) || query_kek(&KEK_n));
//	if((ECC_n+RAS1024_n+RAS2048_n+KEK_n) <= 10){
//		clear_filedir_file("1:/kek");   		//���KEK��Կ�ļ�
//		clear_filedir_file("1:/cipher");   	//����û���Կ����Կ�ļ�
//		clear_fs_file();        						//����û��ļ�
//	}
//	else{
		clear_fs();						//����ļ�
		FS_config();
//	}
	UserLogout();
	BackUpAdminQuit();
	return 0;
}
