#ifndef _DEVMANAGE_H_
#define _DEVMANAGE_H_

#include "fpga_sm4.h"
#include "fpga_sm2.h"
#include "cipher.h"
#include "user_manage.h"
#include "config.h"

#define FPGA_SOURCE			1
#define MCU_SOURCE			0
#define KEY_SOURCE		FPGA_SOURCE
#define MAINKEY_LEN				SM4_KEY_LEN

//eflash 0x7F000 - 0x80000 ���������� 8��page
#define	EFLASH_DATA_ADDR			0x7F000		//�洢�豸��Ϣ�ĵ�ַ
#define SPIFLASH_DEVDATA_OFFSET ((void *)(0))
#define SHUDUN_NAME				"Shudun Information Technology Co., Ltd."
//#define MAGIC_DWORD     "\x19\x12\x12\x17"

#define DEVICE_SET					1
#define DEVICE_RESET				2
#define DEVICE_INFO_ADDR		0x10
#define DEVICE_DATA_ADDR		DEVICE_INFO_ADDR + 4			//32byte
#define UKEY_DATA_ADDR			DEVICE_DATA_ADDR + 64			// 4byte

// �豸״̬
typedef enum {
		FactoryStatus = 0,// ����̬->����̬         TOMUC  +1
		InitialStatus,		// ��װ̬(δ��������Ա�����������豸��Կ)1
		ReadyStatus,			// ����̬->����̬/����̬2    
		WorkStatus,				// ����̬->����̬3
		ManagementStatus,	// ����̬->����̬/����̬/����̬4
		DestroyStatus,		// ����̬->����̬5
}DeviceStateStr;


#pragma pack(1)
//������eflashһ������512B
typedef struct {
	unsigned int  DATA_STATUS;		//��2λ��ʾ�Ƿ����ÿ��Ǳ�������
																//!0xA5A5 �ر�
																// 0xA5A5 ����
																//��2λ��ʾ�Ѿ��״��ϵ�
																//0x0000 -- �³����豸  
																//0x0001 -- ���״��ϵ��豸
	unsigned int  DEV_STATE;			//�豸״̬
	unsigned char MAINKEY_MCU[MAINKEY_LEN];
	unsigned char AUTHKEY[DEF_OPERATOR_NUM_MAX][MAINKEY_LEN];
	unsigned short OPERNUM;				//��2�ֽڴ������Ա����2�ֽڴ������Ա		//4B
	unsigned short ADMINNUM;
	unsigned char Devkeypair[sizeof(SM2KeyPair)];
	unsigned char Devkeypin[16];
	unsigned char Hmac[32];			  //�����ã����붨���ڽṹ���β
	//unsigned char MGTPRIKEY[sizeof(SM2PrivateKey)];
  //unsigned char MAGIC_NUMBER[sizeof(SM2KeyPair)];
} FlashData;
/*
typedef struct {
	unsigned char IssuerName[40];			//�豸������������
	unsigned char DeviceName[16];			//�豸�ͺ�
	unsigned char DeviceSerial[16];		//�豸���
	unsigned int FPGAVersion;					//FPGA�汾
	unsigned int ARMVersion;					//MCU�汾
	unsigned int APIVersion;			
	unsigned int StandardVersion;			//֧�ֵĽӿڹ淶�汾	
	unsigned int AsymAlgAbility[2];		
	unsigned int SymAlgAbility;
	unsigned int HashAlgAbility;
	unsigned int BufferSize;			
} DEVICEINFOhua3;
*/
typedef struct DeviceInfo_st{
	unsigned char IssuerName[40];  //�豸������������
	unsigned char DeviceName[16];  //�豸�ͺ�
	unsigned char DeviceSerial[16];//�豸���
	unsigned int DeviceVersion;
	unsigned int StandardVersion;  //֧�ֵĽӿڹ淶�汾
	unsigned int AsymAlgAbility[2];
	unsigned int SymAlgAbility;
	unsigned int HashAlgAbility;
	unsigned int BufferSize;
}DEVICEINFO;

typedef struct EnvelopedECCKey_st{
unsigned int ulAsymmAlgID;            	// �����Գ���Կ��ECC�㷨��ʶ
unsigned int ulSymmAlgID;             	// �Գ��㷨��ʶ���޶�ECBģʽ
unsigned int ulBits;     								// ECC��Կ�Ե���Կλ����
unsigned char  cbEncryptedPriKey[32];		// ECC��Կ��˽Կ������		ECCref_MAX_LEN
ECCrefPublicKey PubKey;        					// ECC��Կ�ԵĹ�Կ
ECCCipher ECCCipherBlob;    						// ��ECC������Կ���ܵĶԳ���Կ���Ľṹ
}EnvelopedECCKey;

typedef struct {
	unsigned int SM2_Status;
	unsigned int SM3_Status;
	unsigned int SM4_Status;
	unsigned int RND_Status;
	unsigned int Dev_State;
} DEVICESTATUS;


typedef struct {
	unsigned char spiflash;
	unsigned char sram;//
	unsigned char sm2mcu;
	unsigned char sm2enc;
	unsigned char sm2ver;
	unsigned char sm2exchange;
	unsigned char sm4FPGA;
	unsigned char sm4MCU;
	unsigned char sm1FPGA;
	unsigned char sm1MCU;
	unsigned char ras;
	unsigned char sha;
	unsigned char aes;
	unsigned char sm3FPGA;
	unsigned char sm3MCU;
	unsigned char usrcheck;		  //�û�����Կ�����Լ��
	unsigned char Randomcheck;  //����Լ��
	unsigned char des;          //Ukey err num: bit 1
} MCUSelfCheck;

#pragma pack()

//�û���¼״̬
typedef enum {
	NOUSER_LOGGED_IN = 0		//���û���¼
	, ADMIN_LOGGING_IN		//����Ա��¼������
	, ADMIN_LOGGED_IN		//����Ա�ѵ�¼
	, OPERATOR_LOGGED_IN		//����Ա�ѵ�¼
} LoginStatus;


void data_xor(unsigned char *source1,unsigned char *source2,unsigned char *result, unsigned short datalen);

void readFlashData(void);

void setDBGStatus(int status);

int setAdminPolicy(int totalnum, int accessnum);
void getAdminPolicy(int *totalnum, int *accessnum);

// �豸�����ܳ�ʼ��
int DeviceManagementInit(void);

void Update_DevState(DeviceStateStr state);
DeviceStateStr Get_DevState(void);

// �豸��ʼ�����������̬������̬������̬��ִ��
//int DeviceInit(char *PIN, int PINlen, int ukeyindex);
int DeviceInit(void);
// 
int CreataOperator(char *PIN, int PINlen, int ukeyindex);

int DelOperator(void);

// �û���֤���������̬������̬������̬��ִ�У���״̬�½�֧�ֹ���Ա��¼�ָ�������Կ�����лָ�
//           ����̬�¹���Ա��¼�������̬
//           ����̬�µ�¼Ϊ��ͨ��¼
int UserLogin(uint16_t logusrtype, char *PIN, int PINlen);

// �û��˳���֤���������̬������̬������̬������̬������̬��ִ��
int UserLogout(void);

int getAdminRemaining(void);


// ���ܿ��豸���ݱ���
int DevMsgBackup(char *PIN, int PINlen);
// ���ܿ��豸���ݻָ�	
int DevMsgRecover(char *PIN, int PINlen);

// ����Ա�������ݣ��������̬��ִ��
int MgrBackup(void);

// ����Ա�ָ����ݣ��������̬������̬������̬������̬��ִ��
int MgrRecover(void);

//�ָ���������ʱ������Ա��¼
int RegcoverLogin(char *PIN, int PINlen, int* RemNum);
//�˳����ݵ�¼
int RegcoverOut(void);

// ����Ա�������ݣ��������̬��ִ��
int MgrCleanup(void);

// ����Ա�������ݣ��������̬��ִ��
int MgrDestroy(void);
int RetUsbKey(/*char *PIN, int PINlen*/void);
// ����Կ�ӽ������� �����û���Կ�ӽ���
int MainKeyEncrypt(unsigned char *enc, unsigned char *data, int *len);
int MainKeyDecrypt(unsigned char *data, unsigned char *enc, int *len);

void getDevModelSerial(unsigned char *model, unsigned char *serial);
int myttest(void);


void Update_DevState(DeviceStateStr state);

DeviceStateStr Get_DevState(void);


void ReadeFlashData(FlashData * user_data);

void WriteFlashData(void);

void Get_DEVICESTATUS(MCUSelfCheck *status);	//�忨����Դ״̬
void GetFlashData(void);
//���eflash���û�����
int clean_usr_eflash(void);
//������ݲ����ص�boot����
int cleanmcu_toboot(void);
//�ָ�����̬
int go_to_factory(void);

#endif
