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

//eflash 0x7F000 - 0x80000 用做数据区 8个page
#define	EFLASH_DATA_ADDR			0x7F000		//存储设备信息的地址
#define SPIFLASH_DEVDATA_OFFSET ((void *)(0))
#define SHUDUN_NAME				"Shudun Information Technology Co., Ltd."
//#define MAGIC_DWORD     "\x19\x12\x12\x17"

#define DEVICE_SET					1
#define DEVICE_RESET				2
#define DEVICE_INFO_ADDR		0x10
#define DEVICE_DATA_ADDR		DEVICE_INFO_ADDR + 4			//32byte
#define UKEY_DATA_ADDR			DEVICE_DATA_ADDR + 64			// 4byte

// 设备状态
typedef enum {
		FactoryStatus = 0,// 出厂态->就绪态         TOMUC  +1
		InitialStatus,		// 初装态(未创建管理员仅仅生成了设备密钥)1
		ReadyStatus,			// 就绪态->工作态/管理态2    
		WorkStatus,				// 工作态->就绪态3
		ManagementStatus,	// 管理态->就绪态/擦除态/销毁态4
		DestroyStatus,		// 销毁态->就绪态5
}DeviceStateStr;


#pragma pack(1)
//不超过eflash一个扇区512B
typedef struct {
	unsigned int  DATA_STATUS;		//高2位表示是否启用开盖保护功能
																//!0xA5A5 关闭
																// 0xA5A5 开启
																//低2位表示已经首次上电
																//0x0000 -- 新出厂设备  
																//0x0001 -- 已首次上电设备
	unsigned int  DEV_STATE;			//设备状态
	unsigned char MAINKEY_MCU[MAINKEY_LEN];
	unsigned char AUTHKEY[DEF_OPERATOR_NUM_MAX][MAINKEY_LEN];
	unsigned short OPERNUM;				//高2字节代表管理员，低2字节代表操作员		//4B
	unsigned short ADMINNUM;
	unsigned char Devkeypair[sizeof(SM2KeyPair)];
	unsigned char Devkeypin[16];
	unsigned char Hmac[32];			  //检验用，必须定义在结构体结尾
	//unsigned char MGTPRIKEY[sizeof(SM2PrivateKey)];
  //unsigned char MAGIC_NUMBER[sizeof(SM2KeyPair)];
} FlashData;
/*
typedef struct {
	unsigned char IssuerName[40];			//设备生产厂商名称
	unsigned char DeviceName[16];			//设备型号
	unsigned char DeviceSerial[16];		//设备编号
	unsigned int FPGAVersion;					//FPGA版本
	unsigned int ARMVersion;					//MCU版本
	unsigned int APIVersion;			
	unsigned int StandardVersion;			//支持的接口规范版本	
	unsigned int AsymAlgAbility[2];		
	unsigned int SymAlgAbility;
	unsigned int HashAlgAbility;
	unsigned int BufferSize;			
} DEVICEINFOhua3;
*/
typedef struct DeviceInfo_st{
	unsigned char IssuerName[40];  //设备生产厂商名称
	unsigned char DeviceName[16];  //设备型号
	unsigned char DeviceSerial[16];//设备编号
	unsigned int DeviceVersion;
	unsigned int StandardVersion;  //支持的接口规范版本
	unsigned int AsymAlgAbility[2];
	unsigned int SymAlgAbility;
	unsigned int HashAlgAbility;
	unsigned int BufferSize;
}DEVICEINFO;

typedef struct EnvelopedECCKey_st{
unsigned int ulAsymmAlgID;            	// 保护对称密钥的ECC算法标识
unsigned int ulSymmAlgID;             	// 对称算法标识，限定ECB模式
unsigned int ulBits;     								// ECC密钥对的密钥位长度
unsigned char  cbEncryptedPriKey[32];		// ECC密钥对私钥的密文		ECCref_MAX_LEN
ECCrefPublicKey PubKey;        					// ECC密钥对的公钥
ECCCipher ECCCipherBlob;    						// 用ECC保护公钥加密的对称密钥密文结构
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
	unsigned char usrcheck;		  //用户和密钥完整性检测
	unsigned char Randomcheck;  //随机性检测
	unsigned char des;          //Ukey err num: bit 1
} MCUSelfCheck;

#pragma pack()

//用户登录状态
typedef enum {
	NOUSER_LOGGED_IN = 0		//无用户登录
	, ADMIN_LOGGING_IN		//管理员登录过程中
	, ADMIN_LOGGED_IN		//管理员已登录
	, OPERATOR_LOGGED_IN		//操作员已登录
} LoginStatus;


void data_xor(unsigned char *source1,unsigned char *source2,unsigned char *result, unsigned short datalen);

void readFlashData(void);

void setDBGStatus(int status);

int setAdminPolicy(int totalnum, int accessnum);
void getAdminPolicy(int *totalnum, int *accessnum);

// 设备管理功能初始化
int DeviceManagementInit(void);

void Update_DevState(DeviceStateStr state);
DeviceStateStr Get_DevState(void);

// 设备初始化：允许出厂态、擦除态、销毁态下执行
//int DeviceInit(char *PIN, int PINlen, int ukeyindex);
int DeviceInit(void);
// 
int CreataOperator(char *PIN, int PINlen, int ukeyindex);

int DelOperator(void);

// 用户认证：允许出厂态、擦除态、销毁态下执行，此状态下仅支持管理员登录恢复备份密钥并进行恢复
//           擦除态下管理员登录进入管理态
//           就绪态下登录为普通登录
int UserLogin(uint16_t logusrtype, char *PIN, int PINlen);

// 用户退出认证：允许出厂态、工作态、管理态、擦除态、销毁态下执行
int UserLogout(void);

int getAdminRemaining(void);


// 加密卡设备数据备份
int DevMsgBackup(char *PIN, int PINlen);
// 加密卡设备数据恢复	
int DevMsgRecover(char *PIN, int PINlen);

// 管理员备份数据：允许管理态下执行
int MgrBackup(void);

// 管理员恢复数据：允许出厂态、管理态、擦除态、销毁态下执行
int MgrRecover(void);

//恢复备份数据时，管理员登录
int RegcoverLogin(char *PIN, int PINlen, int* RemNum);
//退出备份登录
int RegcoverOut(void);

// 管理员擦除数据：允许管理态下执行
int MgrCleanup(void);

// 管理员销毁数据：允许管理态下执行
int MgrDestroy(void);
int RetUsbKey(/*char *PIN, int PINlen*/void);
// 主密钥加解密运算 用于用户密钥加解密
int MainKeyEncrypt(unsigned char *enc, unsigned char *data, int *len);
int MainKeyDecrypt(unsigned char *data, unsigned char *enc, int *len);

void getDevModelSerial(unsigned char *model, unsigned char *serial);
int myttest(void);


void Update_DevState(DeviceStateStr state);

DeviceStateStr Get_DevState(void);


void ReadeFlashData(FlashData * user_data);

void WriteFlashData(void);

void Get_DEVICESTATUS(MCUSelfCheck *status);	//板卡各资源状态
void GetFlashData(void);
//清除eflash中用户数据
int clean_usr_eflash(void);
//清除数据并返回到boot控制
int cleanmcu_toboot(void);
//恢复出厂态
int go_to_factory(void);

#endif
