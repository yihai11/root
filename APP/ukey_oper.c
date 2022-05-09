/***********************************************************************
 * Copyright (c)  2020, beijing shudun Co.,Ltd .
 * All rights reserved.
 * Filename    : ukey_oper.c
 * Description : c file of Ukey operate
 *									1.create admin/operator Ukey
 *									2.read user data from Ukey
 * Author(s)   : jaime
 * version     : V1.0
 * Modify date : 2020-10-26
 ***********************************************************************/

#include "ukey_oper.h"
#include "SKFInterface.h"
#include "sl811_usb.h"
#include "FreeRTOS.h"
#include "Semphr.h"
#include "fpga_sm2.h"
#include <string.h>
#include "SKFError.h"
#include "sl811.h"
#include "common.h"
char AppName[32] ;
char AppFileName[16]  =  "Appfile";
unsigned char	 pbRandom[32] = {0};
#define WAITUKEY_TIME		10000
unsigned int FileSize = 1*1024;

void Ukey_ReadFinish(void)
{
	//sl811_os_init();
}
unsigned int Ukey_Connect(void **ukey_handle)
{
	int rtval;
	int8_t ukey_drv_name[256];
	ULONG drv_name_len = 256;
	//uint32_t dev_status;
	//sl811_disk_init();
	rtval = SKF_EnumDev(1, (LPSTR)ukey_drv_name, &drv_name_len);
	if (rtval != SAR_OK)
	{
		print(PRINT_811USB,"SKF EumDev ERR\r\n");
	}
	else
	{
		//print(PRINT_811USB,"drv_name_len is %ld \r\n", drv_name_len);
		print(PRINT_811USB,"UKey name %s\r\n", ukey_drv_name);
	}
	
	rtval = SKF_ConnectDev((LPSTR)ukey_drv_name,ukey_handle);
	if (rtval != SAR_OK)
	{
		print(PRINT_811USB,"SKF ConDev ERR is 0x%x\r\n", rtval);
	}
	else
	{
		print(PRINT_811USB,"SKF ConDev OK!!!\r\n");
	}
	
	return rtval;
//	rtval = SKF_GetDevState(*ukey_handle, &dev_status);
//	if (rtval != SAR_OK)
//	{
//		print(PRINT_811USB,"SKF_GetDevState error, rtval is 0x%x\n", rtval);		
//	}
//	else
//	{
//		print(PRINT_811USB,"dev_status is 0x%x\n", dev_status);
//	}
}

//	rtval = SKF_GetDevInfo(ukey_dev, &dev_info);
unsigned int Ukey_DevAuth(void * UkeyHandle)
{
	 unsigned int ulRet;
	 //unsigned char	 pbRandom[32] = {0};
	 unsigned long	 ulRandomLen = 8;

	 unsigned char	 pbKey[16] = {0};
	 unsigned int	 ulKeyLen = 16;

	 unsigned char	 pbOut[64] = {0};
	 unsigned long	 ulOutLen;
	 uint8_t i=0;
	 void * hKey = NULL;
	 BLOCKCIPHERPARAM EncryptParam;

	 memset(pbRandom, 0, sizeof(pbRandom));
	 //ReadLen = 4*((ulRandomLen + 2 + 7)/4);
	 ulRet = SKF_GenRandom(UkeyHandle, pbRandom, ulRandomLen);
	 if(ulRet != SAR_OK){
		 return ulRet;
	 }
	 //print(PRINT_811USB,"Gen ran data status is:%d\r\n",ulRet);
	 print(PRINT_811USB,"ran data is:\r\n");
	 for(;i<ulRandomLen;i++)
	 print(PRINT_811USB,"0x%x ",pbRandom[i]);

	 //ReadLen = 64;
	 //print(PRINT_811USB,"ran data is ok\r\n");
	 memcpy(pbKey, (unsigned char*)"1234567812345678", ulKeyLen);
	 ulRet = SKF_SetSymmKey(UkeyHandle, pbKey, SGD_SMS4_ECB, &hKey);
	 if(ulRet != SAR_OK){
		 return ulRet;
	 }
	 print(PRINT_811USB,"SetSymmKey ok\r\n");
	 EncryptParam.PaddingType = 0;
	 ulRet = SKF_EncryptInit(hKey, EncryptParam);
	 if(ulRet != SAR_OK){
		 SKF_CloseHandle(hKey);
		 return ulRet;
	 }
	 print(PRINT_811USB,"EnInit ok\r\n");
	 
	 memset(pbOut, 0x00, sizeof(pbOut));
	 ulRet = SKF_Encrypt(hKey, pbRandom, 16, pbOut, &ulOutLen);
	 if(ulRet != SAR_OK){
		 SKF_CloseHandle(hKey);
		 return ulRet;
	 }
	 print(PRINT_811USB,"Enc ok\r\n");
	 ulRet = SKF_CloseHandle(hKey);
	 if(ulRet != SAR_OK){
		 return ulRet;
	 }
	 print(PRINT_811USB,"Close Handle ok\r\n");
	 ulRet = SKF_DevAuth(UkeyHandle, pbOut, ulOutLen);
	 if(ulRet != SAR_OK){
		 return ulRet;
	 }
	 print(PRINT_811USB,"DevAuth ok\r\n");
	 ulRet = SKF_SetLabel(UkeyHandle, "New_Label");
	 if(ulRet != SAR_OK){
		 return ulRet;
	 }
	  print(PRINT_811USB,"SetLabel ok\r\n");
    return ulRet;
	
}

int Ukey_Creat_User(int UserType, char *PIN,void * UkeyHandle,void ** hApplication)
{
		int ret_v= 0;
		char Admin_Pin[16]={0};
		ret_v = Ukey_DevAuth(UkeyHandle);
		if(0 != ret_v){
			 print(PRINT_811USB,"UK_DAuth ERR 0x%x\r\n",ret_v);
			 return ERR_UKEY_DEVAUTH;
		}
		strcpy(AppName,"UserApp");
		strcpy(Admin_Pin,"AdminPIN");

		//检查是否是空Ukey ,不是管理员操作员备份员KEY
		if(0 == SKF_OpenApplication( UkeyHandle,"UserApp",hApplication)){
				SKF_CloseApplication(*hApplication);
				*hApplication = NULL;
			  return ERR_UKEY_NOFREE;
		}
		//创建应用
		printf_buff_byte((unsigned char *)PIN,16);
		ret_v = SKF_CreateApplication(UkeyHandle,AppName,Admin_Pin, 10, PIN, \
																	10,SECURE_ANYONE_ACCOUNT,hApplication);
		if(0 != ret_v){		//创建失败
			print(PRINT_811USB,"new app ERR 0x%x\r\n",ret_v);
			SKF_DeleteApplication(UkeyHandle,"UserApp");
			return ERR_UKEY_APP;

		}
		print(PRINT_811USB,"app new \r\n");
		ret_v = SKF_CreateFile(*hApplication,AppFileName,FileSize,SECURE_ANYONE_ACCOUNT,SECURE_ANYONE_ACCOUNT);
		if(0 != ret_v){		//创建文件失败
			print(PRINT_811USB,"CR file ERR %d\r\n",ret_v);
			SKF_DeleteApplication(UkeyHandle,"UserApp");
			return ERR_UKEY_FILE;
		}
		print(PRINT_811USB,"file new\r\n");
		return 0;
}


/*
//int writeAdminData(int index, char *PIN, int PINlen, unsigned char *R2, unsigned char *authkey, \
//							SM2PublicKey *pk,unsigned char *backkeypart, unsigned int TotalNum, unsigned int AccessNum)
//{
//	BaseType_t er=pdFALSE;
//	UKeyData UKey;
//	BYTE *EncUkey = NULL;
//	unsigned int EncUkeyLtmp = 0;
//	int EncUkeyL = 0;
//	BYTE Key[20] ={0};

//	//检查Ukey是否连接就绪 FPGA_DATA_LEN(l)
//	er=xSemaphoreTake(UkeyInsertSemaphore,portMAX_DELAY);			//更改为一个明确的超时时间
//	
//	if(er ==pdFALSE )
//	{
//			return ERR_UKEY_TIMEOUT;
//	}
//	//创建管理员用户 0
//	ret_v = Ukey_Creat_User(0, PIN);
//	if( 0 != ret_v )
//	{
//			Ukey_DisConnect(hApplication);
//		  UkeyHandle = 	NULL;				
//			return ret_v;
//	}
//	memset(&UKey, 0, sizeof(UKeyData));
//	UKey.index = index;
//	UKey.AdmTotalNum  = TotalNum;
//	UKey.AdmAccessNum = AccessNum;
//	memcpy(UKey.MAINKEY_PART, R2, MAINKEY_LEN);
//	memcpy(UKey.AUTHKEY, authkey, MAINKEY_LEN);
//	memcpy(UKey.MGTPUBKEY, pk, sizeof(SM2PublicKey));
//	memcpy(UKey.BACKKEYPART, backkeypart, SHAMIR_PART_LEN(MAINKEY_LEN));
//	//writeFlash((void *)DBG_UKEYDATA_FLASH_OFFSET(index), &UKey, sizeof(UKeyData));
//	
//	//获取加密数据密钥 通过PIN和UKEY序列号		
//	ret_v = Ukey_GetKey(PIN,PINlen,Key);
//	if( 0 != ret_v )
//	{
//			Ukey_DisConnect(UkeyHandle);
//		  UkeyHandle = 	NULL;				
//			return ERR_UKEY_PIN;
//	}
//	//加密数据
//	EncUkeyL = FPGA_DATA_LEN(sizeof(UKeyData));
//	EncUkey = malloc(EncUkeyL);
//	EncUkeyL = sizeof(UKeyData);
//	SM4Encrypt(Key,EncUkey,(BYTE*)&UKey,&EncUkeyL);
//	//把加密密文写入到UKEY中
//	EncUkeyLtmp = EncUkeyL;
//	ret_v = Ukey_WriteFile(hApplication,FileName,0,EncUkey,EncUkeyLtmp);
//	if( 0 != ret_v )
//	{
//			S_free(EncUkey);
//			Ukey_DisConnect(UkeyHandle);
//		  UkeyHandle = 	NULL;
//			return ERR_UKEY_FILE;
//	}
//	S_free(EncUkey);
//	Ukey_DisConnect(UkeyHandle);
//	UkeyHandle = 	NULL;
//	return 0;
//}
*/

//创建管理员Ukey
//input  index ：	用户索引号
//			 Pin	 ：	用户密码
//			 PInlen：	密码长度
//			 *R2   ：	要写入ukey的主密钥分量指针
//			 *authkey:身份认证密钥指针
//			 *PK :		设备密钥公钥指针
//			 *backkeypart:	备份密钥分量指针
//			 TotalNum ：允许注册的管理员总数
//			 AccessNum: 管理态所需最少登录的管理员数
int CreateAdminUkey(int index, char *PIN, int PINlen, unsigned char *R2, unsigned char *authkey, \
SM2PublicKey *pk,unsigned char *backkeypart, unsigned int TotalNum, unsigned int AccessNum)
{
	int ret_v;
	BaseType_t er=pdFALSE;
	UKeyData UKey;
	void *  UkeyHandle;
	void * hApplication;
	char Opera_Pin[16]={0};
	uint32_t data_len;
	
	ret_v = Ukey_Connect(&UkeyHandle);
	if(ret_v) return ERR_UKEY_CONNECT;
	print(PRINT_811USB,"UKey CON\r\n");
	memset(Opera_Pin,0,16);
	memcpy(Opera_Pin,PIN,PINlen);

	ret_v = Ukey_Creat_User(0,Opera_Pin, UkeyHandle,&hApplication);
	if( 0 != ret_v ){
			//SKF_DeleteApplication(UkeyHandle,"UserApp");
			SKF_DisConnectDev(UkeyHandle);
		  UkeyHandle = NULL;
			return ret_v;
	}
	print(PRINT_811USB,"UKey NEW app+file\r\n");
	memset(&UKey, 0, sizeof(UKeyData));
	UKey.index = index;
	UKey.AdmTotalNum  = TotalNum;
	UKey.AdmAccessNum = AccessNum;
	memcpy(UKey.MAINKEY_PART, R2, MAINKEY_LEN);
	memcpy(UKey.AUTHKEY, authkey, MAINKEY_LEN);
	memcpy(UKey.MGTPUBKEY, pk, sizeof(SM2PublicKey));
	memcpy(UKey.BACKKEYPART, backkeypart, SHAMIR_PART_LEN(MAINKEY_LEN));

	data_len= sizeof(UKeyData);
	ret_v = SKF_WriteFile(hApplication,AppFileName,0,(uint8_t *)&UKey,data_len);
	if( 0 != ret_v ){
			print(PRINT_811USB,"WE file ERR is %d\r\n",ret_v);
			SKF_DeleteApplication(UkeyHandle,"UserApp");
			SKF_DisConnectDev(UkeyHandle);
		  UkeyHandle = NULL;
			return ERR_UKEY_FILE;
	}
	print(PRINT_811USB,"UKey WE file\r\n");
	SKF_DisConnectDev(UkeyHandle);
	UkeyHandle = NULL;		
	return 0;
}
int CreateOperUkey(int index, char *PIN, int PINlen, unsigned char *R2, unsigned char *authkey)
{
	int ret_v;
	UKeyData UKey;
//	char ukey_drv_name[256];
	char Opera_Pin[16]={0};
//	uint32_t drv_name_len = 256;
//	uint32_t dev_status;	
	void * UkeyHandle;				//  ukey传来的句柄
	void * hApplication;

	ret_v = Ukey_Connect(&UkeyHandle);
	if(ret_v) return ERR_UKEY_CONNECT;
#if UKEY_DEBUG
	print(PRINT_811USB,"UKey CON\r\n");
#endif
	memset(Opera_Pin,0,16);
	memcpy(Opera_Pin,PIN,PINlen);
	ret_v = Ukey_Creat_User(1, Opera_Pin, UkeyHandle,&hApplication);
	if( 0 != ret_v ){
			//SKF_DeleteApplication(UkeyHandle,"UserApp");
			SKF_DisConnectDev(UkeyHandle);
		  UkeyHandle = NULL;
			return ret_v;
	}
	memset(&UKey, 0, sizeof(UKeyData));
	UKey.index = index;
	memcpy(UKey.MAINKEY_PART, R2, MAINKEY_LEN);
	memcpy(UKey.AUTHKEY, authkey, MAINKEY_LEN);
	//writeFlash((void *)DBG_UKEYDATA_FLASH_OFFSET(index), &UKey, sizeof(UKeyData));
	
	ret_v = SKF_WriteFile(hApplication,AppFileName,0,(uint8_t *)&UKey,sizeof(UKeyData));
	if( 0 != ret_v ){
			SKF_CloseApplication(hApplication);
			SKF_DeleteApplication(UkeyHandle,"UserApp");
			SKF_DisConnectDev(UkeyHandle);
		  UkeyHandle = NULL;
			return ERR_UKEY_FILE;
	}
	SKF_CloseApplication(hApplication);
	SKF_DisConnectDev(UkeyHandle);
	UkeyHandle = NULL;
	return 0;
}

unsigned int Ukey_OpenApplication(void * UkeyHandle,char* szAppName,void** hApplication)
{
	unsigned int ulRet;
	ulRet = SKF_OpenApplication(UkeyHandle, szAppName, hApplication);
	ulRet &= 0xff;
	return ulRet;
}


int readUserData(unsigned char *index, char *PIN, int PINlen, unsigned char *R2,  \
unsigned char *authkey, unsigned char *backkeypart,unsigned int *TotalNum, 			  \
unsigned int *AccessNum)
{
	
	UKeyData UKey;
	uint8_t ret_v =0;
//	uint8_t v_time=0;
//	uint32_t dev_status;
	char ukeypin[16]={0};
	void * UkeyHandle= 0;				//  ukey传来的句柄
  void * hApplication =0 ;
//	BYTE Key[20] ={0};
	unsigned long OutLen = 0;

	ret_v = Ukey_Connect(&UkeyHandle);
	if( 0 != ret_v )
	{
			print(PRINT_811USB,"UKey CON ERR：0x%x\r\n",ret_v);
			return ERR_UKEY_CONNECT;
	}
	
	ret_v = Ukey_OpenApplication(UkeyHandle,"UserApp",&hApplication);
	if((SAR_APPLICATION_NOT_EXISTS & 0xff) == ret_v) {
		SKF_DisConnectDev(UkeyHandle);
		UkeyHandle = NULL;
		return ERR_UKEY_VOID;
	}
	if( 0 != ret_v ){
		print(PRINT_811USB,"UKey OP app ERR %x\r\n",ret_v);
		SKF_DisConnectDev(UkeyHandle);
		UkeyHandle = NULL;
		return ERR_UKEY_APP;
	}
	print(PRINT_811USB,"UKey OP app\r\n");
	memset(ukeypin,0,16);
	memcpy(ukeypin,PIN,PINlen);
	print(PRINT_811USB,"pin len %d\r\n",PINlen);
	printf_buff_byte((uint8_t*)ukeypin,16);
	print(PRINT_811USB,"&happ 0x%x,happ 0x%x,val 0x%x\r\n",(uint32_t)&hApplication,(uint32_t)hApplication,*(uint32_t *)hApplication);
	ret_v =  SKF_VerifyPIN(hApplication,1,ukeypin,&OutLen);
	if( 0 != ret_v )
	{
			print(PRINT_811USB,"UKey VER ERR 0x%x\r\n",ret_v);
			SKF_CloseApplication(hApplication);
			SKF_DisConnectDev(UkeyHandle);
			UkeyHandle = NULL;
			if(ret_v == (SAR_PIN_LOCKED&0x00ff)){
				return ERR_UKEY_LOCK;
			}
			return ret_v;
	}
	print(PRINT_811USB,"UKey VER pin\r\n");
	OutLen = sizeof(UKeyData);
	ret_v = SKF_ReadFile(hApplication,AppFileName,0,sizeof(UKeyData),(unsigned char*)&UKey,&OutLen);
	if( 0 != ret_v )
	{
			SKF_CloseApplication(hApplication);
			SKF_DisConnectDev(UkeyHandle);
			UkeyHandle = NULL;
			return ERR_UKEY_FILE;
	}
	print(PRINT_811USB,"UKey RD file\r\n");
	*index = UKey.index;
	memcpy(R2, UKey.MAINKEY_PART, MAINKEY_LEN);
	memcpy(authkey, UKey.AUTHKEY, MAINKEY_LEN);
	memcpy(backkeypart, UKey.BACKKEYPART, SHAMIR_PART_LEN(MAINKEY_LEN));
	if(NULL != TotalNum && NULL !=AccessNum)
	{
			*TotalNum = UKey.AdmTotalNum;
		  *AccessNum= UKey.AdmAccessNum;
	}
	SKF_CloseApplication(hApplication);
	SKF_DisConnectDev(UkeyHandle);
	UkeyHandle = NULL;
	return 0;
}

int ResetUserPin(int index, char *PIN, int PINlen,FlashData *ukey_eFlash){
	
	UKeyData UKey;
	unsigned long OutLen = 0;
	uint8_t ret_v =0;
	void * UkeyHandle = 0;
	void * hApplication =0 ;
	char ukeypin[32]={0};
	ret_v = Ukey_Connect(&UkeyHandle);
	if( 0 != ret_v )
	{
			print(PRINT_811USB,"UKey CON ERR %x\r\n",ret_v);
			return ERR_UKEY_CONNECT;
	}	
	ret_v = Ukey_OpenApplication(UkeyHandle,"UserApp",&hApplication);
	if((SAR_APPLICATION_NOT_EXISTS & 0xff) == ret_v) 
	{
		SKF_DisConnectDev(UkeyHandle);
		UkeyHandle = NULL;
		return ERR_UKEY_VOID;
	}
		if( 0 != ret_v )
	{
			print(PRINT_811USB,"UKey OP app ERR %x \r\n",ret_v);
			SKF_DisConnectDev(UkeyHandle);
			//SKF_CloseApplication(hApplication);
			return ERR_UKEY_APP;
	}
	OutLen = sizeof(UKeyData);
	ret_v = SKF_ReadFile(hApplication,AppFileName,0,sizeof(UKeyData),(unsigned char*)&UKey,&OutLen);
	if( 0 != ret_v )
	{
			print(PRINT_811USB,"SKF RD File %x \r\n",ret_v);
			SKF_CloseApplication(hApplication);
			SKF_DisConnectDev(UkeyHandle);
			return ERR_UKEY_FILE;
	}
	if(memcmp(UKey.AUTHKEY,ukey_eFlash->AUTHKEY[UKey.index],16)){
		SKF_CloseApplication(hApplication);
		SKF_DisConnectDev(UkeyHandle);
		return ERR_UKEY_FIELD;
	}
	if(index != UKey.index){
		SKF_CloseApplication(hApplication);
		SKF_DisConnectDev(UkeyHandle);
		return ERR_UKEY_KIND;
	}
	memcpy(ukeypin,PIN,PINlen);
	//ret_v = Ukey_ChangePIN(hApplication, 1, szOldPin, szNewPin);
	ret_v = SKF_UnblockPIN(hApplication, "AdminPIN", ukeypin,  (ULONG *)&ukeypin[20]);
	if( 0 != ret_v )
	{
			print(PRINT_811USB,"SKF PIN ERR %x\r\n",ret_v);
			SKF_CloseApplication(hApplication);
			SKF_DisConnectDev(UkeyHandle);
			UkeyHandle = NULL;
			return ERR_UKEY_CHANGEPIN;
	}
	SKF_CloseApplication(hApplication);
	SKF_DisConnectDev(UkeyHandle);
	UkeyHandle = NULL;
	return 0;
}	

int ChangeUserPin(uint8_t usrtype,uint16_t old_len,char *pwd_old,uint16_t new_len,char *pwd_new,FlashData *ukey_eFlash){
	UKeyData UKey;
	uint32_t ret_v =0;
	char oldpin[16]={0};
	char newpin[16]={0};
	void * UkeyHandle = 0;
	void * hApplication =0 ;
	unsigned long OutLen = 0;
	ret_v = Ukey_Connect(&UkeyHandle);
	if( 0 != ret_v )
	{
			print(PRINT_811USB,"UKey CON ERR\r\n");		
			return ERR_UKEY_CONNECT;
	}
	
	ret_v = Ukey_OpenApplication(UkeyHandle,"UserApp",&hApplication);
	if((SAR_APPLICATION_NOT_EXISTS & 0xff) == ret_v) return ERR_UKEY_VOID;
	if( 0 != ret_v ){
			print(PRINT_811USB,"UKey OP app ERR %x \r\n",ret_v);
			SKF_CloseApplication(hApplication);
			SKF_DisConnectDev(UkeyHandle);		
			UkeyHandle = NULL;
			return ERR_UKEY_APP;
	}
	memset(oldpin,0,16);
	memcpy(oldpin,pwd_old,old_len);
	printf_buff_byte((uint8_t*)oldpin,16);
	print(PRINT_811USB,"&happ 0x%x,happ 0x%x,val 0x%x\r\n",(uint32_t)&hApplication,(uint32_t)hApplication,*(uint32_t *)hApplication);
	ret_v = SKF_VerifyPIN(hApplication,1,oldpin,&OutLen);
	if( 0 != ret_v )
	{
		print(PRINT_811USB,"UKey VER pin ERR 0x%x\r\n",ret_v);
		SKF_CloseApplication(hApplication);
		SKF_DisConnectDev(UkeyHandle);
		UkeyHandle = NULL;
		if(ret_v == (SAR_PIN_LOCKED&0x00ff)){
			return ERR_UKEY_LOCK;
		}
		return ERR_UKEY_PIN;
	}
	OutLen = sizeof(UKeyData);
	ret_v = SKF_ReadFile(hApplication,AppFileName,0,sizeof(UKeyData),(unsigned char*)&UKey,&OutLen);
	if( 0 != ret_v )
	{
			print(PRINT_811USB,"SKF RD File %x\r\n",ret_v);
			SKF_CloseApplication(hApplication);
			SKF_DisConnectDev(UkeyHandle);
			return ERR_UKEY_FILE;
	}
	
	if(usrtype > 2){	//工作态，只允许修改操作员pin
		if(UKey.index < 3){
			SKF_CloseApplication(hApplication);
			SKF_DisConnectDev(UkeyHandle);
			UkeyHandle = NULL;
			return ERR_UKEY_KIND;
		}
		if(usrtype != UKey.index){
			SKF_CloseApplication(hApplication);
			SKF_DisConnectDev(UkeyHandle);
			UkeyHandle = NULL;
			return ERR_UKEY_KIND;
		}
	}
	else{
		if(UKey.index >= 3){
			SKF_CloseApplication(hApplication);
			SKF_DisConnectDev(UkeyHandle);
			UkeyHandle = NULL;
			return ERR_UKEY_KIND;
			
		}
		if(memcmp(UKey.AUTHKEY,ukey_eFlash->AUTHKEY[UKey.index],16)){
			SKF_CloseApplication(hApplication);
			SKF_DisConnectDev(UkeyHandle);
			UkeyHandle = NULL;
			return ERR_UKEY_FIELD;
		}
	}

	memcpy(newpin,pwd_new,new_len);
	ret_v = SKF_ChangePIN(hApplication, 1, oldpin, pwd_new,&OutLen);
	//ret_v = SKF_UnblockPIN(hApplication, "AdminPIN", ukeypin,  (ULONG *)&ukeypin[20]);
	if( 0 != ret_v )
	{
			print(PRINT_811USB,"SKF CK PIN %x\r\n",ret_v);
			SKF_CloseApplication(hApplication);
			SKF_DisConnectDev(UkeyHandle);
			UkeyHandle = NULL;
			return ERR_UKEY_CHANGEPIN;
	}
	SKF_CloseApplication(hApplication);
	SKF_DisConnectDev(UkeyHandle);
	UkeyHandle = NULL;
	return 0;
}	
int Ukey_Enc_WithKey(UINT8 *in_data,UINT32 in_len,UINT8 *key,UINT32 key_len,UINT8 *out_data){
	uint8_t ret_v =0;
	void * UkeyHandle = 0;
	void * hApplication =0 ;
	void * hKey = NULL;
	unsigned long	 ulOutLen;
	BLOCKCIPHERPARAM EncryptParam;
	ret_v = Ukey_Connect(&UkeyHandle);
	if( 0 != ret_v )
	{
			print(PRINT_811USB,"UKey CON ERR\r\n");		
			return ERR_UKEY_CONNECT;
	}
	
	ret_v = Ukey_OpenApplication(UkeyHandle,"UserApp",&hApplication);
	if((SAR_APPLICATION_NOT_EXISTS & 0xff) == ret_v){
		SKF_DisConnectDev(UkeyHandle);
		UkeyHandle = NULL;
		return ERR_UKEY_VOID;
	}
	if( 0 != ret_v )
	{
			print(PRINT_811USB,"UKey OP app ERR %x \r\n",ret_v);
			SKF_DisConnectDev(UkeyHandle);
			UkeyHandle = NULL;
			return ERR_UKEY_APP;
	}
	ret_v = SKF_SetSymmKey(UkeyHandle, key, SGD_SMS4_ECB, &hKey);
	if(ret_v != SAR_OK){
			SKF_CloseApplication(hApplication);
			SKF_DisConnectDev(UkeyHandle);
			UkeyHandle = NULL;
			return ERR_UKEY_APP;
	}
	print(PRINT_811USB,"SetSymmKey ok\r\n");
	EncryptParam.PaddingType = 0;
	ret_v = SKF_EncryptInit(hKey, EncryptParam);
	if(ret_v != SAR_OK){
			SKF_CloseHandle(hKey);
		  SKF_CloseApplication(hApplication);
			SKF_DisConnectDev(UkeyHandle);
			UkeyHandle = NULL;
	    return ERR_UKEY_APP;
	}
	print(PRINT_811USB,"Enc Init is ok\r\n");

	ret_v = SKF_Encrypt(hKey, in_data, 16, out_data, &ulOutLen);
	SKF_CloseHandle(hKey);
	SKF_CloseApplication(hApplication);
	SKF_DisConnectDev(UkeyHandle);
	UkeyHandle = NULL;
	return ret_v;						
}

int DeleteApplication(void){
	uint8_t ret_v =0;
	void * UkeyHandle = 0;
//	void * hApplication =0 ;
	ret_v = Ukey_Connect(&UkeyHandle);
	if( 0 != ret_v )
	{
		print(PRINT_811USB,"UKey CON ERR\r\n");		
		return ERR_UKEY_CONNECT;
	}
	ret_v = Ukey_DevAuth(UkeyHandle);
	if(0 != ret_v){
		 print(PRINT_811USB,"UK_DevAuth ERR 0x%x\r\n",ret_v);
		 SKF_DisConnectDev(UkeyHandle);
		 UkeyHandle = NULL;
		 return ERR_UKEY_DEVAUTH;
	}
	ret_v = SKF_DeleteApplication(UkeyHandle,"UserApp");
	if( 0 != ret_v )
	{
		SKF_DisConnectDev(UkeyHandle);
		UkeyHandle = NULL;
		print(PRINT_811USB,"SKF App DL ERR\r\n");
		if((SAR_APPLICATION_NOT_EXISTS & 0xff) == ret_v) return ERR_UKEY_VOID;
		else return ERR_UKEY_APP;
	}
	SKF_DisConnectDev(UkeyHandle);
	UkeyHandle = NULL;
	return 0;
}
