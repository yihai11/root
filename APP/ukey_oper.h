#ifndef	__UKEY_OPER_H__
#define	__UKEY_OPER_H__

#include "shamir.h"
#include "fpga_sm4.h"
#include "devmanage.h"
#include "ukey_oper.h"
#include "SKFInterface.h"
#include "sl811_usb.h"
#include "FreeRTOS.h"
#include "Semphr.h"
#include "fpga_sm2.h"
#include <string.h>
#include "SKFError.h"


#pragma pack(1)
typedef struct {
	unsigned char index;            //操作员序号
	unsigned char AdmTotalNum;      //操作员总数目
	unsigned char AdmAccessNum;     //操作员登录成功需要数目
	unsigned char MAINKEY_PART[SM4_ENCDATA_LEN(MAINKEY_LEN)];
	unsigned char AUTHKEY[SM4_ENCDATA_LEN(MAINKEY_LEN)];
	unsigned char MGTPUBKEY[sizeof(SM2PublicKey)];
	unsigned char BACKKEYPART[SHAMIR_PART_LEN(MAINKEY_LEN)];
} UKeyData;
#pragma pack()



unsigned int Ukey_Connect(void **ukey_handle);
unsigned int Ukey_DevAuth(void * UkeyHandle);

int Ukey_Creat_User(int UserType, char *PIN,void * UkeyHandle,void ** hApplication);
void  Ukey_ReadFinish(void);

int writeAdminData(int index, char *PIN, int PINlen, unsigned char *R2, unsigned char *authkey, \
							SM2PublicKey *pk,unsigned char *backkeypart, unsigned int TotalNum, unsigned int AccessNum);
int CreateAdminUkey(int index, char *PIN, int PINlen, unsigned char *R2, unsigned char *authkey, \
							SM2PublicKey *pk,unsigned char *backkeypart, unsigned int TotalNum, unsigned int AccessNum);
int CreateOperUkey(int index, char *PIN, int PINlen, unsigned char *R2, unsigned char *authkey);



int readUserData(unsigned char *index, char *PIN, int PINlen, unsigned char *R2, unsigned char *authkey, \
							unsigned char *backkeypart,unsigned int *TotalNum, unsigned int *AccessNum);

int ResetUserPin(int index, char *PIN, int PINlen,FlashData *ukey_eFlash);
int ChangeUserPin(uint8_t usrtype,uint16_t old_len,char *pwd_old,uint16_t new_len,char *pwd_new,FlashData *ukey_eFlash);
int Ukey_Enc_WithKey(UINT8 *in_data,UINT32 in_len,UINT8 *key,UINT32 key_len,UINT8 *out_data);

int DeleteApplication(void);
#endif
