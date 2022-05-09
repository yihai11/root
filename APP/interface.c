#include "interface.h"
#include "FreeRTOS.h"
#include "devmanage.h"
#include "type_code.h"
#include "spiflash_addr.h"
#include "user_manage.h"
#include "usrconfig.h"
#include "fatfs_file.h"
#include "internal_alg.h"
#include "cipher.h"
#include "at24cxx.h"
#include "gpio.h"

#define ERROR		1
#define	MAX_REC_PKG			1
#define	CIPH_STAT				1
#define	KEK_STAT				2
#define INFO_FLAG			0xa5
#define PRINT_INTERFACE 2
//uint8_t TransBuff[4096*MAX_REC_PKG]		__attribute__ ((at(60000800)));
//FlashData	FlsDevData;
//	FPGAHeader header  __attribute__((at(0x60001000)));
extern FlashData eFlash;
extern MCUSelfCheck DevSelfCheck;
extern struct USRLOG_STR usr_status;
extern unsigned char back_key[MAINKEY_LEN];
extern unsigned char mainkey_mcu[MAINKEY_LEN];
SM2KeyPair mgtkeypair;  // 设备管理密钥
char pin0_temp[17];		//临时设备密钥pin	最后一个字节表示pin长度
extern USRLOG usr;
extern unsigned char null_array[MAINKEY_LEN];
extern uint8_t ArgFlag;

extern uint8_t  recover_iv[MAINKEY_LEN];
extern uint16_t recover_key_index;
extern uint16_t recover_pag_count;
extern uint8_t  recover_backkey[MAINKEY_LEN];
extern uint8_t  recover_login_num;
extern uint8_t  recover_mainkey[MAINKEY_LEN];

TaskFunc	InterFuncList[] = {
NULL,
do_SD_TASK_GETDEVINFO,						  //0x1001
do_SD_TASK_GETKEYACCRINGHT,					//0x1002
do_SD_TASK_EXPSIGNPUB_RSA,					//0x1003
do_SD_TASK_EXPENCPUB_RSA,					  //0x1004
do_SD_TASK_GENKEYPAIREXPORT_RSA,
do_SD_TASK_GENKEYWIHTIPK_RSA,
do_SD_TASK_GENKEYWITHEPK_RSA,
do_SD_TASK_IMPORTKEYWITHISK_RSA,
do_SD_TASK_EXPSIGNPUB_ECC,
do_SD_TASK_EXPENCPUB_ECC,					//0x100A
do_SD_TASK_GENKEYPAIREXPORT_ECC,
do_SD_TASK_GENKEYWIHTIPK_ECC,
do_SD_TASK_GENKEYWITHEPK_ECC,
do_SD_TASK_IMPORTKEYWITHISK_ECC,
do_SD_TASK_GENAGREEDATAWITHECC,
do_SD_TASK_GENKEYWITHECC,					//0x1010
do_SD_TASK_GENAGREEANDKEYWITHECC,
do_SD_TASK_GENKEYWIHTKEK,
do_SD_TASK_IMPORTKEYWITHKEK,
do_SD_TASK_IMPORTSESSIONKEY,
do_SD_TASK_DESTORYKEY,
do_SD_TASK_EXTPUBKEYOPER_RSA,
do_SD_TASK_EXTPRIKEYOPER_RSA,
do_SD_TASK_INTPUBKEYOPER_RSA,
do_SD_TASK_INTPRIKEYOPER_RSA,
do_SD_TASK_INTSYMENC_AES,
do_SD_TASK_EXTSYMENC_AES,
do_SD_TASK_INTSYMENC_DES,
do_SD_TASK_EXTSYMENC_DES,
do_SD_TASK_INTSYMDEC_AES,
do_SD_TASK_EXTSYMDEC_AES,
do_SD_TASK_INTSYMDEC_DES,
do_SD_TASK_EXTSYMDEC_DES,
do_SD_TASK_CREATEFILE,
do_SD_TASK_READFILE,
do_SD_TASK_WRITEFILE,
do_SD_TASK_DELETEFILE,
do_SD_TASK_CLEARFILE,
do_SD_TASK_ENUMFILE,
do_SD_TASK_ADDUSER,
do_SD_TASK_USERLOGIN,
do_SD_TASK_USERLOGOUT,
NULL,//do_SD_TASK_RESETPWD,  			 0x102B
do_SD_TASK_DELUSER,
do_SD_TASK_RESETOPERATORPWD,
do_SD_TASK_GETLOGINSTATUS,
do_SD_TASK_CHGOCURPWD,
do_SD_TASK_CONFIGFILE,						//0x1030
do_SD_TASK_BACKUPADMININFO,
do_SD_TASK_RECOVERYADMININFO,
do_SD_TASK_BACKUPOPERATOR,
do_SD_TASK_BACKUPKEY,
do_SD_TASK_BACKUPADMINLOGIN,
do_SD_TASK_BACKUPADMINQUIT,
do_SD_TASK_GETDEVICESTATE,
do_SD_TASK_RECOVEROPERATOR,
do_SD_TASK_CHECKSELF,
do_SD_TASK_CYCLECHECKSELF,
do_SD_TASK_GENDEVKEY,
do_SD_TASK_EXPORTDEVPUBKEY,
do_SD_TASK_GENKEYUSERKEYPAIR,
do_SD_TASK_CHGKEYKEYPAIRPWD,
do_SD_TASK_GENKEK,
do_SD_TASK_DELKEK,							//0x1040
do_SD_TASK_RECOVERKEY,
do_SD_TASK_IMPORTKEYPAIR,
do_SD_TASK_DESKEYPAIR,
do_SD_TASK_GETKEYPAIRNUM,
do_SD_TASK_GETKEYPAIRSTAT,
do_SD_TASK_EXPORTKEYPAIR,
do_SD_TASK_GETUSERKEYCHK,
do_SD_TASK_GETKEKCHK,
do_SD_TASK_IMPORTENCKEY,
do_SD_TASK_IMPORTKEK,
do_SD_TASK_DEVKEKENC,
do_SD_TASK_DEVKEKDEC,
do_SD_TASK_DEVKEKSIGN,
do_SD_TASK_DEVKEKVERIFY,
do_SD_TASK_DESTORYDEV,
do_SD_TASK_CLEARUKEY,						//0x1050
do_SD_MANU_UPDATEDEV,
do_SD_MANU_CLEARMCU,            //擦除MCU,return to boot
do_SD_MANU_SETDEVINFO,
do_SD_MANU_CLEARUKEY,
do_SD_TASK_HASHSHA1,
do_SD_TASK_HASHSHA256,
do_SD_TASK_EXCHDIGENVELOP_RSA,
do_SD_TASK_EXCHDIGENVELOP_ECC,
do_SD_TASK_EXTPUBKEYENC_ECC,
do_SD_TASK_EXTPRIKEYDEC_ECC,
do_SD_TASK_INTPUBKEYENC_ECC,
do_SD_TASK_INTPRIKEYDEC_ECC,
do_SD_TASK_GOTOFACTORY,
do_SD_TASK_INTPRIKEYSIGN_ECC,			//内部私钥ECC签名运算
do_SD_TASK_INTPUBKEYVERI_ECC,			//内部公钥ECC验签运算
do_SD_TASK_EXTPRIKEYSIGN_ECC,			//外部私钥ECC签名运算
do_SD_TASK_EXTPUBKEYVERI_ECC,			//外部公钥ECC验签运算
do_SD_TASK_SHA384,								//SHA384
do_SD_TASK_SHA512,								//SHA512
do_SD_TASK_INTSYMENC_SM1,					//SM1内部秘钥加密
do_SD_TASK_INTSYMDEC_SM1,					//SM1内部秘钥解密
do_SD_TASK_EXTSYMENC_SM1,					//SM1外部秘钥加密
do_SD_TASK_EXTSYMDEC_SM1,					//SM1外部秘钥解密
do_SD_TASK_GETMUCVERSION,					//获取MCU版本
do_SD_TASK_GOTOFACTORY_NOADMIN		//恢复出厂态无管理员
};

unsigned long lc = 0;
unsigned long lc1 = 0;

void Inter_MCU_CMD(unsigned char *myInData)
{
	FPGAHeader *header = NULL;
	unsigned char *pchar;
	// mcu header 数据
	MCUHeader *mcuheader = NULL;
	lc++;
	// fpga头
	header = (FPGAHeader *)myInData;
	if (FPGA_DATA_ARM != header->dst) { // 非arm数据不进行处理
		return;
	}
	if ((FPGA_DATAHEAD_LEN + FPGA_MCUHEAD_LEN) > header->pkglen) { // 长度异常不处理
		return;
	}
	
	// 数据接收完成
	// 解析mcu头
	//pchar = get_mcu_header((unsigned char *)FPGA_DATA_READ_ADDR+ FPGA_DATAHEAD_LEN, &mcuheader);
	mcuheader = (MCUHeader *)(myInData+FPGA_DATAHEAD_LEN);
	header->dst = header->src;
	header->src = FPGA_DATA_ARM;
	
	//fpga_read_finish();
	
#if 0 //与驱动回环测试

				int len = header.pkglen - FPGA_DATAHEAD_LEN - FPGA_MCUHEAD_LEN;
				mcuheader.length = FPGA_MCUHEAD_LEN + len;
				memcpy((unsigned char *)(FPGA_DATA_WRITE_ADDR+FPGA_DATAHEAD_LEN+FPGA_MCUHEAD_LEN),pchar,len);
				header.pkglen = FPGA_DATAHEAD_LEN + FPGA_DATA_LEN(mcuheader.length);
				header.retpkglen = 0;		
				if(fpga_write_start()==REG_REST) return;
				pchar = set_fpga_header((unsigned char *)FPGA_DATA_WRITE_ADDR, &header);
				pchar = set_mcu_header(pchar, &mcuheader);
				fpga_write_finish(header.pkglen);
				lc1++;
				return;
#endif	
	
	


	
	if((mcuheader->cmd > MCUCMD_START) && (mcuheader->cmd < MCUCMD_END)){		//合法命令
		switch(mcuheader->cmd ){
			case SD_TASK_READFILE:
		//	case SD_TASK_WRITEFILE:
				//多包通讯
				InterFuncList[SD_TASK_NUM(mcuheader->cmd)](header,mcuheader, myInData+FPGA_DATAHEAD_LEN+FPGA_MCUHEAD_LEN, \
									(unsigned char *)(FPGA_DATA_WRITE_ADDR+FPGA_DATAHEAD_LEN+FPGA_MCUHEAD_LEN));
				break;
			default:
				//单包通讯
				InterFuncList[SD_TASK_NUM(mcuheader->cmd)](header,mcuheader, myInData+FPGA_DATAHEAD_LEN+FPGA_MCUHEAD_LEN, \
									(unsigned char *)(FPGA_DATA_WRITE_ADDR+FPGA_DATAHEAD_LEN+FPGA_MCUHEAD_LEN));

				header->pkglen = FPGA_DATAHEAD_LEN + FPGA_DATA_LEN(mcuheader->length);
				header->retpkglen = 0;		
			
				
				if(fpga_write_start()==REG_REST) break;
				pchar = set_fpga_header((unsigned char *)FPGA_DATA_WRITE_ADDR, header);
				pchar = set_mcu_header(pchar, mcuheader);
				fpga_write_finish(header->pkglen);
			break;
		}
	}
	else{
		mcuheader->length = FPGA_MCUHEAD_LEN;
		mcuheader->total = 1;
		mcuheader->count = 1;
		mcuheader->result = 1;		//error
		fpga_read_finish();
		if(fpga_write_start()==REG_REST) return;
		header->pkglen = FPGA_DATAHEAD_LEN + FPGA_DATA_LEN(mcuheader->length);
		header->retpkglen = 0;//FPGA_DATAHEAD_LEN + FPGA_DATA_LEN(FPGA_MCUHEAD_LEN);
		pchar = set_fpga_header((unsigned char *)FPGA_DATA_WRITE_ADDR, header);
		pchar = set_mcu_header(pchar, mcuheader);
		fpga_write_finish(header->pkglen);
	}
}

void fpga_get_test(uint16_t key_index){
		SM2PublicKey pkB={0};
		SM2PrivateKey skB={0};
		fpga_sm2_getkey(key_index*2, &skB, &pkB);
		print(PRINT_INTERFACE,"enc sk: \r\n");
		printf_buff_byte((uint8_t*)&skB,sizeof(skB));
		print(PRINT_INTERFACE,"enc pk: \r\n");
		printf_buff_byte((uint8_t*)&pkB,sizeof(pkB));
	}

/*************************SD_TASK_GETMUCVERSION************************
*获取MCU版本
********************************************************************/
TASK_FUNC(do_SD_TASK_GETMUCVERSION)
{
	char McuVersion[64] = {0};
	if(DevStatusNo(WorkStatus)){ //状态检测
		mcuheader->result = ERR_DVES_WORKSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	get_version(McuVersion,ARM_FIRMWARE_VERSION);
	//strcpy(McuVersion,MCU_V_NAME);
	memcpy(outdata,McuVersion,64);
	mcuheader->arg1 = strlen(McuVersion);
	mcuheader->total = 1;
	mcuheader->count = 1;
	mcuheader->result = 0;
	mcuheader->length = FPGA_MCUHEAD_LEN + 64;
}			

/*************************SD_TASK_GETDEVINFO************************
*获取设备信息
********************************************************************/
TASK_FUNC(do_SD_TASK_GETDEVINFO)
{
	DEVICEINFO *pdevinfo = pvPortMalloc(FPGA_DATA_LEN(sizeof(DEVICEINFO)));
	memset(pdevinfo, 0, FPGA_DATA_LEN(sizeof(DEVICEINFO)));
	uint8_t info[4] = {0};
	
	if(DevStatusNo(WorkStatus)){ //状态检测
		mcuheader->result = ERR_DVES_WORKSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	strcpy((char *)(pdevinfo->IssuerName),SHUDUN_NAME);
	at24cxx_read_bytes(DEVICE_INFO_ADDR, info, 4);
	if(INFO_FLAG != info[0]){
		//print(PRINT_INTERFACE,"start to 0 info!\r\n");
		memset((uint8_t*)pdevinfo->DeviceName, 0, 32);  //初始化为0
		//at24cxx_write_bytes(DEVICE_DATA_ADDR, (uint8_t*)pdevinfo->DeviceName, 32);
	}
	else{
		at24cxx_read_bytes(DEVICE_DATA_ADDR, (uint8_t*)pdevinfo->DeviceName, 32);
	}
	print(PRINT_INTERFACE,"dev inf %s\r\n",pdevinfo->DeviceName);
	print(PRINT_INTERFACE,"dev inf %s\r\n",pdevinfo->DeviceSerial);
//	if((ArgFlag&0x01) == 0){//加密卡	
//		memcpy(pdevinfo->DeviceSerial,(char*)"2020100100104001",16);
//		strcpy((char *)(pdevinfo->DeviceName),"PEM611");
//	}else{//签名卡
//		memcpy(pdevinfo->DeviceSerial,(char*)"2020100100103001",16);
//		strcpy((char *)(pdevinfo->DeviceName),"PEM601");
//	}
	pdevinfo->DeviceVersion = ARM_FIRMWARE_VERSION;
	pdevinfo->StandardVersion = STANDARD_VERSION;

	pdevinfo->AsymAlgAbility[0] = SGD_SM2 | SGD_RSA;
	pdevinfo->AsymAlgAbility[1] = SM2_BITS | 2048;
	pdevinfo->SymAlgAbility = SGD_SM4_ECB | SGD_SM4_CBC|SGD_SM1_ECB | SGD_SM1_CBC |\
														SGD_AES128_ECB|SGD_AES128_CBC|SGD_AES192_ECB|SGD_AES192_CBC|\
														SGD_AES256_ECB|SGD_AES256_CBC;
	pdevinfo->HashAlgAbility = SGD_SM3;//|SGD_SHA1|SGD_SHA256;
	pdevinfo->BufferSize = 8*1024*1024;

	memcpy(outdata, pdevinfo, FPGA_DATA_LEN(sizeof(DEVICEINFO)));
	vPortFree(pdevinfo);

	mcuheader->total = 1;
	mcuheader->count = 1;
	mcuheader->result = 0;
	mcuheader->length = FPGA_MCUHEAD_LEN + sizeof(DEVICEINFO);
}					

/*************************SD_TASK_GETKEYACCRINGHT************************
*获取密钥权限  (工作态)
********************************************************************/
TASK_FUNC(do_SD_TASK_GETKEYACCRINGHT)
{
	char cipher_pin_name[20]= "1:cipherpin/pin";//15+3+1
	char index_str[4]={0};
	uint16_t ciph_index = mcuheader->arg1;
	uint8_t ciph_len = mcuheader->arg2;
	if(DevStatusNo(WorkStatus)){ //状态检测
		mcuheader->result = ERR_DVES_WORKSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	if(mcuheader->arg2 < 17)		//密码长度不可以超过16字节
	{
		mcuheader->result = check_cipher_access(mcuheader->arg1, mcuheader->arg2, (char *)indata);
	}
	else
	{
		mcuheader->result = ERR_MANG_PINLEN;
	}
		
	mcuheader->arg1 = ciph_index;
	mcuheader->arg2 = 0;
	mcuheader->length=FPGA_MCUHEAD_LEN;
}
//释放密钥权限  	//无需muc处理。
TASK_FUNC(do_SD_TASK_DELEKEYACCRINGHT){}
/*************************SD_TASK_EXPSIGNPUB_RSA************************
*导出RSA签名公钥
********************************************************************/
TASK_FUNC(do_SD_TASK_EXPSIGNPUB_RSA)
{
	if(DevStatusNo(WorkStatus)){ //状态检测
		mcuheader->result = ERR_DVES_WORKSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	mcuheader->result = export_ras_pubkey(mcuheader->arg1, ASYM_KEYPAIR_CRYPT, outdata, &mcuheader->arg2);
	if (mcuheader->result)
	{
		mcuheader->length = FPGA_MCUHEAD_LEN;
	}
	else
	{
		mcuheader->length = FPGA_MCUHEAD_LEN + BIT_TO_BYTE(mcuheader->arg2) * 2;
	}
}
/*************************SD_TASK_EXPENCPUB_RSA************************
*导出RSA加密公钥
********************************************************************/
TASK_FUNC(do_SD_TASK_EXPENCPUB_RSA)
{
	if(DevStatusNo(WorkStatus)){ //状态检测
		mcuheader->result = ERR_DVES_WORKSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	mcuheader->result = export_ras_pubkey(mcuheader->arg1, ASYM_KEYPAIR_CRYPT, outdata, &mcuheader->arg2);
	if (mcuheader->result)
	{
		mcuheader->length = FPGA_MCUHEAD_LEN;
	}
	else
	{
		mcuheader->length = FPGA_MCUHEAD_LEN + BIT_TO_BYTE(mcuheader->arg2) * 2;
	}
}
/*************************SD_TASK_GENKEYPAIREXPORT_RSA************************
*产生输出RSA密钥对
********************************************************************/
TASK_FUNC(do_SD_TASK_GENKEYPAIREXPORT_RSA)
{
	uint8_t rsa_keypair[RSA2048_BUFFLEN];
	if(DevStatusNo(WorkStatus)){ //状态检测
		mcuheader->result = ERR_DVES_WORKSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	mcuheader->result = GenRSA(rsa_keypair, mcuheader->arg1);
	if (mcuheader->result)
	{
		mcuheader->length = FPGA_MCUHEAD_LEN;
	}
	else
	{
		memcpy(outdata, rsa_keypair, RSA_PRIKEY_LEN(mcuheader->arg1));
		mcuheader->length = FPGA_MCUHEAD_LEN + RSA_PRIKEY_LEN(mcuheader->arg1);
	}
}
/*************************SD_TASK_GENKEYWIHTIPK_RSA************************
*生成会话密钥并用内部RSA公钥加密输出
********************************************************************/
TASK_FUNC(do_SD_TASK_GENKEYWIHTIPK_RSA)
{
	uint16_t key_len;
	uint16_t rsa_index;
	uint32_t SKeyindex = 0;
	uint32_t out_len = 0;
	uint8_t random_key[32] = {0};
	uint8_t key_cipher[RSA2048_BUFFLEN];
	uint16_t rtval;

	if(DevStatusNo(WorkStatus)){ //状态检测
		mcuheader->result = ERR_DVES_WORKSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	key_len = BIT_TO_BYTE(mcuheader->arg1);
	rsa_index = mcuheader->arg2;
	
	mcuheader->result = 0;
	do
	{
		if (key_len > 32 || rsa_index <= SM2_KEYPAIR_NUM || rsa_index > SM2_KEYPAIR_NUM+RSA_KEYPAIR_NUM)
		{
			mcuheader->result = ERR_CIPN_INDEXLEN;
			break;
		}
		
		rtval = get_random_MCU(random_key, key_len);
		if (rtval)
		{
			mcuheader->result = ERR_CIPN_GENRANDOM;
			break;
		}
		rtval = MUC_RSA_Pubkey_Enc_internal_pading(rsa_index, random_key, key_len, key_cipher, &out_len);
		if (rtval)
		{
			mcuheader->result = ERR_CIPN_RSAPUBKEYOP;
			break;
		}
		rtval = writer_sessionkey_mcufpga(key_len, random_key, &SKeyindex);
		if (rtval)
		{
			mcuheader->result = rtval;
			break;
		}			
	} while (0);
	
	if (mcuheader->result)
	{
		mcuheader->length = FPGA_MCUHEAD_LEN;
	}
	else
	{
		memcpy(outdata, key_cipher, out_len);
		mcuheader->arg1 = SKeyindex;
		mcuheader->arg2 = BYTE_TO_BIT(key_len);
		mcuheader->length = FPGA_MCUHEAD_LEN + out_len;
	}
}
/*************************SD_TASK_GENKEYWITHEPK_RSA************************
*生成会话密钥并用外部RSA公钥加密输出
********************************************************************/
TASK_FUNC(do_SD_TASK_GENKEYWITHEPK_RSA)
{
	uint16_t key_len;
	uint16_t rsa_len;
	uint32_t SKeyindex = 0;
	uint32_t out_len = 0;
	uint8_t random_key[32] = {0};
	uint8_t key_rsa[RSA2048_BUFFLEN];
	uint8_t key_cipher[RSA2048_BUFFLEN];
	uint16_t rtval;

	if(DevStatusNo(WorkStatus)){ //状态检测
		mcuheader->result = ERR_DVES_WORKSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	key_len = BIT_TO_BYTE(mcuheader->arg1);
	rsa_len = BIT_TO_BYTE(mcuheader->arg2);
	
	mcuheader->result = 0;
	do
	{
		if (key_len > 32)
		{
			mcuheader->result = ERR_CIPN_INDEXLEN;
			break;
		}
		
		rtval = get_random_MCU(random_key, key_len);
		if (rtval)
		{
			mcuheader->result = ERR_CIPN_GENRANDOM;
			break;
		}
		memcpy(key_rsa,indata,rsa_len*2);
		out_len = rsa_len;
		rtval = MUC_RSA_Pubkey_Enc_external_pading(key_rsa, random_key, key_len, key_cipher, &out_len);
		if (rtval)
		{
			mcuheader->result = rtval;
			break;
		}
		rtval = writer_sessionkey_mcufpga(key_len, random_key, &SKeyindex);
		if (rtval)
		{
			mcuheader->result = rtval;
			break;
		}			
	} while (0);
	
	if (mcuheader->result)
	{
		mcuheader->length = FPGA_MCUHEAD_LEN;
	}
	else
	{
		memcpy(outdata, key_cipher, out_len);
		mcuheader->arg1 = SKeyindex;
		mcuheader->arg2 = BYTE_TO_BIT(key_len);
		mcuheader->length = FPGA_MCUHEAD_LEN + out_len;
	}
	
	
}
/*************************SD_TASK_IMPORTKEYWITHISK_RSA************************
*导入会话秘钥并用内部RSA私钥解密
********************************************************************/
TASK_FUNC(do_SD_TASK_IMPORTKEYWITHISK_RSA)
{
	uint16_t enckey_len;
	uint16_t rsa_index;
	uint32_t SKeyindex = 0;
	uint32_t out_len = 0;
	uint8_t session_enckey[RSA2048_BUFFLEN] = {0};
	uint8_t session_key[64];
	uint16_t rtval;
	if(DevStatusNo(WorkStatus)){ //状态检测
		mcuheader->result = ERR_DVES_WORKSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	rsa_index =mcuheader->arg1;
	enckey_len = mcuheader->arg2;
	
	mcuheader->result = 0;
	do
	{
		if (enckey_len > RSA2048_BUFFLEN || rsa_index <= SM2_KEYPAIR_NUM || rsa_index > SM2_KEYPAIR_NUM+RSA_KEYPAIR_NUM)
		{
			mcuheader->result = ERR_CIPN_INDEXLEN;
			break;
		}
		memcpy(session_enckey, indata, enckey_len);

		rtval = MUC_RSA_Prikey_Dec_internal_pading(rsa_index, session_enckey, enckey_len, session_key, &out_len);
		if (rtval)
		{
			mcuheader->result = ERR_CIPN_RSAPUBKEYOP;
			break;
		}
		rtval = writer_sessionkey_mcufpga(out_len, session_key, &SKeyindex);
		if (rtval)
		{
			mcuheader->result = rtval;
			break;
		}			
	} while (0);
	
	if (mcuheader->result)
	{
		mcuheader->length = FPGA_MCUHEAD_LEN;
	}
	else
	{
		mcuheader->arg1 = SKeyindex;
		mcuheader->arg2 = BYTE_TO_BIT(out_len);
		mcuheader->length = FPGA_MCUHEAD_LEN + out_len;
	}
}
/*************************SD_TASK_EXPSIGNPUB_ECC************************
*导出ECC签名公钥
********************************************************************/
TASK_FUNC(do_SD_TASK_EXPSIGNPUB_ECC)
{
	if(DevStatusNo(WorkStatus)){ //状态检测
		mcuheader->result = ERR_DVES_WORKSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}	
	mcuheader->result = export_sm2_pubkey(mcuheader->arg1, ASYM_KEYPAIR_SIGN, (SM2PublicKey *)outdata);
	if (mcuheader->result)
	{
		mcuheader->length = FPGA_MCUHEAD_LEN;
	}
	else
	{
		mcuheader->length = FPGA_MCUHEAD_LEN + sizeof(SM2PublicKey);
	}
}

/*************************SD_TASK_EXPENCPUB_ECC***********************
*导出ECC加密公钥
********************************************************************/
TASK_FUNC(do_SD_TASK_EXPENCPUB_ECC)
{
	if(DevStatusNo(WorkStatus)){ //状态检测
		mcuheader->result = ERR_DVES_WORKSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	mcuheader->result = export_sm2_pubkey(mcuheader->arg1, ASYM_KEYPAIR_CRYPT, (SM2PublicKey *)outdata);
	if (mcuheader->result)
	{
		mcuheader->length = FPGA_MCUHEAD_LEN;
	}
	else
	{
		mcuheader->length = FPGA_MCUHEAD_LEN + sizeof(SM2PublicKey);
	}
}
//产生ECC非对称秘钥对并输出  	//不经过MCU，FPGA直接返回给驱动
/*************************SD_TASK_GENKEYPAIREXPORT_ECC**************
*产生ECC非对称秘钥对并输出
********************************************************************/
TASK_FUNC(do_SD_TASK_GENKEYPAIREXPORT_ECC)
{
	uint8_t res = 0 ; 
	ECC_G_STR sm2_para;
	SM2KeyPair genkeypair;
	if(DevStatusNo(WorkStatus)){   //状态检测
		mcuheader->result = ERR_DVES_FACTYSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	SM2_param_init(&sm2_para);
	res = SM2_Gen_Keypair(&sm2_para,(uint8_t*)(&genkeypair.sk),(uint8_t*)(&genkeypair.pk.x),(uint8_t*)(&genkeypair.pk.y));
	if(res){	//生成密钥错误
		mcuheader->length = FPGA_MCUHEAD_LEN;
		mcuheader->result = ERR_CIPN_GENSM2KEY; 
	}
		
	memcpy(outdata,&genkeypair,sizeof(SM2KeyPair));
  mcuheader->arg1  = sizeof(SM2KeyPair);		
  mcuheader->length = FPGA_MCUHEAD_LEN + sizeof(SM2KeyPair);
	
}
/*************************SD_TASK_GENKEYWIHTIPK_ECC**************
*生成会话密钥并用内部ECC公钥加密输出
********************************************************************/
TASK_FUNC(do_SD_TASK_GENKEYWIHTIPK_ECC)
{
	uint16_t key_len;
	uint16_t sm2_index;
	uint32_t SKeyindex = 0;
	uint32_t out_len = 0;
	uint8_t random_key[32] = {0};
	uint8_t key_cipher[128];
	uint16_t rtval;
	if(DevStatusNo(WorkStatus)){ //状态检测
		mcuheader->result = ERR_DVES_WORKSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	key_len = BIT_TO_BYTE(mcuheader->arg1);
	sm2_index = mcuheader->arg2;
	
	mcuheader->result = 0;
	do
	{
		if (key_len > 32 || sm2_index == 0 || sm2_index > SM2_KEYPAIR_NUM)
		{
			mcuheader->result = ERR_CIPN_INDEXLEN;
			break;
		}
		
		rtval = get_random_MCU(random_key, key_len);
		if (rtval)
		{
			mcuheader->result = ERR_CIPN_GENRANDOM;
			break;
		}
		rtval = fpga_sm2_encrypt_internal(sm2_index, random_key, key_len, key_cipher, &out_len);
		if (rtval)
		{
			mcuheader->result = rtval;
			break;
		}
		rtval = writer_sessionkey_mcufpga(key_len, random_key, &SKeyindex);
		if (rtval)
		{
			mcuheader->result = rtval;
			break;
		}			
	}while (0);
	
	if (mcuheader->result)
	{
		mcuheader->length = FPGA_MCUHEAD_LEN;
	}
	else
	{
		memcpy(outdata, key_cipher, out_len);
		mcuheader->arg1 = SKeyindex;
		mcuheader->arg2 = BYTE_TO_BIT(key_len);
		mcuheader->length = FPGA_MCUHEAD_LEN + out_len;
	}
}

/*************************SD_TASK_GENKEYWITHEPK_ECC**************
*生成会话密钥并用外部ECC公钥加密输出
********************************************************************/
TASK_FUNC(do_SD_TASK_GENKEYWITHEPK_ECC)
{
	uint16_t rtval = 0;
	uint16_t key_len;
	uint32_t SKeyindex = 0;
	uint32_t out_len = 0;
	uint8_t random_key[32]={0}; 
	uint8_t key_cipher[128];
	SM2PublicKey sm2_pubkey;
	if(DevStatusNo(WorkStatus)){ //状态检测
		mcuheader->result = ERR_DVES_WORKSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}	
	key_len = BIT_TO_BYTE(mcuheader->arg1);
	mcuheader->result = 0;
	
	do
	{
		if (key_len > 32)
		{
			mcuheader->result = ERR_CIPN_INDEXLEN;
			break;
		}
		rtval = get_random_MCU(random_key, key_len);
		if (rtval)
		{
			mcuheader->result = ERR_CIPN_GENRANDOM;
			break;
		}
		memcpy(&sm2_pubkey, indata, sizeof(SM2PublicKey));
		rtval = fpga_sm2_encrypt_external(&sm2_pubkey, random_key, key_len, key_cipher, &out_len);
		if (rtval)
		{
			mcuheader->result = rtval;
			break;
		}
		rtval = writer_sessionkey_mcufpga(key_len, random_key, &SKeyindex);
		if (rtval)
		{
			mcuheader->result = rtval;
			break;
		}	
	} while (0);
	
	if (mcuheader->result)
	{
		mcuheader->length = FPGA_MCUHEAD_LEN;
	}
	else
	{
		memcpy(outdata, key_cipher, out_len);
		mcuheader->arg1 = SKeyindex;
		mcuheader->arg2 = BYTE_TO_BIT(key_len);
		mcuheader->length = FPGA_MCUHEAD_LEN + out_len;
	}
}

/*************************SD_TASK_IMPORTKEYWITHISK_ECC**************
*导入会话秘钥并用内部ECC私钥解密
********************************************************************/
TASK_FUNC(do_SD_TASK_IMPORTKEYWITHISK_ECC)
{
	uint16_t sm2_index;
	uint16_t data_len;
	uint32_t out_len;
	uint32_t SKeyindex = 0;
	int32_t rtval;
	uint8_t key_buff[128];
	if(DevStatusNo(WorkStatus)){ //状态检测
		mcuheader->result = ERR_DVES_WORKSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}	
	data_len = mcuheader->arg1;
	sm2_index = mcuheader->arg2;
	mcuheader->result = 0;
	
	do
	{
		if (sm2_index == 0 || sm2_index > SM2_KEYPAIR_NUM)
		{
			mcuheader->result = ERR_CIPN_INDEXLEN;
			break;
		}
		rtval = fpga_sm2_decrypt_internal(sm2_index, indata, data_len, key_buff, &out_len);
		if (rtval)
		{
			mcuheader->result = rtval;
			break;
		}
		
		rtval = writer_sessionkey_mcufpga(out_len, key_buff, &SKeyindex);
		if (rtval)
		{
			mcuheader->result = rtval;
			break;
		}	
	} while (0);
	
	if (mcuheader->result)
	{
		mcuheader->length = FPGA_MCUHEAD_LEN;
	}
	else
	{
		mcuheader->arg1 = SKeyindex;
		mcuheader->arg2 = BYTE_TO_BIT(out_len);
		mcuheader->length = FPGA_MCUHEAD_LEN;
	}
}

/*************************SD_TASK_GENAGREEDATAWITHECC**************
*生成秘钥协商参数并输出
********************************************************************/
TASK_FUNC(do_SD_TASK_GENAGREEDATAWITHECC)
{
	//int32_t rtval;
	uint16_t sm2_index = mcuheader->arg1;
	uint16_t keybit = mcuheader->arg2;
	uint32_t idlen = 0;
	uint8_t id[1024];
	SM2PublicKey sponsor_pubkey; 
	SM2PublicKey sponsor_tmp_pubkey;
	void *agreement_handle = NULL;
	mcuheader->result = 0;
	uint32_t outlen = 0;
	//uint32_t SKeyindex = 0;
	if(DevStatusNo(WorkStatus)){ //状态检测
		mcuheader->result = ERR_DVES_WORKSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	memcpy((uint8_t*)&idlen,indata,4);
	if(idlen > 1024 || idlen == 0){
		mcuheader->result = ERR_COMM_INPUTLEN;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	memcpy(id,indata+4,idlen);
	mcuheader->result = fpga_sm2_agreement_generate_data(sm2_index,keybit,id,idlen,&sponsor_pubkey,&sponsor_tmp_pubkey,&agreement_handle);
	if(mcuheader->result){
			mcuheader->length=FPGA_MCUHEAD_LEN;
			return;
	}
	memcpy(outdata,(uint8_t*)&sponsor_pubkey,sizeof(SM2PublicKey));
	outlen += sizeof(SM2PublicKey);
	memcpy(outdata+outlen,(uint8_t*)&sponsor_tmp_pubkey,sizeof(SM2PublicKey));
	outlen += sizeof(SM2PublicKey);
	memcpy(outdata+outlen,&agreement_handle,4);
	outlen += 4;
	mcuheader->length=FPGA_MCUHEAD_LEN + outlen;
}

/*************************SD_TASK_GENKEYWITHECC**************
*计算会话秘钥
********************************************************************/
TASK_FUNC(do_SD_TASK_GENKEYWITHECC)
{
	uint16_t keybits = mcuheader->arg2;
	uint32_t ridlen = 0;
	uint8_t rid[1024];
	SM2PublicKey responsor_pubkey; 
	SM2PublicKey responsor_tmp_pubkey;
	uint32_t outlen = 0;
	uint32_t SKeyindex = 0;
	void *agreement_handle = NULL;
	if(DevStatusNo(WorkStatus)){ //状态检测
		mcuheader->result = ERR_DVES_WORKSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	mcuheader->result = 0;
//响应方ID长度 + 响应方ID	
	memcpy((uint8_t*)&ridlen,indata,4);
	if(ridlen > 1024 || ridlen == 0){
		mcuheader->result = ERR_COMM_INPUTLEN;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	outlen +=4;
	memcpy(rid,indata+outlen,ridlen);
	outlen +=ridlen;		
//响应方ECCrefPublicKey结构体 + 响应方临时公钥ECCrefPublicKey结构体
	memcpy((uint8_t*)&responsor_pubkey,    indata+outlen,sizeof(SM2PublicKey));
	outlen +=sizeof(SM2PublicKey);
	memcpy((uint8_t*)&responsor_tmp_pubkey,indata+outlen,sizeof(SM2PublicKey));
	outlen +=sizeof(SM2PublicKey);
	memcpy(&agreement_handle,indata+outlen,4);
	outlen +=4;
	
	mcuheader->result = fpga_sm2_agreement_generate_key(rid,ridlen,&responsor_pubkey,&responsor_tmp_pubkey,agreement_handle,&SKeyindex);
	if(mcuheader->result){
			mcuheader->length=FPGA_MCUHEAD_LEN;
			return;
	}
	mcuheader->arg1 = SKeyindex;
	mcuheader->arg2 = ((AgreementData *)agreement_handle)->key_bits;
	mcuheader->length=FPGA_MCUHEAD_LEN;
}

/*************************SD_TASK_GENAGREEANDKEYWITHECC**************
*产生协商参数并计算会话秘钥
********************************************************************/
TASK_FUNC(do_SD_TASK_GENAGREEANDKEYWITHECC)
{
	uint16_t sm2_index = mcuheader->arg1;
	uint16_t keybits = mcuheader->arg2;
	uint32_t sidlen = 0;
	uint8_t sid[1024];
	uint32_t ridlen = 0;
	uint8_t rid[1024];
	SM2PublicKey sponsor_pubkey; 
	SM2PublicKey sponsor_tmp_pubkey;
	SM2PublicKey responsor_pubkey; 
	SM2PublicKey responsor_tmp_pubkey;
	uint32_t outlen = 0;
	uint32_t SKeyindex = 0;
	if(DevStatusNo(WorkStatus)){ //状态检测
		mcuheader->result = ERR_DVES_WORKSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	mcuheader->result = 0;
//响应方ID长度 + 响应方ID	
	memcpy((uint8_t*)&ridlen,indata,4);
	if(ridlen > 1024 || ridlen == 0){
		mcuheader->result = ERR_COMM_INPUTLEN;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	outlen +=4;
	memcpy(rid,indata+outlen,ridlen);
	outlen +=ridlen;
//4B发起方ID长度 + 发起方ID
	memcpy((uint8_t*)&sidlen,indata+outlen,4);
	if(sidlen > 1024 || sidlen == 0){
		mcuheader->result = ERR_COMM_INPUTLEN;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	outlen +=4;
	memcpy(sid,indata+outlen,sidlen);
	outlen +=sidlen;		
//发起方ECCrefPublicKey结构体 + 发起方临时公钥ECCrefPublicKey结构体
	memcpy((uint8_t*)&sponsor_pubkey,    indata+outlen,sizeof(SM2PublicKey));
	outlen +=sizeof(SM2PublicKey);
	memcpy((uint8_t*)&sponsor_tmp_pubkey,indata+outlen,sizeof(SM2PublicKey));
	outlen +=sizeof(SM2PublicKey);
	
	
	mcuheader->result = fpga_sm2_agreement_generate_data_key(sm2_index,keybits, rid, ridlen,sid,sidlen, &sponsor_pubkey, 
																							&sponsor_tmp_pubkey,&responsor_pubkey, &responsor_tmp_pubkey, &SKeyindex);
	if(mcuheader->result){
			mcuheader->length=FPGA_MCUHEAD_LEN;
			return;
	}
	outlen = 0;
	mcuheader->arg1 = SKeyindex;
	mcuheader->arg2 = keybits;
	memcpy(outdata+outlen,(uint8_t*)&responsor_pubkey,    sizeof(SM2PublicKey));
	outlen +=sizeof(SM2PublicKey);
	memcpy(outdata+outlen,(uint8_t*)&responsor_tmp_pubkey,sizeof(SM2PublicKey));
	outlen +=sizeof(SM2PublicKey);
	mcuheader->length=FPGA_MCUHEAD_LEN + outlen;
	
}

/*************************SD_TASK_GENKEYWIHTKEK**********************
*生成会话秘钥并用秘钥加密秘钥加密输出
********************************************************************/
TASK_FUNC(do_SD_TASK_GENKEYWIHTKEK)
{
	uint16_t rtval = 0;
	uint32_t SKeyindex = 0;
	uint8_t random_key[32]={0}; 
	uint8_t key_cipher[64]={0};
	uint32_t out_len = 0;
	uint16_t SKeyLen = BIT_TO_BYTE(mcuheader->arg1);
	uint16_t ArgId = mcuheader->arg2;
	uint16_t KekIndex = mcuheader->result;
	mcuheader->result = 0;
	if(DevStatusNo(WorkStatus)){ //状态检测
		mcuheader->result = ERR_DVES_WORKSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}	
	do
	{
		if (SKeyLen > 32 || KekIndex ==0 || KekIndex > KEK_NUM)
		{
			mcuheader->result = ERR_CIPN_INDEXLEN;
			break;
		}
		rtval = get_random_MCU(random_key, SKeyLen);
		if (rtval)
		{
			mcuheader->result = ERR_CIPN_GENRANDOM;
			break;
		}
		//print(PRINT_INTERFACE,"RSA_Gen_Keypair error!!!\n");
		rtval = kek_encrypt(KekIndex, ArgId, random_key, SKeyLen, key_cipher, &out_len);
		if (rtval)
		{
			mcuheader->result = rtval;
			break;
		}
		rtval = writer_sessionkey_mcufpga(SKeyLen, random_key, &SKeyindex);
		if (rtval)
		{
			mcuheader->result = rtval;
			break;
		}
		
	}while (0);
	if (mcuheader->result){
		mcuheader->length = FPGA_MCUHEAD_LEN;
	}
	else{
		memcpy(outdata, key_cipher, out_len);
		mcuheader->arg1 = SKeyindex;
		mcuheader->arg2 = BYTE_TO_BIT(SKeyLen);
		mcuheader->length = FPGA_MCUHEAD_LEN + out_len;
	}
}

/*************************SD_TASK_IMPORTKEYWITHKEK**********************
*导入会话秘钥并用秘钥加密秘钥解密
********************************************************************/
TASK_FUNC(do_SD_TASK_IMPORTKEYWITHKEK)
{
	uint16_t rtval = 0;
	uint32_t SKeyindex = 0;
	uint8_t session_key[32]={0}; 
	uint8_t key_cipher[32]={0};
	uint32_t cipher_len = mcuheader->result;
	uint32_t SKeyLen = 0;
	uint16_t ArgId = mcuheader->arg1;
	uint16_t KekIndex = mcuheader->arg2;
	mcuheader->result = 0;
	if(DevStatusNo(WorkStatus)){ //状态检测
		mcuheader->result = ERR_DVES_WORKSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}	
	do
	{
		if (SKeyLen > 32 || KekIndex ==0 || KekIndex > KEK_NUM)
		{
			mcuheader->result = ERR_CIPN_INDEXLEN;
			break;
		}
		memcpy(key_cipher,indata,cipher_len);
		rtval = kek_decrypt(KekIndex, ArgId, key_cipher, cipher_len, session_key, &SKeyLen);
		if (rtval)
		{
			mcuheader->result = rtval;
			break;
		}
		rtval = writer_sessionkey_mcufpga(SKeyLen, session_key, &SKeyindex);
		if (rtval)
		{
			mcuheader->result = rtval;
			break;
		}
		
	}while (0);
	if (mcuheader->result){
		mcuheader->length = FPGA_MCUHEAD_LEN;
	}
	else{
		mcuheader->arg1 = SKeyindex;
		mcuheader->arg2 = BYTE_TO_BIT(SKeyLen);
		mcuheader->length = FPGA_MCUHEAD_LEN + SKeyLen;
	}
}

/*************************SD_TASK_IMPORTSESSIONKEY**********************
*明文导入\导出会话秘钥
********************************************************************/
TASK_FUNC(do_SD_TASK_IMPORTSESSIONKEY)
{
	if(DevStatusNo(WorkStatus)){ //状态检测
		mcuheader->result = ERR_DVES_WORKSTATE;
		mcuheader->length = FPGA_MCUHEAD_LEN;
		return;
	}
	uint8_t key[32] = {0};
	uint16_t out_len;
	uint32_t SKeyindex = 0;
	uint16_t key_index = mcuheader->result;
	if(1 == mcuheader->arg2){
		//写入会话密钥到MCU和FPGA
		mcuheader->result = writer_sessionkey_mcufpga(mcuheader->arg1, indata, &SKeyindex);
		if(mcuheader->result){
			mcuheader->arg1 = SKeyindex;
		}
		mcuheader->arg2 = BYTE_TO_BIT(mcuheader->arg1);
		mcuheader->arg1 = SKeyindex;
		mcuheader->length = FPGA_MCUHEAD_LEN;
	}
	else if(2 == mcuheader->arg2){
		//读取密钥
		mcuheader->result = read_sessionkey_mcu(&out_len,key,key_index);
		if(mcuheader->result){
			mcuheader->length = FPGA_MCUHEAD_LEN;
			return;
		}
		memcpy(outdata,key,out_len);
		mcuheader->arg2 = BYTE_TO_BIT(out_len);
		mcuheader->length = FPGA_MCUHEAD_LEN + out_len;
		
	}
	else{
		//错误参数
		mcuheader->result = ERR_COMM_INPUT;
		mcuheader->length = FPGA_MCUHEAD_LEN;
	}
}

/*************************do_SD_TASK_DESTORYKEY**********************
*销毁会话秘钥
********************************************************************/
TASK_FUNC(do_SD_TASK_DESTORYKEY)
{
	if(DevStatusNo(WorkStatus)){ //状态检测
		mcuheader->result = ERR_DVES_WORKSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	//销毁MCU和FPGA的会话密钥
	mcuheader->result = destory_sessionkey_mcufpga(mcuheader->arg1, indata);
	
	mcuheader->length = FPGA_MCUHEAD_LEN;
}
//////////////////////////////非对称算法运算/////////////////////////////
/*************************SD_TASK_EXTPUBKEYOPER_RSA**********************
*外部公钥RSA运算
********************************************************************/
TASK_FUNC(do_SD_TASK_EXTPUBKEYOPER_RSA)
{
	uint32_t out_len = 0;
	uint16_t in_len = mcuheader->arg1;
	uint8_t out_data[256]={0};
	uint8_t in_data[256]={0};
	//uint8_t RSA_key1[1024]={0};
	uint8_t *RSA_key = NULL;//[1408]={0};
	mcuheader->result = 0;
	if(DevStatusNo(WorkStatus)){ //状态检测
		mcuheader->result = ERR_DVES_WORKSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}	
	if(in_len*8 != mcuheader->arg2 || (mcuheader->arg2 != 1024 && mcuheader->arg2 != 2048)){
		mcuheader->result = ERR_CIPN_RSAINLEN;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	RSA_key = pvPortMalloc(1408);
	if (RSA_key == NULL)
	{
		mcuheader->result = ERR_COMM_MALLOC;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	memcpy(RSA_key,  indata, in_len*2);
	memcpy(in_data, indata+in_len*2, in_len);
	
//	print(PRINT_INTERFACE,"in_data0\r\n");
//	printfb(in_data,in_len);
	
	mcuheader->result = MUC_RSA_Pubkey_Operation_external(RSA_key, in_data, in_len, out_data, &out_len);

	memcpy(outdata, out_data, in_len);
	mcuheader->arg1 = (uint16_t)out_len;
	mcuheader->length = FPGA_MCUHEAD_LEN + mcuheader->arg1;
	if(mcuheader->arg1 == 0){
		mcuheader->result = ERR_CIPN_RSAPUBKEYOP;
	}
	if (RSA_key)
	{
		vPortFree(RSA_key);		
	}
}
/*************************SD_TASK_EXTPRIKEYOPER_RSA**********************
*外部私钥RSA运算
********************************************************************/	
TASK_FUNC(do_SD_TASK_EXTPRIKEYOPER_RSA)
{
	uint32_t out_len = 0;
	uint16_t in_len = mcuheader->arg1;
	uint8_t out_data[256]={0};
	uint8_t in_data[256]={0};
	//uint8_t RSA_key[1408]={0};
	uint8_t *RSA_key = NULL;
	mcuheader->result = 0;
	if(DevStatusNo(WorkStatus)){ //状态检测
		mcuheader->result = ERR_DVES_WORKSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}	
	if(in_len*8 != mcuheader->arg2 || (mcuheader->arg2 != 1024 && mcuheader->arg2 != 2048)){
		mcuheader->result = ERR_CIPN_RSAINLEN;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	
	RSA_key = pvPortMalloc(1408);
	if (RSA_key == NULL)
	{
		mcuheader->result = ERR_COMM_MALLOC;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	if(mcuheader->arg2 == 2048){
		memcpy(RSA_key,  indata, 1408);
		memcpy(in_data, indata+1408, in_len);
	}else{
		memcpy(RSA_key,  indata, 704);
		memcpy(in_data, indata+704, in_len);
	}
	//print(PRINT_INTERFACE,"RSA_key\n");
	//printfb(RSA_key, 704);		
	
	mcuheader->result = MUC_RSA_Prikey_Operation_external(RSA_key, in_data, in_len, out_data, &out_len);

	memcpy(outdata, out_data, in_len);
	mcuheader->arg1 = (uint16_t)out_len;
	mcuheader->length = FPGA_MCUHEAD_LEN + mcuheader->arg1;
	if (RSA_key)
	{
		vPortFree(RSA_key);		
	}
	if(mcuheader->arg1 == 0){
		mcuheader->result = ERR_CIPN_RSAPRIKEYOP;
	}
	
}
/*************************SD_TASK_INTPUBKEYOPER_RSA**********************
*内部公钥RSA运算
********************************************************************/
TASK_FUNC(do_SD_TASK_INTPUBKEYOPER_RSA)
{
	uint32_t out_len = 0;
	uint16_t in_len = mcuheader->arg1;
	uint8_t out_data[256]={0};
	uint8_t in_data[256]={0};
	uint16_t RSA_index = mcuheader->arg2;
	uint16_t RSA_bits = in_len*8;
	mcuheader->result = 0;
	if(DevStatusNo(WorkStatus)){ //状态检测
		mcuheader->result = ERR_DVES_WORKSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}	
	if(RSA_bits != 1024 && RSA_bits != 2048){
		mcuheader->result = ERR_CIPN_RSAINLEN;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	memcpy(in_data, indata, in_len);
	mcuheader->result = MUC_RSA_Pubkey_Operation_internal(RSA_index, in_data, in_len, out_data, &out_len);

	memcpy(outdata, out_data, in_len);
	mcuheader->arg1 = (uint16_t)out_len;
	mcuheader->length = FPGA_MCUHEAD_LEN + mcuheader->arg1;
	if(mcuheader->arg1 == 0){
		mcuheader->result = ERR_CIPN_RSAPUBKEYOP;
	}
}
/*************************SD_TASK_INTPRIKEYOPER_RSA**********************
*内部私钥RSA运算
********************************************************************/	
TASK_FUNC(do_SD_TASK_INTPRIKEYOPER_RSA)
{
	uint32_t out_len = 0;
	uint16_t in_len = mcuheader->arg1;
	uint8_t out_data[256]={0};
	uint8_t in_data[256]={0};
	uint16_t RSA_index = mcuheader->arg2;
	uint16_t RSA_bits = in_len*8;
	mcuheader->result = 0;
	if(DevStatusNo(WorkStatus)){ //状态检测
		mcuheader->result = ERR_DVES_WORKSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}	
	if(RSA_bits != 1024 && RSA_bits != 2048){
		mcuheader->result = ERR_CIPN_RSAINLEN;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	memcpy(in_data, indata, in_len);
	mcuheader->result = MUC_RSA_Prikey_Operation_internal(RSA_index, in_data, in_len, out_data, &out_len);

	memcpy(outdata, out_data, in_len);
	mcuheader->arg1 = (uint16_t)out_len;
	mcuheader->length = FPGA_MCUHEAD_LEN + mcuheader->arg1;
	if(mcuheader->arg1 == 0){
		mcuheader->result = ERR_CIPN_RSAPRIKEYOP;
	}
}
/*************************SD_TASK_EXTPRIKEYDEC_ECC***********************
*ECC外部公钥加密
********************************************************************/
TASK_FUNC(do_SD_TASK_EXTPUBKEYENC_ECC)
{
	uint32_t out_len;
	uint16_t data_len = mcuheader->arg1;
	uint8_t *mcu_data = NULL;
	uint8_t *enc_data = NULL;
	if(DevStatusNo(WorkStatus)){ //状态检测
		mcuheader->result = ERR_DVES_WORKSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}	
	do
	{
		if(mcuheader->length <= FPGA_MCUHEAD_LEN)
		{
			mcuheader->result = ERR_COMM_INPUT;
			break;
		}
		
		mcu_data = pvPortMalloc(mcuheader->length - FPGA_MCUHEAD_LEN);
		if (mcu_data == NULL)
		{
			mcuheader->result = ERR_COMM_MALLOC;
			break;
		}
		enc_data = pvPortMalloc(data_len + SM2_BYTE_LEN * 3);
		if (enc_data == NULL)
		{
			mcuheader->result = ERR_COMM_MALLOC;
			break;
		}
		memcpy(mcu_data, indata, mcuheader->length - FPGA_MCUHEAD_LEN);
		mcuheader->result = fpga_sm2_encrypt_external((SM2PublicKey *)mcu_data, (uint8_t *)(mcu_data + sizeof(SM2PublicKey)), data_len, enc_data, &out_len);
//		if (mcuheader->result)
//			mcuheader->result = rtval;
	} while (0);

	
	if (mcuheader->result)
	{
		mcuheader->length = FPGA_MCUHEAD_LEN;
	}
	else
	{
		memcpy(outdata, enc_data, out_len);
		mcuheader->arg1 = (uint16_t)out_len;
		mcuheader->length = FPGA_MCUHEAD_LEN + mcuheader->arg1;
	}
	
	if (mcu_data)
	{
		vPortFree(mcu_data);		
	}
	if (enc_data)
	{
		vPortFree(enc_data);		
	}
}
/*************************SD_TASK_EXTPRIKEYDEC_ECC***********************
*ECC外部私钥解密
********************************************************************/
TASK_FUNC(do_SD_TASK_EXTPRIKEYDEC_ECC)
{
	uint32_t out_len;
	uint16_t data_len = mcuheader->arg1;
	uint8_t *mcu_data = NULL;
	uint8_t *data_buff = NULL;
	if(DevStatusNo(WorkStatus)){ //状态检测
		mcuheader->result = ERR_DVES_WORKSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}	
	do
	{
		if(mcuheader->length <= FPGA_MCUHEAD_LEN)
		{
			mcuheader->result = ERR_COMM_INPUT;
			break;
		}
		mcu_data = pvPortMalloc(mcuheader->length - FPGA_MCUHEAD_LEN);
		if (mcu_data == NULL)
		{
			mcuheader->result = ERR_COMM_MALLOC;
			break;
		}
		if((data_len - SM2_BYTE_LEN * 3)<=0)
		{
			mcuheader->result = ERR_COMM_INPUT;
			break;
		}
		data_buff = pvPortMalloc(data_len - SM2_BYTE_LEN * 3+16);
		if (data_buff == NULL)
		{
			mcuheader->result = ERR_COMM_MALLOC;
			break;
		}
		memcpy(mcu_data, indata, mcuheader->length - FPGA_MCUHEAD_LEN);
		mcuheader->result = fpga_sm2_decrypt_external((SM2PrivateKey *)mcu_data, (uint8_t *)(mcu_data + sizeof(SM2PrivateKey)), data_len, data_buff, &out_len);
//		if (mcuheader->result)
//			mcuheader->result = ERR_CIPN_FPGASM2DECIN;
	} while (0);
	
	if (mcuheader->result)
	{
		mcuheader->length = FPGA_MCUHEAD_LEN;
	}
	else
	{
		memcpy(outdata, data_buff, FPGA_DATA_LEN(out_len));
		mcuheader->arg1 = (uint16_t)out_len;
		mcuheader->length = FPGA_MCUHEAD_LEN + mcuheader->arg1;
	}
	
	if (mcu_data)
	{
		vPortFree(mcu_data);		
	}
	if (data_buff)
	{
		vPortFree(data_buff);		
	}
}
/*************************SD_TASK_INTPUBKEYENC_ECC***********************
*ECC内部公钥加密
********************************************************************/
TASK_FUNC(do_SD_TASK_INTPUBKEYENC_ECC)
{
	uint32_t out_len;
	uint16_t key_index;
	uint16_t data_len = mcuheader->arg1;
	uint8_t *mcu_data = NULL;
	uint8_t *enc_data = NULL;
	if(DevStatusNo(WorkStatus)){ //状态检测
		mcuheader->result = ERR_DVES_WORKSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	do
	{
		if(mcuheader->length <= FPGA_MCUHEAD_LEN)
		{
			mcuheader->result = ERR_COMM_INPUT;
			break;
		}
		mcu_data = pvPortMalloc(mcuheader->length - FPGA_MCUHEAD_LEN);
		if (mcu_data == NULL)
		{
			mcuheader->result = ERR_COMM_MALLOC;
			break;
		}
		enc_data = pvPortMalloc(data_len + SM2_BYTE_LEN * 3);
		if (enc_data == NULL)
		{
			mcuheader->result = ERR_COMM_MALLOC;
			break;
		}
		
		key_index = mcuheader->arg2;
		memcpy(mcu_data, indata, mcuheader->length - FPGA_MCUHEAD_LEN);

		mcuheader->result = fpga_sm2_encrypt_internal(key_index, (uint8_t *)mcu_data, data_len, enc_data, &out_len);
//		if (mcuheader->result)
//				mcuheader->result = ERR_CIPN_FPGASM2ENCIN;
	} while (0);
	
	if (mcuheader->result)
	{
		mcuheader->length = FPGA_MCUHEAD_LEN;
	}
	else
	{
		memcpy(outdata, enc_data, out_len);
		mcuheader->arg1 = (uint16_t)out_len;
		mcuheader->length = FPGA_MCUHEAD_LEN + mcuheader->arg1;
	}
	
	if (mcu_data)
	{
		vPortFree(mcu_data);
	}
	if (enc_data)
	{
		vPortFree(enc_data);
	}
}
/*************************SD_TASK_INTPRIKEYDEC_ECC***********************
*ECC内部私钥解密
********************************************************************/
TASK_FUNC(do_SD_TASK_INTPRIKEYDEC_ECC)
{
	uint32_t out_len;
	uint16_t key_index;
	uint16_t data_len = mcuheader->arg1;
	uint8_t *mcu_data = NULL;
	uint8_t *data_buff = NULL;
	if(DevStatusNo(WorkStatus)){ //状态检测
		mcuheader->result = ERR_DVES_WORKSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	do
	{
		if(mcuheader->length <= FPGA_MCUHEAD_LEN)
		{
			mcuheader->result = ERR_COMM_INPUT;
			break;
		}
		mcu_data = pvPortMalloc(mcuheader->length - FPGA_MCUHEAD_LEN);
		if (mcu_data == NULL)
		{
			mcuheader->result = ERR_COMM_MALLOC;
			break;
		}
		if(data_len <= SM2_BYTE_LEN * 3)
		{
			mcuheader->result = ERR_COMM_INPUT;
			break;
		}
		data_buff = pvPortMalloc(data_len - SM2_BYTE_LEN * 3);
		if (data_buff == NULL)
		{
			mcuheader->result = ERR_COMM_MALLOC;
			break;
		}
		memcpy(mcu_data, indata, mcuheader->length - FPGA_MCUHEAD_LEN);
		key_index = mcuheader->arg2;
		mcuheader->result = fpga_sm2_decrypt_internal(key_index, (uint8_t *)mcu_data, mcuheader->arg1, data_buff, &out_len);
//		if (mcuheader->result)
//			mcuheader->result = ERR_CIPN_FPGASM2DECIN;
	} while (0);
	
	if (mcuheader->result)
	{
		mcuheader->length = FPGA_MCUHEAD_LEN;
	}
	else
	{
		memcpy(outdata, data_buff, FPGA_DATA_LEN(out_len));
		mcuheader->arg1 = (uint16_t)out_len;
		mcuheader->length = FPGA_MCUHEAD_LEN + mcuheader->arg1;
	}
	
	if (mcu_data)
	{
		vPortFree(mcu_data);		
	}
	if (data_buff)
	{
		vPortFree(data_buff);		
	}
}

/*************************SD_TASK_EXTPRIKEYSIGN_ECC***********************
*外部私钥ECC签名
********************************************************************/
TASK_FUNC(do_SD_TASK_EXTPRIKEYSIGN_ECC)			//外部私钥ECC签名
{
	uint32_t out_len = 0;
	uint16_t data_len = mcuheader->arg1;
	uint8_t *data_in_hash = NULL;
	uint8_t data_out[64];
	if(DevStatusNo(WorkStatus)){ //状态检测
		mcuheader->result = ERR_DVES_WORKSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}	
	do
	{
		data_in_hash = indata+32+sizeof(SM2PrivateKey);
		mcuheader->result = fpga_sm2_sign_external((SM2PrivateKey *)(indata+32), data_in_hash, data_out, data_out+32);
		//fpga_sm2_decrypt_external((SM2PrivateKey *)mcu_data, (uint8_t *)(mcu_data + sizeof(SM2PrivateKey)), data_len, data_buff, &out_len);
	} while (0);
	
	if (mcuheader->result)
	{
		mcuheader->result = SDR_SIGNERR;
		mcuheader->length = FPGA_MCUHEAD_LEN;
	}
	else
	{
		out_len = 64;
		memcpy(outdata, data_out, out_len);
		mcuheader->arg1 = (uint16_t)out_len;
		mcuheader->length = FPGA_MCUHEAD_LEN + mcuheader->arg1;
	}
}
/*************************SD_TASK_EXTPUBKEYVERI_ECC***********************
*外部公钥ECC验签
********************************************************************/
TASK_FUNC(do_SD_TASK_EXTPUBKEYVERI_ECC)			//外部公钥ECC验签
{
	uint32_t out_len = 0;
	uint16_t data_len = mcuheader->arg1;
	uint8_t *data_in_hash = NULL;
	uint8_t *data_sign = NULL;
	if(DevStatusNo(WorkStatus)){ //状态检测
		mcuheader->result = ERR_DVES_WORKSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	do
	{
		data_in_hash = indata+sizeof(SM2PublicKey);
		data_sign = data_in_hash + 32;
		mcuheader->result = fpga_sm2_verify_external((SM2PublicKey *)(indata), data_sign, data_sign+32, data_in_hash);
	} while (0);
	if (mcuheader->result)
	{
		mcuheader->result = SDR_VERIFYERR;
		mcuheader->length = FPGA_MCUHEAD_LEN;
	}
	else
	{
		mcuheader->length = FPGA_MCUHEAD_LEN;
	}
}
/*************************SD_TASK_INTPRIKEYSIGN_ECC***********************
*内部私钥ECC签名
********************************************************************/
TASK_FUNC(do_SD_TASK_INTPRIKEYSIGN_ECC)			//内部私钥ECC签名
{
	uint32_t out_len = 0;
	uint16_t keyindex = mcuheader->arg1;
	uint8_t *data_in_hash = NULL;
	uint8_t data_out[64];
	if(DevStatusNo(WorkStatus)){ //状态检测
		mcuheader->result = ERR_DVES_WORKSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}	
	do
	{
		data_in_hash = indata+32;
		mcuheader->result = fpga_sm2_sign_internal(keyindex, data_in_hash, data_out, data_out+32);
		//fpga_sm2_decrypt_external((SM2PrivateKey *)mcu_data, (uint8_t *)(mcu_data + sizeof(SM2PrivateKey)), data_len, data_buff, &out_len);
	} while (0);
	
	if (mcuheader->result)
	{ //ERR_CIPN_USRKEYNOEXIT
		mcuheader->result = SDR_SIGNERR;
		mcuheader->length = FPGA_MCUHEAD_LEN;
	}
	else
	{
		out_len = 64;
		memcpy(outdata, data_out, out_len);
		mcuheader->arg1 = (uint16_t)out_len;
		mcuheader->length = FPGA_MCUHEAD_LEN + mcuheader->arg1;
	}
}
/*************************SD_TASK_INTPUBKEYVERI_ECC***********************
*内部公钥ECC验签
********************************************************************/
TASK_FUNC(do_SD_TASK_INTPUBKEYVERI_ECC)			//内部公钥ECC验签
{
	uint32_t out_len = 0;
	uint16_t keyindex = mcuheader->arg1;
	uint8_t *data_in_hash = NULL;
	uint8_t *data_sign = NULL;
	if(DevStatusNo(WorkStatus)){ //状态检测
		mcuheader->result = ERR_DVES_WORKSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	do
	{
		data_in_hash = indata;
		data_sign = data_in_hash + 32;
		mcuheader->result = fpga_sm2_verify_internal(keyindex, data_sign, data_sign+32, data_in_hash);
	} while (0);
	if (mcuheader->result)
	{
		mcuheader->result = SDR_VERIFYERR;
		mcuheader->length = FPGA_MCUHEAD_LEN;
	}
	else
	{
		mcuheader->length = FPGA_MCUHEAD_LEN;
	}
}
/*************************SD_TASK_INTSYMENC_SM1***********************
*SM1内部秘钥加密
********************************************************************/
TASK_FUNC(do_SD_TASK_INTSYMENC_SM1){
	uint16_t ret = 0;
	uint16_t out_len = 0;
	uint16_t in_len 	 = mcuheader->arg1;
	uint16_t key_index = mcuheader->arg2;
	uint16_t iven = ((mcuheader->result)&0x8000)>>15;
	uint16_t key_len = 16;//(mcuheader->result)&0x7fff;
	uint8_t iv[32] = {0};
	uint8_t key[32] = {0};
	uint8_t *in_data = NULL;
	uint8_t *out_data = NULL;
	mcuheader->result = 0;
	if(DevStatusNo(WorkStatus)){ //状态检测
		mcuheader->result = ERR_DVES_WORKSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	ret = read_sessionkey_mcu(&out_len,key,key_index);
	if(ret){
		mcuheader->result = ret;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	if(out_len != key_len){
		mcuheader->result = ERR_CIPN_SKEYLEN;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	if(iven){
		memcpy(iv, indata+ret, 16);
		ret += 16;
	}
	if(in_len <= 0)
		{
			mcuheader->result = ERR_COMM_INPUT;
			mcuheader->length=FPGA_MCUHEAD_LEN;
			return;
		}
	in_data = pvPortMalloc(in_len);
	if (in_data == NULL){
		mcuheader->result = ERR_COMM_MALLOC;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	memcpy(in_data, indata+ret, in_len);
	out_data = pvPortMalloc(in_len);
	if(out_data == NULL){
		mcuheader->result = ERR_COMM_MALLOC;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		vPortFree(in_data);	
		return;
	}
	mcuheader->result = Sym_Crypt_WithKey(in_data,in_len,key,out_len,iv,16,SYM_ALG_SM1,SYM_ENCRYPTION, iven,out_data);
	memcpy(outdata, out_data, in_len);
	mcuheader->arg1 = (uint16_t)in_len;
	mcuheader->length = FPGA_MCUHEAD_LEN + mcuheader->arg1;	

	vPortFree(in_data);	
	vPortFree(out_data);
}
/*************************SD_TASK_INTSYMENC_SM1***********************
*SM1内部秘钥解密
********************************************************************/
TASK_FUNC(do_SD_TASK_INTSYMDEC_SM1){
	uint16_t ret = 0;
	uint16_t out_len = 0;
	uint16_t in_len 	 = mcuheader->arg1;
	uint16_t key_index = mcuheader->arg2;
	uint16_t iven = ((mcuheader->result)&0x8000)>>15;
	uint16_t key_len = (mcuheader->result)&0x7fff;
	uint8_t iv[32] = {0};
	uint8_t key[32] = {0};
	uint8_t *in_data = NULL;
	uint8_t *out_data = NULL;
	mcuheader->result = 0;
	if(DevStatusNo(WorkStatus)){ //状态检测
		mcuheader->result = ERR_DVES_WORKSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	ret = read_sessionkey_mcu(&out_len,key,key_index);
	if(ret){
		mcuheader->result = ret;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	if(out_len != key_len){
		mcuheader->result = ERR_CIPN_SKEYLEN;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	if(iven){
		memcpy(iv, indata+ret, 16);
		ret += 16;
	}
	if(in_len <= 0)
	{
		mcuheader->result = ERR_COMM_INPUT;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	in_data = pvPortMalloc(in_len);
	if (in_data == NULL){
		mcuheader->result = ERR_COMM_MALLOC;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	memcpy(in_data, indata+ret, in_len);
	out_data = pvPortMalloc(in_len);
	if(out_data == NULL){
		mcuheader->result = ERR_COMM_MALLOC;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		vPortFree(in_data);	
		return;
	}
	mcuheader->result = Sym_Crypt_WithKey(in_data,in_len,key,out_len,iv,16,SYM_ALG_SM1,SYM_DECRYPTION, iven,out_data);
	memcpy(outdata, out_data, in_len);
	mcuheader->arg1 = (uint16_t)in_len;
	mcuheader->length = FPGA_MCUHEAD_LEN + mcuheader->arg1;	

	vPortFree(in_data);
	vPortFree(out_data);
}
/*************************SD_TASK_INTSYMENC_SM1***********************
*SM1外部秘钥加密
********************************************************************/
TASK_FUNC(do_SD_TASK_EXTSYMENC_SM1){
	uint16_t ret = 0;
	//uint16_t out_len = 0;
	uint16_t in_len  = mcuheader->arg1;
	uint16_t key_len = 16;//BIT_TO_BYTE(mcuheader->arg2);
	uint16_t iven 	 = ((mcuheader->result)&0x8000)>>15;
	uint8_t iv[32]   = {0};
	uint8_t key[32]  = {0};
	uint8_t *in_data = NULL;
	uint8_t *out_data= NULL;
	mcuheader->result= 0;
	if(DevStatusNo(WorkStatus)){ //状态检测
		mcuheader->result = ERR_DVES_WORKSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	if(key_len > 32){
		mcuheader->result = ERR_CIPN_SKEYLEN;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	memcpy(key, indata, key_len);
	ret += key_len;
	if(iven){
		memcpy(iv, indata+ret, 16);
		ret += 16;
	}
	if(in_len <= 0)
	{
		mcuheader->result = ERR_COMM_INPUT;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	in_data = pvPortMalloc(in_len);
	if (in_data == NULL){
		mcuheader->result = ERR_COMM_MALLOC;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	memcpy(in_data, indata+ret, in_len);
	out_data = pvPortMalloc(in_len);
	if(out_data == NULL){
		mcuheader->result = ERR_COMM_MALLOC;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		vPortFree(in_data);	
		return;
	}
	mcuheader->result = Sym_Crypt_WithKey(in_data,in_len,key,key_len,iv,16,SYM_ALG_SM1,SYM_ENCRYPTION, iven,out_data);
	memcpy(outdata, out_data, in_len);
	mcuheader->arg1 = (uint16_t)in_len;
	mcuheader->length = FPGA_MCUHEAD_LEN + mcuheader->arg1;	

	vPortFree(in_data);	
	vPortFree(out_data);
}
/*************************SD_TASK_INTSYMENC_SM1***********************
*SM1外部秘钥解密
********************************************************************/
TASK_FUNC(do_SD_TASK_EXTSYMDEC_SM1){
	uint16_t ret = 0;
	//uint16_t out_len = 0;
	uint16_t in_len  = mcuheader->arg1;
	uint16_t key_len = 16;//BIT_TO_BYTE(mcuheader->arg2);
	uint16_t iven 	 = ((mcuheader->result)&0x8000)>>15;
	uint8_t iv[32]   = {0};
	uint8_t key[32]  = {0};
	uint8_t *in_data = NULL;
	uint8_t *out_data= NULL;
	mcuheader->result= 0;
	if(DevStatusNo(WorkStatus)){ //状态检测
		mcuheader->result = ERR_DVES_WORKSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	if(key_len > 32){
		mcuheader->result = ERR_CIPN_SKEYLEN;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	memcpy(key, indata, key_len);
	ret += key_len;
	if(iven){
		memcpy(iv, indata+ret, 16);
		ret += 16;
	}
	if(in_len <= 0)
	{
		mcuheader->result = ERR_COMM_INPUT;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	in_data = pvPortMalloc(in_len);
	if (in_data == NULL){
		mcuheader->result = ERR_COMM_MALLOC;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	memcpy(in_data, indata+ret, in_len);
	out_data = pvPortMalloc(in_len);
	if(out_data == NULL){
		mcuheader->result = ERR_COMM_MALLOC;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		vPortFree(in_data);	
		return;
	}
	mcuheader->result = Sym_Crypt_WithKey(in_data,in_len,key,key_len,iv,16,SYM_ALG_SM1,SYM_DECRYPTION, iven,out_data);
	memcpy(outdata, out_data, in_len);
	mcuheader->arg1 = (uint16_t)in_len;
	mcuheader->length = FPGA_MCUHEAD_LEN + mcuheader->arg1;	

	vPortFree(in_data);
	vPortFree(out_data);
}
/*************************SD_TASK_INTSYMENC_AES***********************
*AES内部秘钥加密
********************************************************************/
TASK_FUNC(do_SD_TASK_INTSYMENC_AES)
{
	uint16_t ret = 0;
	uint16_t out_len = 0;
	uint16_t in_len 	 = mcuheader->arg1;
	uint16_t key_index = mcuheader->arg2;
	uint16_t iven = ((mcuheader->result)&0x8000)>>15;
	uint16_t key_len = (mcuheader->result)&0x7fff;
	uint8_t iv[32] = {0};
	uint8_t key[32] = {0};
	uint8_t *in_data = NULL;
	uint8_t *out_data = NULL;
	mcuheader->result = 0;
	if(DevStatusNo(WorkStatus)){ //状态检测
		mcuheader->result = ERR_DVES_WORKSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	ret = read_sessionkey_mcu(&out_len,key,key_index);
	if(ret){
		mcuheader->result = ret;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	if(out_len != key_len){
		mcuheader->result = ERR_COMM_INPUT;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	if(iven){
		memcpy(iv, indata+ret, 16);
		ret += 16;
	}
	if(in_len <= 0)
	{
		mcuheader->result = ERR_COMM_INPUT;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	in_data = pvPortMalloc(in_len);
	if (in_data == NULL){
		mcuheader->result = ERR_COMM_MALLOC;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	memcpy(in_data, indata+ret, in_len);
	out_data = pvPortMalloc(in_len);
	if(out_data == NULL){
		mcuheader->result = ERR_COMM_MALLOC;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		vPortFree(in_data);	
		return;
	}
	mcuheader->result = Sym_Crypt_WithKey(in_data,in_len,key,out_len,iv,16,SYM_ALG_AES,SYM_ENCRYPTION, iven,out_data);
	memcpy(outdata, out_data, in_len);
	mcuheader->arg1 = (uint16_t)in_len;
	mcuheader->length = FPGA_MCUHEAD_LEN + mcuheader->arg1;	

	vPortFree(in_data);	
	vPortFree(out_data);
}	
/*************************SD_TASK_INTSYMENC_AES***********************
*AES外部秘钥加密
********************************************************************/
TASK_FUNC(do_SD_TASK_EXTSYMENC_AES)
{
	uint16_t ret = 0;
	//uint16_t out_len = 0;
	uint16_t in_len  = mcuheader->arg1;
	uint16_t key_len = BIT_TO_BYTE(mcuheader->arg2);
	uint16_t iven 	 = ((mcuheader->result)&0x8000)>>15;
	uint8_t iv[32]   = {0};
	uint8_t key[32]  = {0};
	uint8_t *in_data = NULL;
	uint8_t *out_data= NULL;
	mcuheader->result= 0;
	if(DevStatusNo(WorkStatus)){ //状态检测
		mcuheader->result = ERR_DVES_WORKSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	if(key_len > 32){
		mcuheader->result = ERR_CIPN_INDEXLEN;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	memcpy(key, indata, key_len);
	ret += key_len;
	if(iven){
		memcpy(iv, indata+ret, 16);
		ret += 16;
	}
	if(in_len <= 0)
	{
		mcuheader->result = ERR_COMM_INPUT;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	in_data = pvPortMalloc(in_len);
	if (in_data == NULL){
		mcuheader->result = ERR_COMM_MALLOC;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	memcpy(in_data, indata+ret, in_len);
	out_data = pvPortMalloc(in_len);
	if(out_data == NULL){
		mcuheader->result = ERR_COMM_MALLOC;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		vPortFree(in_data);	
		return;
	}
	mcuheader->result = Sym_Crypt_WithKey(in_data,in_len,key,key_len,iv,16,SYM_ALG_AES,SYM_ENCRYPTION, iven,out_data);
	memcpy(outdata, out_data, in_len);
	mcuheader->arg1 = (uint16_t)in_len;
	mcuheader->length = FPGA_MCUHEAD_LEN + mcuheader->arg1;	

	vPortFree(in_data);	
	vPortFree(out_data);
}
/*************************SD_TASK_INTSYMENC_DES***********************
*DES内部秘钥加密
********************************************************************/
TASK_FUNC(do_SD_TASK_INTSYMENC_DES)
{
	uint16_t ret = 0;
	uint16_t out_len = 0;
	uint16_t in_len 	 = mcuheader->arg1;
	uint16_t key_index = mcuheader->arg2;
	uint16_t iven = ((mcuheader->result)&0x8000)>>15;
	uint16_t key_len = (mcuheader->result)&0x7fff;
	uint8_t iv[32] = {0};
	uint8_t key[32] = {0};
	uint8_t *in_data = NULL;
	uint8_t *out_data = NULL;
	mcuheader->result = 0;
	if(DevStatusNo(WorkStatus)){ //状态检测
		mcuheader->result = ERR_DVES_WORKSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	ret = read_sessionkey_mcu(&out_len,key,key_index);
	if(ret){
		mcuheader->result = ret;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	if(out_len != key_len){
		mcuheader->result = ERR_COMM_INPUT;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	if(key_len != 8 && key_len != 24){
		mcuheader->result = ERR_CIPN_INDEXLEN;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	if(iven){
		memcpy(iv, indata+ret, 8);
		ret += 8;
	}
	if(in_len <= 0)
	{
		mcuheader->result = ERR_COMM_INPUT;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	in_data = pvPortMalloc(in_len);
	if (in_data == NULL){
		mcuheader->result = ERR_COMM_MALLOC;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	memcpy(in_data, indata+ret, in_len);
	out_data = pvPortMalloc(in_len);
	if(out_data == NULL){
		mcuheader->result = ERR_COMM_MALLOC;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		vPortFree(in_data);	
		return;
	}
	mcuheader->result = Sym_Crypt_WithKey(in_data,in_len,key,out_len,iv,8,key_len==8?SYM_ALG_DES:SYM_ALG_3DES,SYM_ENCRYPTION, iven,out_data);
	memcpy(outdata, out_data, in_len);
	mcuheader->arg1 = (uint16_t)in_len;
	mcuheader->length = FPGA_MCUHEAD_LEN + mcuheader->arg1;	

	vPortFree(in_data);	
	vPortFree(out_data);
}

/*************************SD_TASK_INTSYMENC_DES***********************
*DES外部秘钥加密
********************************************************************/
TASK_FUNC(do_SD_TASK_EXTSYMENC_DES)
{
	uint16_t ret = 0;
	//uint16_t out_len = 0;
	uint16_t in_len  = mcuheader->arg1;
	uint16_t key_len = BIT_TO_BYTE(mcuheader->arg2);
	uint16_t iven 	 = ((mcuheader->result)&0x8000)>>15;
	uint8_t iv[32]   = {0};
	uint8_t key[32]  = {0};
	uint8_t *in_data = NULL;
	uint8_t *out_data= NULL;
	mcuheader->result= 0;
	if(DevStatusNo(WorkStatus)){ //状态检测
		mcuheader->result = ERR_DVES_WORKSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	if(key_len != 8 && key_len != 24){
		mcuheader->result = ERR_CIPN_INDEXLEN;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	memcpy(key, indata, key_len);
	ret += key_len;
	if(iven){
		memcpy(iv, indata+ret, 8);
		ret += 8;
	}
	if(in_len <= 0)
	{
		mcuheader->result = ERR_COMM_INPUT;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	in_data = pvPortMalloc(in_len);
	if (in_data == NULL){
		mcuheader->result = ERR_COMM_MALLOC;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	memcpy(in_data, indata+ret, in_len);
	out_data = pvPortMalloc(in_len);
	if(out_data == NULL){
		mcuheader->result = ERR_COMM_MALLOC;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		vPortFree(in_data);	
		return;
	}
	mcuheader->result = Sym_Crypt_WithKey(in_data,in_len,key,key_len,iv,8,key_len==8?SYM_ALG_DES:SYM_ALG_3DES,SYM_ENCRYPTION, iven,out_data);
	memcpy(outdata, out_data, in_len);
	mcuheader->arg1 = (uint16_t)in_len;
	mcuheader->length = FPGA_MCUHEAD_LEN + mcuheader->arg1;	

	vPortFree(in_data);	
	vPortFree(out_data);
	
}
/*************************SD_TASK_INTSYMENC_AES***********************
*AES内部秘钥解密
********************************************************************/
TASK_FUNC(do_SD_TASK_INTSYMDEC_AES)
{
	uint16_t ret = 0;
	uint16_t out_len = 0;
	uint16_t in_len 	 = mcuheader->arg1;
	uint16_t key_index = mcuheader->arg2;
	uint16_t iven = ((mcuheader->result)&0x8000)>>15;
	uint16_t key_len = (mcuheader->result)&0x7fff;
	uint8_t iv[32] = {0};
	uint8_t key[32] = {0};
	uint8_t *in_data = NULL;
	uint8_t *out_data = NULL;
	mcuheader->result = 0;
	if(DevStatusNo(WorkStatus)){ //状态检测
		mcuheader->result = ERR_DVES_WORKSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	ret = read_sessionkey_mcu(&out_len,key,key_index);
	if(ret){
		mcuheader->result = ret;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	if(out_len != key_len){
		mcuheader->result = ERR_COMM_INPUT;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	if(iven){
		memcpy(iv, indata+ret, 16);
		ret += 16;
	}
	if(in_len <= 0)
	{
		mcuheader->result = ERR_COMM_INPUT;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	in_data = pvPortMalloc(in_len);
	if (in_data == NULL){
		mcuheader->result = ERR_COMM_MALLOC;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	memcpy(in_data, indata+ret, in_len);
	out_data = pvPortMalloc(in_len);
	if(out_data == NULL){
		mcuheader->result = ERR_COMM_MALLOC;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		vPortFree(in_data);	
		return;
	}
	mcuheader->result = Sym_Crypt_WithKey(in_data,in_len,key,out_len,iv,16,SYM_ALG_AES,SYM_DECRYPTION, iven,out_data);
	memcpy(outdata, out_data, in_len);
	mcuheader->arg1 = (uint16_t)in_len;
	mcuheader->length = FPGA_MCUHEAD_LEN + mcuheader->arg1;	

	vPortFree(in_data);
	vPortFree(out_data);
}
/*************************SD_TASK_INTSYMENC_AES***********************
*AES外部秘钥解密
********************************************************************/
TASK_FUNC(do_SD_TASK_EXTSYMDEC_AES)
{
	uint16_t ret = 0;
	//uint16_t out_len = 0;
	uint16_t in_len  = mcuheader->arg1;
	uint16_t key_len = BIT_TO_BYTE(mcuheader->arg2);
	uint16_t iven 	 = ((mcuheader->result)&0x8000)>>15;
	uint8_t iv[32]   = {0};
	uint8_t key[32]  = {0};
	uint8_t *in_data = NULL;
	uint8_t *out_data= NULL;
	mcuheader->result= 0;
	if(DevStatusNo(WorkStatus)){ //状态检测
		mcuheader->result = ERR_DVES_WORKSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	if(key_len > 32){
		mcuheader->result = ERR_CIPN_INDEXLEN;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	memcpy(key, indata, key_len);
	ret += key_len;
	if(iven){
		memcpy(iv, indata+ret, 16);
		ret += 16;
	}
	if(in_len <= 0)
	{
		mcuheader->result = ERR_COMM_INPUT;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	in_data = pvPortMalloc(in_len);
	if (in_data == NULL){
		mcuheader->result = ERR_COMM_MALLOC;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	memcpy(in_data, indata+ret, in_len);
	out_data = pvPortMalloc(in_len);
	if(out_data == NULL){
		mcuheader->result = ERR_COMM_MALLOC;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		vPortFree(in_data);	
		return;
	}
	mcuheader->result = Sym_Crypt_WithKey(in_data,in_len,key,key_len,iv,16,SYM_ALG_AES,SYM_DECRYPTION, iven,out_data);
	memcpy(outdata, out_data, in_len);
	mcuheader->arg1 = (uint16_t)in_len;
	mcuheader->length = FPGA_MCUHEAD_LEN + mcuheader->arg1;	

	vPortFree(in_data);
	vPortFree(out_data);
}
/*************************SD_TASK_INTSYMENC_DES***********************
*DES内部秘钥解密
********************************************************************/
TASK_FUNC(do_SD_TASK_INTSYMDEC_DES)
{
	uint16_t ret = 0;
	uint16_t out_len = 0;
	uint16_t in_len 	 = mcuheader->arg1;
	uint16_t key_index = mcuheader->arg2;
	uint16_t iven = ((mcuheader->result)&0x8000)>>15;
	uint16_t key_len = (mcuheader->result)&0x7fff;
	uint8_t iv[32] = {0};
	uint8_t key[32] = {0};
	uint8_t *in_data = NULL;
	uint8_t *out_data = NULL;
	mcuheader->result = 0;
	if(DevStatusNo(WorkStatus)){ //状态检测
		mcuheader->result = ERR_DVES_WORKSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	ret = read_sessionkey_mcu(&out_len,key,key_index);
	if(ret){
		mcuheader->result = ret;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	if(out_len != key_len){
		mcuheader->result = ERR_COMM_INPUT;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	if(key_len != 8 && key_len != 24){
		mcuheader->result = ERR_CIPN_INDEXLEN;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	if(iven){
		memcpy(iv, indata+ret, 8);
		ret += 8;
	}
	if(in_len <= 0)
	{
		mcuheader->result = ERR_COMM_INPUT;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	in_data = pvPortMalloc(in_len);
	if (in_data == NULL){
		mcuheader->result = ERR_COMM_MALLOC;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	memcpy(in_data, indata+ret, in_len);
	out_data = pvPortMalloc(in_len);
	if(out_data == NULL){
		mcuheader->result = ERR_COMM_MALLOC;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		vPortFree(in_data);	
		return;
	}
	mcuheader->result = Sym_Crypt_WithKey(in_data,in_len,key,out_len,iv,8,key_len==8?SYM_ALG_DES:SYM_ALG_3DES,SYM_DECRYPTION, iven,out_data);
	memcpy(outdata, out_data, in_len);
	mcuheader->arg1 = (uint16_t)in_len;
	mcuheader->length = FPGA_MCUHEAD_LEN + mcuheader->arg1;	

	vPortFree(in_data);
	vPortFree(out_data);
	
}
/*************************SD_TASK_INTSYMENC_DES***********************
*DES外部秘钥解密
********************************************************************/
TASK_FUNC(do_SD_TASK_EXTSYMDEC_DES)
{
	uint16_t ret = 0;
	//uint16_t out_len = 0;
	uint16_t in_len  = mcuheader->arg1;
	uint16_t key_len = BIT_TO_BYTE(mcuheader->arg2);
	uint16_t iven 	 = ((mcuheader->result)&0x8000)>>15;
	uint8_t iv[32]   = {0};
	uint8_t key[32]  = {0};
	uint8_t *in_data = NULL;
	uint8_t *out_data= NULL;
	mcuheader->result= 0;
	if(DevStatusNo(WorkStatus)){ //状态检测
		mcuheader->result = ERR_DVES_WORKSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	if(key_len != 8 && key_len != 24){
		mcuheader->result = ERR_CIPN_INDEXLEN;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	memcpy(key, indata, key_len);
	ret += key_len;
	if(iven){
		memcpy(iv, indata+ret, 8);
		ret += 8;
	}
	if(in_len <= 0)
	{
		mcuheader->result = ERR_COMM_INPUT;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	in_data = pvPortMalloc(in_len);
	if (in_data == NULL){
		mcuheader->result = ERR_COMM_MALLOC;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	memcpy(in_data, indata+ret, in_len);
	out_data = pvPortMalloc(in_len);
	if(out_data == NULL){
		mcuheader->result = ERR_COMM_MALLOC;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		vPortFree(in_data);	
		return;
	}
	mcuheader->result = Sym_Crypt_WithKey(in_data,in_len,key,key_len,iv,8,key_len==8?SYM_ALG_DES:SYM_ALG_3DES,SYM_DECRYPTION, iven,out_data);
	memcpy(outdata, out_data, in_len);
	mcuheader->arg1 = (uint16_t)in_len;
	mcuheader->length = FPGA_MCUHEAD_LEN + mcuheader->arg1;	

	vPortFree(in_data);
	vPortFree(out_data);

}

////////////////////////////////文件管理/////////////////////////////////
/*************************SD_TASK_CREATEFILE**********************
*创建文件
********************************************************************/
TASK_FUNC(do_SD_TASK_CREATEFILE)
{
	char filename[256];
	uint32_t filesize = 0;			
	uint32_t namelen = 0;
	mcuheader->result = 0;
	if(DevStatusNo(WorkStatus)){ //状态检测
		mcuheader->result = ERR_DVES_WORKSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	filesize = mcuheader->arg1;
	namelen = *(uint32_t*)indata;
	if(namelen > 128 || namelen == 0){
		mcuheader->result = ERR_COMM_INPUTLEN;
		mcuheader->length = FPGA_MCUHEAD_LEN;
		return;
	}
	memcpy(filename, indata+4, namelen);
	
	if(create_fs_file(filename, namelen, filesize)){
			mcuheader->result = ERR_CIPN_CREATEFILE;
	}
	mcuheader->total = 1;
	mcuheader->count = 1;
	mcuheader->arg1  = 0;
	mcuheader->length = FPGA_MCUHEAD_LEN;

}
/*************************SD_TASK_READFILE**********************
*读取文件
********************************************************************/
TASK_FUNC(do_SD_TASK_READFILE)
{
	char filename[256]={0};
	uint8_t *pchar = NULL;
	uint8_t *out_data = NULL;
	uint8_t  namelen = 0;
	uint32_t offset=0;
	uint32_t readlen=0;
	mcuheader->result = 0;
	//uint32_t read_i=0;
	if(DevStatusNo(WorkStatus)){ //状态检测
		mcuheader->result = ERR_DVES_WORKSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		fpgaheader->pkglen=FPGA_DATAHEAD_LEN+FPGA_MCUHEAD_LEN;
		goto endreadfile;
	}
	//获取header参数
	offset = mcuheader->arg1;
	readlen= mcuheader->arg2;
	
	out_data = pvPortMalloc(readlen+16);
	if (out_data == NULL){
		mcuheader->result = ERR_COMM_MALLOC;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		fpgaheader->pkglen=FPGA_DATAHEAD_LEN+FPGA_MCUHEAD_LEN;
		goto endreadfile;
	}
	
	namelen = *(uint32_t*)indata;
	if(namelen > 128 || namelen == 0){
		mcuheader->result = ERR_COMM_INPUTLEN;
		mcuheader->length = FPGA_MCUHEAD_LEN;
		fpgaheader->pkglen=FPGA_DATAHEAD_LEN+FPGA_MCUHEAD_LEN;
		goto endreadfile;
	}
	memcpy(filename, indata+4, namelen);
//	print(0,"namelen %d\r\n",namelen);
//	print(PRINT_INTERFACE,"fname %s\r\n",filename);
//   for(int i=0;i<10;i++){
//    print(0,"%c",*((uint8_t*)filename+i));
//  }
	//管理员下可以读取@bug日志内容
#ifdef DEBUG
	if(eFlash.DEV_STATE == ManagementStatus){
		if(!memcmp(filename,"__@bug",6))
		{
			delete_fs_file(filename,namelen);
			if((mcuheader->result = create_fs_file(filename, namelen, 2048))){
				//if(FR_EXIST == mcuheader->result) break;
				print(PRINT_INTERFACE,"file CR err %x\r\n",mcuheader->result);
				mcuheader->result = ERR_CIPN_CREATEFILE;
				mcuheader->length = FPGA_MCUHEAD_LEN;
				goto endreadfile;
			}
			print(PRINT_COM,"Heap:%d\r\n",xPortGetFreeHeapSize());
			vTaskDelay(100);
			if((mcuheader->result = write_file(filename,namelen,0,BUG_DATA,2048))){
				print(PRINT_INTERFACE,"file WE err %x\r\n",mcuheader->result);
				mcuheader->result = ERR_CIPN_CREATEFILE;
				mcuheader->length = FPGA_MCUHEAD_LEN;
				goto endreadfile;
			}
		}
	}
#endif

	mcuheader->result = read_file(filename,namelen,offset,out_data,&readlen);
//   for(int i=0;i<2048;i++){
//    print(0,"%c",*((uint8_t*)out_data+i));
//  }
	if(mcuheader->result){
		fpgaheader->pkglen=FPGA_DATAHEAD_LEN+FPGA_MCUHEAD_LEN;
		readlen = 0;
	}	
	else{
		memcpy(outdata, out_data, FPGA_DATA_LEN(readlen));
		fpgaheader->pkglen = ((readlen)%SM4_BLOCK_LEN?SM4_ENCDATA_LEN(readlen):(readlen)) \
												+FPGA_MCUHEAD_LEN+FPGA_DATAHEAD_LEN;
	}	
	fpgaheader->retpkglen = 0;						//存疑
	//mcuheader->total = PAGE_NUM(readlen);
	//mcuheader->count = PAGE_NUM(readlen);
	mcuheader->arg1  = 0;
	mcuheader->arg2  = readlen;
	mcuheader->length = FPGA_MCUHEAD_LEN+mcuheader->arg2;//fpgaheader->pkglen - FPGA_DATAHEAD_LEN;
endreadfile:
	if(fpga_write_start()==REG_REST) return;
	pchar=set_fpga_header((uint8_t *)FPGA_DATA_WRITE_ADDR,fpgaheader);
	pchar=set_mcu_header(pchar,mcuheader);
	fpga_write_finish(fpgaheader->pkglen);
	vPortFree(out_data);	
}


/*************************SD_TASK_WRITEFILE**********************
*写入文件  //更改为单包处理，由驱动分包
********************************************************************/
TASK_FUNC(do_SD_TASK_WRITEFILE)	
{
	//char	*filename=NULL;
	uint8_t 	ret=0;
	char filename[256];
	uint8_t 	namelen=0;
	uint32_t	offset=0;
	uint32_t 	writelen=0;
	uint32_t 	writelenall=0;

	//uint16_t current_pkg_len=0;
	if(DevStatusNo(WorkStatus)){ //状态检测
		mcuheader->result = ERR_DVES_WORKSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	//获取header参数
	offset = mcuheader->arg1;
	writelen= mcuheader->arg2;
	//writelenall = mcuheader->result;
	mcuheader->result = 0;
	namelen = *(uint32_t*)indata;
	if(namelen > 128 || namelen == 0){
		mcuheader->result = ERR_COMM_INPUTLEN;
		mcuheader->length = FPGA_MCUHEAD_LEN;
		return;
	}	
	memcpy(filename, indata+4, namelen);//filename = (char *)indata+4;
	
	ret=CheckPara(filename,namelen,offset,&writelen);
	if(ret){
		mcuheader->result = ret;
		mcuheader->length = FPGA_MCUHEAD_LEN;
		return;
	}
	//mcuheader->total = 1;
	//mcuheader->count = 1;
	mcuheader->arg1  = writelen;
	mcuheader->arg2  = 0;
	mcuheader->length = FPGA_MCUHEAD_LEN;
	mcuheader->result = write_file(filename,namelen,offset,indata+namelen+4,writelen);
}

/*************************SD_TASK_DELETEFILE**********************
*删除文件
********************************************************************/
TASK_FUNC(do_SD_TASK_DELETEFILE)
{
	char *filename = NULL;
	uint32_t namelen=NULL;
	namelen = *(uint32_t*) indata;
	filename = (char *)indata+4;
	if(DevStatusNo(WorkStatus)){ //状态检测
		mcuheader->result = ERR_DVES_WORKSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}	
	mcuheader->total = 1;
	mcuheader->count = 1;
	mcuheader->arg1  = 0;
	mcuheader->length = FPGA_MCUHEAD_LEN;
	if(delete_fs_file(filename,namelen))
		mcuheader->result =ERR_CIPN_DELKEYFILE;

}

/*************************do_SD_TASK_CLEARFILE**********************
*清除文件
********************************************************************/
TASK_FUNC(do_SD_TASK_CLEARFILE)
{
	if(DevStatusNo(ManagementStatus)){ //状态检测
		mcuheader->result = ERR_DVES_MANGSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}		
	mcuheader->total = 1;
	mcuheader->count = 1;
	mcuheader->arg1  = 0;
	mcuheader->length = FPGA_MCUHEAD_LEN;
	if(clear_fs_file())
		mcuheader->result = ERR_CIPN_DELKEYFILE;
}
/*************************do_SD_TASK_ENUMFILE**********************
*枚举文件
********************************************************************/
TASK_FUNC(do_SD_TASK_ENUMFILE)
{
	uint8_t enum_count=0;
	if(enum_usr_file(mcuheader->arg1,mcuheader->arg2,&enum_count,outdata))
		mcuheader->result = ERR_CIPN_READKEYFILE;
	mcuheader->arg2 =enum_count; 
	mcuheader->length= FPGA_MCUHEAD_LEN+enum_count*128;
}

///////////////////////////////用户管理/////////////////////////////////
/*************************SD_TASK_ADDUSER**********************
*添加用户(管理员/操作员)
********************************************************************/
TASK_FUNC(do_SD_TASK_ADDUSER)
{
	
	int ret;
  char *pin = pvPortMalloc(16);//FPGA_DATA_LEN(mcuheader->arg2)
  memset(pin, 0, 16);
  memcpy(pin, indata, mcuheader->arg2);
		
	if(mcuheader->arg1 < DEF_ADMIN_TOTAL_NUM){
		if(DevStatusNo(InitialStatus)){   //状态检测  
			mcuheader->result = ERR_DVES_INIT;
			mcuheader->length=FPGA_MCUHEAD_LEN;
			vPortFree(pin);
			return;
		}				
		ret = add_admin(pin,mcuheader->arg2, mcuheader->arg1);
	}
	else if((mcuheader->arg1 >= DEF_ADMIN_TOTAL_NUM) && (mcuheader->arg1 < DEF_OPERATOR_NUM_MAX)){
		if(DevStatusNo(ManagementStatus)){ //状态检测  
			mcuheader->result = ERR_DVES_OPER;
			mcuheader->length=FPGA_MCUHEAD_LEN;
			vPortFree(pin);
			return;
		}
		ret = add_operator(pin,mcuheader->arg2, mcuheader->arg1);
	}
	else
		ret = ERR_COMM_INPUT;
	vPortFree(pin);
  mcuheader->total = 1;
  mcuheader->count = 1;
  mcuheader->arg1 = eFlash.OPERNUM;
	mcuheader->arg2 = eFlash.ADMINNUM;
  mcuheader->result = (unsigned short)ret;
  mcuheader->length = FPGA_MCUHEAD_LEN;
}

/*************************SD_TASK_USERLOGIN**********************
*用户登录
********************************************************************/
TASK_FUNC(do_SD_TASK_USERLOGIN)
{
	uint16_t psw_len=0;
	uint16_t usrtype=0;
	psw_len = mcuheader->arg1;
	usrtype = mcuheader->arg2;
	if(DevStatusNo(ReadyStatus)){   //状态检测  
		mcuheader->result = ERR_DVES_USERLOGIN;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}	
	mcuheader->length = FPGA_MCUHEAD_LEN;
	mcuheader->result = UserLogin(usrtype,(char *)indata, psw_len);
	mcuheader->arg1=usr.index;//Get_DevState();		//工作状态
	mcuheader->arg2=usr.adm_login_num;
}

/*************************SD_TASK_USERLOGOUT**********************
*用户登出
********************************************************************/
TASK_FUNC(do_SD_TASK_USERLOGOUT)
{
	//设备退出登录
	if(DevStatusNo(WorkStatus) || DevStatusNo(ManagementStatus)){   //状态检测  
		mcuheader->result = ERR_DVES_USERLOGOUT;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}	
	mcuheader->result = UserLogout();
	Update_DevState(ReadyStatus);

	mcuheader->length=FPGA_MCUHEAD_LEN;
	mcuheader->arg2 =0;
	mcuheader->arg1 =Get_DevState();
}
//重置用户密码 删除此条  
TASK_FUNC(do_SD_TASK_RESETPWD){}
/*************************SD_TASK_DELUSER**********************
*删除用户
********************************************************************/
TASK_FUNC(do_SD_TASK_DELUSER)
{
	if(DevStatusNo(ManagementStatus)){   //状态检测  
		mcuheader->result = ERR_DVES_OPER;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}	
	if((mcuheader->arg1 >= DEF_ADMIN_TOTAL_NUM)&&(mcuheader->arg1 <DEF_OPERATOR_NUM_MAX ))
		mcuheader->result=DelUsr(mcuheader->arg1);
	else
		mcuheader->result=ERR_MANG_ERROR_USR;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		mcuheader->arg1 =0;
		mcuheader->arg2 =0;
}
/*************************SD_TASK_RESETOPERATORPWD**********************
*重置操作员口令
********************************************************************/
TASK_FUNC(do_SD_TASK_RESETOPERATORPWD)
{
	if(DevStatusNo(WorkStatus)){   //状态检测  
		mcuheader->result = ERR_DVES_WORKSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}	
	if(mcuheader->arg1 >16){
		mcuheader->result = ERR_MANG_PINLEN;
	}
	else 
		mcuheader->result = ResetOperatorPWD(mcuheader->arg1,mcuheader->arg2,(char*)indata);
	mcuheader->arg1=0;
	mcuheader->arg2=0;
}
//查询设备状态
/*************************SD_TASK_GETLOGINSTATUS**********************
*查询设备登录状态
********************************************************************/
TASK_FUNC(do_SD_TASK_GETLOGINSTATUS)
{
	if(DevStatusNo(WorkStatus)){   //状态检测  
		mcuheader->result = ERR_DVES_WORKSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}	
	mcuheader->length = FPGA_MCUHEAD_LEN;
	mcuheader->arg1 = Get_DevState();
	mcuheader->arg2 = 0;
	mcuheader->result = 0;
		//设置设备状态寄存器
	*(unsigned short *)FPGA_MCU_DRIVER_WRITE = (0x0001<<(mcuheader->arg1));
	
}
/*************************SD_TASK_CHGOCURPWD**********************
*修改当前用户密码
********************************************************************/
TASK_FUNC(do_SD_TASK_CHGOCURPWD)
{
	if(mcuheader->arg1 >16 || mcuheader->arg2 >16){
		mcuheader->result = ERR_MANG_PINLEN;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	mcuheader->result = 0;
	if(eFlash.DEV_STATE == ManagementStatus){	//状态检测
		mcuheader->result=ChangePWD(mcuheader->arg1,(char *)indata,mcuheader->arg2,(char *)(indata+mcuheader->arg1));
	}
	else if(eFlash.DEV_STATE == WorkStatus){	//状态检测
		mcuheader->result=ChangePWDOper(mcuheader->arg1,(char *)indata,mcuheader->arg2,(char *)(indata+mcuheader->arg1));
	}
	else{
		mcuheader->result=ERR_DVES_STATETODO;
	}
	//mcuheader->result=ChangePWD(mcuheader->arg1,(char *)indata,mcuheader->arg2,(char *)(indata+mcuheader->arg1));
	//ChangePWD(uint16_t old_pwd_len,char *pwd_old,uint16_t new_pwd_len,char *pwd_new);
	mcuheader->arg1=0;
	mcuheader->arg2=0;
	mcuheader->length=FPGA_MCUHEAD_LEN;
}

TASK_FUNC(do_SD_TASK_CONFIGFILE)
{
	mcuheader->arg1=0;
	mcuheader->arg2=0;
	mcuheader->result=0;
}

/*************************SD_TASK_BACKUPADMININFO**********************
*备份管理员信息
********************************************************************/	
TASK_FUNC(do_SD_TASK_BACKUPADMININFO)
{
	uint8_t AdmBackData[sizeof(FlashData)+16];
	uint8_t enc_data[sizeof(FlashData)+16];
	uint32_t len16n = 16*((sizeof(FlashData)+15)/16);

	if(mcuheader->arg1 == 1){
		memcpy(recover_iv,back_key,16);
	}else{
		mcuheader->length = FPGA_MCUHEAD_LEN;
		mcuheader->result = ERR_COMM_INPUT;
		return;
	}
	if(mcuheader->arg2 < len16n){
		mcuheader->length = FPGA_MCUHEAD_LEN;
		mcuheader->result = ERR_COMM_INPUT;
		return;
	}
	BackUpAdminInfo(AdmBackData);
	FPGA_SYM_Encrypt(FPGA_DATA_SM4,FPGA_CBC_MODE,back_key,recover_iv,AdmBackData,len16n,enc_data);
	memcpy(recover_iv,enc_data+len16n-16,16);
	memcpy(outdata,enc_data,len16n);
	mcuheader->arg1 = 1;
	mcuheader->arg2 = len16n;
	mcuheader->length = FPGA_MCUHEAD_LEN+len16n;
	mcuheader->result = 0;
}

/*************************SD_TASK_RECOVERYADMININFO**********************
*恢复管理员信息
********************************************************************/	
TASK_FUNC(do_SD_TASK_RECOVERYADMININFO)
{
	uint32_t len16n = mcuheader->result;
	uint8_t enc_data[sizeof(FlashData)+16] = {0};
	uint8_t AdmBackData[sizeof(FlashData)+16] = {0};
	
	if(mcuheader->arg1 == 1 && mcuheader->arg2 == 1){
		memcpy(recover_iv,recover_backkey,16);
	}else{
		mcuheader->length = FPGA_MCUHEAD_LEN;
		mcuheader->result = ERR_COMM_INPUT;
		return;
	}
	if(len16n%MAINKEY_LEN || len16n>sizeof(FlashData)+16){ //数据长度需要是16字节整数倍
		mcuheader->length = FPGA_MCUHEAD_LEN;
		mcuheader->result = ERR_MANG_RECOVER_LEN;
		return;
	}
	else{
		memcpy(enc_data,indata,len16n);
		FPGA_SYM_Decrypt(FPGA_DATA_SM4,FPGA_CBC_MODE,recover_backkey,recover_iv,enc_data,len16n,AdmBackData);
		memcpy(recover_iv,enc_data+len16n-16,16);
		mcuheader->result = RecoverAdminInfo(AdmBackData);
	}
}
/*************************SD_TASK_BACKUPADMININFO**********************
*备份操作员信息
********************************************************************/	
TASK_FUNC(do_SD_TASK_BACKUPOPERATOR)
{
	uint8_t OperBackData[sizeof(FlashData)+16];
	uint8_t enc_data[sizeof(FlashData)+16];
	uint32_t len16n = 16*((sizeof(FlashData)+15)/16);

	if(mcuheader->arg1 == 1){
		memcpy(recover_iv,back_key,16);
	}else{
		mcuheader->length = FPGA_MCUHEAD_LEN;
		mcuheader->result = ERR_COMM_INPUT;
		return;
	}
	if(mcuheader->arg2 < len16n){
		mcuheader->length = FPGA_MCUHEAD_LEN;
		mcuheader->result = ERR_COMM_INPUT;
		return;
	}
	BackUpOperaInfo(OperBackData);
	FPGA_SYM_Encrypt(FPGA_DATA_SM4,FPGA_CBC_MODE,back_key,recover_iv,OperBackData,len16n,enc_data);
	memcpy(recover_iv,enc_data+len16n-16,16);
	memcpy(outdata,enc_data,len16n);
	mcuheader->arg1 = 1;
	mcuheader->arg2 = len16n;
	mcuheader->length = FPGA_MCUHEAD_LEN+len16n;
	mcuheader->result = 0;
	
}
/*************************SD_TASK_RECOVERYADMININFO**********************
*恢复操作员信息
********************************************************************/
TASK_FUNC(do_SD_TASK_RECOVEROPERATOR)
{

	uint32_t len16n = mcuheader->result;
	uint8_t enc_data[sizeof(FlashData)+16] = {0};
	uint8_t OperBackData[sizeof(FlashData)+16] = {0};
	
	if(mcuheader->arg1 == 1 && mcuheader->arg2 == 1){
		memcpy(recover_iv,back_key,16);
	}else{
		mcuheader->length = FPGA_MCUHEAD_LEN;
		mcuheader->result = ERR_COMM_INPUT;
		return;
	}
	if(len16n%MAINKEY_LEN || len16n>sizeof(FlashData)+16){ //数据长度需要是16字节整数倍
		mcuheader->length = FPGA_MCUHEAD_LEN;
		mcuheader->result = ERR_MANG_RECOVER_LEN;
		return;
	}
	else{
		memcpy(enc_data,indata,len16n);
		FPGA_SYM_Decrypt(FPGA_DATA_SM4,FPGA_CBC_MODE,back_key,recover_iv,enc_data,len16n,OperBackData);
		memcpy(recover_iv,enc_data+len16n-16,16);
		mcuheader->result = RecoverOperaInfo(OperBackData);
		mcuheader->length = FPGA_MCUHEAD_LEN;
	}
}

/*************************SD_TASK_BACKUPKEY**********************
*备份用户密钥&KEK
********************************************************************/
TASK_FUNC(do_SD_TASK_BACKUPKEY){
	uint32_t Len16n = 0;
	uint16_t gpagcount = 0;        //总包数
	uint32_t Len = mcuheader->arg1;//当前包数
	//mcuheader->arg2;//用户提供的BUFF长度  enc_data
	uint16_t KeyType = mcuheader->result;
	uint8_t backupdata[4096] = {0};
	uint8_t enc_data[4096] = {0};
	if(Len == 1){
			if(KeyType == 0XFFF2){
				mcuheader->result=BackUpUserkey(NULL,&Len,&gpagcount);
			}
			else if(KeyType == 0XFFF3){
				mcuheader->result=BackUpKEK(NULL,&Len,&gpagcount);
			}
			else if(KeyType == 0XFFF4){
				mcuheader->result=BackUpAllKey(NULL,&Len,&gpagcount);
			}
			else{
				mcuheader->length = FPGA_MCUHEAD_LEN;
				mcuheader->result = SDR_INARGERR;
				return;
			}
			Len16n = 16*(Len+15)/16;
			if(Len16n > (mcuheader->arg2 * 16)){
				mcuheader->length = FPGA_MCUHEAD_LEN;
				mcuheader->result = SDR_NOBUFFER;
			}
			memcpy(recover_iv,back_key,16);
			recover_pag_count = gpagcount;
			Len = 1;
	}
	if(Len > recover_pag_count){
			mcuheader->arg1 = gpagcount;
			mcuheader->arg2 = 0;
			mcuheader->length = FPGA_MCUHEAD_LEN;
			mcuheader->result = SDR_INARGERR;
			return;
	}
	if(KeyType == 0XFFF2){
		mcuheader->result=BackUpUserkey(backupdata,&Len,&gpagcount);
	}
	else if(KeyType == 0XFFF3){
		mcuheader->result=BackUpKEK(backupdata,&Len,&gpagcount);
	}
	else if(KeyType == 0XFFF4){
		mcuheader->result=BackUpAllKey(backupdata,&Len,&gpagcount);
	}else{
			mcuheader->length = FPGA_MCUHEAD_LEN;
			mcuheader->result = SDR_INARGERR;
			return;
	}
	if(gpagcount == 0xFF99 || mcuheader->arg1 == recover_pag_count){	//尾包
		gpagcount = 0xFF99;
		memcpy(backupdata+Len,(uint8_t*)&gpagcount,2);
		Len+=16;
	}
	Len16n = Len;
	FPGA_SYM_Encrypt(FPGA_DATA_SM4,FPGA_CBC_MODE,back_key,recover_iv,backupdata,Len16n,enc_data);
	memcpy(recover_iv,enc_data+Len16n-16,16);
	memcpy(outdata,enc_data,Len16n);
	mcuheader->arg1 = recover_pag_count;
	mcuheader->arg2 = Len / 16;
	mcuheader->length = FPGA_MCUHEAD_LEN+Len16n;
	return;

}
/*************************SD_TASK_RECOVERKEY**********************
*恢复用户密钥&KEK
********************************************************************/
TASK_FUNC(do_SD_TASK_RECOVERKEY){
	uint32_t Len16n = mcuheader->length-FPGA_MCUHEAD_LEN;
	//uint16_t allcount = mcuheader->arg1;  // 总包数
	uint16_t pagcount = mcuheader->arg2;    // 当前包数

	uint16_t KeyType = mcuheader->result;
	uint8_t backupdata[4096] = {0};
	uint8_t enc_data[4096] = {0};
	memcpy(enc_data,indata,Len16n);
	if(pagcount == 1){
			recover_pag_count = mcuheader->arg1;
			if(recover_login_num >=DEF_ADMIN_ACCESS_NUM){
				memcpy(recover_iv,recover_backkey,16); //recover_backkey
			}else{
				memcpy(recover_iv,back_key,16);
				memcpy(recover_backkey,back_key,16);
			}
			FPGA_SYM_Decrypt(FPGA_DATA_SM4,FPGA_CBC_MODE,recover_backkey,recover_iv,enc_data,Len16n,backupdata);
			memcpy(recover_iv,enc_data+Len16n-16,16);
			if(KeyType == 0XFFF2){
				mcuheader->result=RecoverUserkey(backupdata,Len16n,pagcount);
			}
			else if(KeyType == 0XFFF3){
				mcuheader->result=RecoverKEK(backupdata,Len16n,pagcount);
			}
			else if(KeyType == 0XFFF4){
				mcuheader->result=RecoverAllKey(backupdata,Len16n,pagcount);
			}else{
				mcuheader->length = FPGA_MCUHEAD_LEN;
				mcuheader->result = SDR_INARGERR;
				return;
			}
			mcuheader->length = FPGA_MCUHEAD_LEN;
			//mcuheader->result = 0;
			return;
	}
	if(pagcount > recover_pag_count){
			mcuheader->arg1 = pagcount;
			mcuheader->arg2 = 0;
			mcuheader->length = FPGA_MCUHEAD_LEN;
			mcuheader->result = SDR_INARGERR;
			return;
	}
	FPGA_SYM_Decrypt(FPGA_DATA_SM4,FPGA_CBC_MODE,recover_backkey,recover_iv,enc_data,Len16n,backupdata);
	memcpy(recover_iv,enc_data+Len16n-16,16);
	if(KeyType == 0XFFF2){
		mcuheader->result=RecoverUserkey(backupdata,Len16n,pagcount);
	}
	else if(KeyType == 0XFFF3){
		mcuheader->result=RecoverKEK(backupdata,Len16n,pagcount);
	}
	else if(KeyType == 0XFFF4){
		mcuheader->result=RecoverAllKey(backupdata,Len16n,pagcount);
	}else{
			mcuheader->length = FPGA_MCUHEAD_LEN;
			mcuheader->result = SDR_INARGERR;
			return;
	}
	mcuheader->length = FPGA_MCUHEAD_LEN;
	return;

}	
	
/*************************SD_TASK_BACKUPADMINLOGIN**********************
*备份管理员登录
********************************************************************/
TASK_FUNC(do_SD_TASK_BACKUPADMINLOGIN)
{
	uint16_t pinlen=0;
	pinlen = mcuheader->arg1;
	uint8_t *pin = pvPortMalloc(16);  //pinlen
	memset(pin,0,16);
	memcpy(pin,indata,pinlen);
	mcuheader->result = BackUpAdminLogin(pinlen,pin);
	mcuheader->arg1 = eFlash.DEV_STATE;
	mcuheader->arg2 = recover_login_num;
	mcuheader->length = FPGA_MCUHEAD_LEN;
	vPortFree(pin);
}

TASK_FUNC(do_SD_TASK_BACKUPADMINQUIT)
{
	mcuheader->result = BackUpAdminQuit();
	mcuheader->arg1 = eFlash.DEV_STATE;
	mcuheader->length = FPGA_MCUHEAD_LEN;
}
//获取设备状态
TASK_FUNC(do_SD_TASK_GETDEVICESTATE)
{
	//MCUSelfCheck status;
	//Get_DEVICESTATUS(&status);//GETDEVICESTATE
	memcpy(outdata,&DevSelfCheck,sizeof(MCUSelfCheck));
	mcuheader->result = 0;
	mcuheader->length = FPGA_MCUHEAD_LEN + sizeof(MCUSelfCheck);
}

///////////////////////////////设备自检/////////////////////////////////
TASK_FUNC(do_SD_TASK_CHECKSELF)
{
	
 Run_Test_task();
}


//周期自检主动发起给PCIE
TASK_FUNC(do_SD_TASK_CYCLECHECKSELF)
{

}

/*************************SD_TASK_GENDEVKEY**********************
*生成设备密钥
********************************************************************/	
TASK_FUNC(do_SD_TASK_GENDEVKEY)
{
	uint8_t res =0 ; 
	ECC_G_STR sm2_para;
	uint8_t pin_len=mcuheader->arg1;		
	memcpy(pin0_temp,indata,pin_len);	//设备密钥标识码
	pin0_temp[16]=pin_len;
	if(DevStatusNo(FactoryStatus)){   //状态检测  
		mcuheader->result = ERR_DVES_FACTYSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}		
	mcuheader->total = 1;
  mcuheader->count = 1;
  mcuheader->arg1  = 0;		//设备密钥索引为0
  mcuheader->length = FPGA_MCUHEAD_LEN;
	
	SM2_param_init(&sm2_para);
	if(SM2_Gen_Keypair(&sm2_para,(uint8_t*)(&mgtkeypair.sk),(uint8_t*)(&mgtkeypair.pk.x),(uint8_t*)(&mgtkeypair.pk.y)))
		//生成密钥错误
		mcuheader->result = ERR_CIPN_GENSM2KEY; 
	else{
		memcpy(eFlash.Devkeypair,&mgtkeypair,sizeof(SM2KeyPair));
		//WriteFlashData();
		eFlash.DEV_STATE = InitialStatus;
		*(unsigned short *)FPGA_MCU_DRIVER_WRITE = 0x0001<<InitialStatus;
		mcuheader->result = 0;
	}
}
/*************************SD_TASK_EXPORTDEVPUBKEY**********************
*导出设备公钥
********************************************************************/
TASK_FUNC(do_SD_TASK_EXPORTDEVPUBKEY){
	SM2KeyPair *dev_ciph = (SM2KeyPair*)(eFlash.Devkeypair);
	memcpy(outdata, &dev_ciph->pk, sizeof(SM2PublicKey));
	mcuheader->length = FPGA_MCUHEAD_LEN+sizeof(SM2PublicKey);
}
/*************************SD_TASK_GENKEYUSERKEYPAIR**********************
*生成用户密钥对
********************************************************************/	
TASK_FUNC(do_SD_TASK_GENKEYUSERKEYPAIR)
{
	char  Ciph_Pin[16]={0};
	uint16_t ciph_index = mcuheader->arg1;
	uint16_t ciph_type	 = mcuheader->arg2;
	uint16_t ciph_PinLen	 = mcuheader->result;
	if(DevStatusNo(WorkStatus)){   //状态检测  
		mcuheader->result = ERR_DVES_MANGSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}		
	//memset(Ciph_Pin,0,ciph_PinLen);
	memcpy(Ciph_Pin,indata,ciph_PinLen);
	if((ciph_type == USER_KEYTYPE_SM2 && ciph_index > 0 &&ciph_index <= SM2_KEYPAIR_NUM) || \
		 ((ciph_type == USER_KEYTYPE_RSA1024 || ciph_type == USER_KEYTYPE_RSA2048) && ciph_index > SM2_KEYPAIR_NUM && ciph_index <= SM2_KEYPAIR_NUM + RSA_KEYPAIR_NUM)){
				mcuheader->result=GenUsrCiph(ciph_index,ciph_type,Ciph_Pin,ciph_PinLen);
	}
	else
		mcuheader->result = ERR_COMM_INPUT;			//命令参数错误
	mcuheader->length = FPGA_MCUHEAD_LEN;
	mcuheader->arg2 = 0;
	
}
/*************************SD_TASK_CHGKEYKEYPAIRPWD**********************
*修改私钥访问控制码
********************************************************************/
TASK_FUNC(do_SD_TASK_CHGKEYKEYPAIRPWD)
{
	char  Ciph_OldPin[16]={0};
	char  Ciph_NewPin[16]={0};
	uint16_t ciph_index = mcuheader->arg1;
	uint16_t Ciph_OldPinL = mcuheader->arg2;
	uint16_t Ciph_NewPinL = mcuheader->result;
	mcuheader->result = 0;
	if(DevStatusNo(WorkStatus)){   //状态检测  
		mcuheader->result = ERR_DVES_MANGSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
  if(Ciph_OldPinL>16||Ciph_NewPinL>16||Ciph_NewPinL<8||Ciph_OldPinL<8){
		mcuheader->result = ERR_COMM_INPUT;			//命令参数错误
		mcuheader->length = FPGA_MCUHEAD_LEN;
		return;
	}
	memset(Ciph_OldPin,0,Ciph_OldPinL);
	memcpy(Ciph_OldPin,indata,Ciph_OldPinL);
	
	if(check_cipher_access(ciph_index,Ciph_OldPinL,Ciph_OldPin)){
		mcuheader->result = ERR_MANG_PINCHECK;
		mcuheader->length = FPGA_MCUHEAD_LEN;
		return;
	}
	memset(Ciph_NewPin,0,Ciph_NewPinL);
	memcpy(Ciph_NewPin,indata+Ciph_OldPinL,Ciph_NewPinL);

	
	if(change_cipher_access(ciph_index,Ciph_NewPinL,Ciph_NewPin)){
		mcuheader->result = ERR_CIPN_WRITKEYFILE;
		mcuheader->length = FPGA_MCUHEAD_LEN;
		return;
	}
	mcuheader->arg1 = ciph_index;
	mcuheader->result = 0;
	mcuheader->length = FPGA_MCUHEAD_LEN;
}
/*************************SD_TASK_GENKEK**********************
*生成KEK
********************************************************************/
TASK_FUNC(do_SD_TASK_GENKEK)
{
	if(DevStatusNo(WorkStatus)){   //状态检测  
		mcuheader->result = ERR_DVES_MANGSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}			
	mcuheader->result = GenKEK(mcuheader->arg1,mcuheader->arg2);
	mcuheader->length = FPGA_MCUHEAD_LEN;
	mcuheader->arg2=0;
	mcuheader->total=1;
}
/*************************SD_TASK_DELKEK**********************
*删除KEK
********************************************************************/
TASK_FUNC(do_SD_TASK_DELKEK)
{
	if(DevStatusNo(WorkStatus)){   //状态检测  
		mcuheader->result = ERR_DVES_MANGSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}			
	mcuheader->result=DelKEK(mcuheader->arg1);
	mcuheader->arg1=0;
	mcuheader->arg2=0;
	mcuheader->total=1;
	mcuheader->length = FPGA_MCUHEAD_LEN;
}
/*************************do_SD_TASK_IMPORTKEYPAIR**********************
*导入密钥对
********************************************************************/
TASK_FUNC(do_SD_TASK_IMPORTKEYPAIR)
{
	uint16_t index_use = 0,index_in = 0;
	if(DevStatusNo(ManagementStatus)){   //状态检测  
		mcuheader->result = ERR_DVES_MANGSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	index_use = mcuheader->arg1;
	index_in  = mcuheader->arg2;
	uint8_t *ECC_data = pvPortMalloc(sizeof(EnvelopedECCKey)+16);
	memcpy(ECC_data, (uint8_t*)indata, (sizeof(EnvelopedECCKey)+16));
	mcuheader->result = importkeypair1(index_use,index_in, ECC_data);
	mcuheader->length = FPGA_MCUHEAD_LEN;
	vPortFree(ECC_data);
}
//销毁用户密钥对
/*************************SD_TASK_DESKEYPAIR**********************
*销毁用户密钥对
********************************************************************/
TASK_FUNC(do_SD_TASK_DESKEYPAIR)
{
	if(DevStatusNo(WorkStatus)){   //状态检测  
		mcuheader->result = ERR_DVES_MANGSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}			
	mcuheader->result = DelUsrCiph(mcuheader->arg1);
	mcuheader->length = FPGA_MCUHEAD_LEN;
	mcuheader->arg1=0;
	mcuheader->arg2=0;
}
	
//查询密钥对数量
/*************************SD_TASK_GETKEYPAIRNUM**********************
*查询密钥对数量
********************************************************************/
TASK_FUNC(do_SD_TASK_GETKEYPAIRNUM)
{
	if(DevStatusNo(WorkStatus)){   //状态检测  
		mcuheader->result = ERR_DVES_MANGSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}			
	mcuheader->arg1=0;
	mcuheader->arg2=0;
	mcuheader->total=1;
	mcuheader->result = Get_Cipher_Num(outdata);
	mcuheader->length = FPGA_MCUHEAD_LEN + 8;
}
/*************************SD_TASK_GETKEYPAIRSTAT**********************
*查询密钥对状态
********************************************************************/	
TASK_FUNC(do_SD_TASK_GETKEYPAIRSTAT)
{
	if(DevStatusNo(WorkStatus)){   //状态检测  
		mcuheader->result = ERR_DVES_MANGSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}			
	if(mcuheader->arg1 == CIPH_STAT ){
		mcuheader->arg1 = 289;
		mcuheader->result = Get_cipher_status(outdata);
	}
	else if(mcuheader->arg1 == KEK_STAT ){
		mcuheader->arg1 = 256;
		mcuheader->result = Get_KEK_status(outdata);
	}
	mcuheader->length = FPGA_MCUHEAD_LEN+mcuheader->arg1;
}
/*************************do_SD_TASK_EXPORTKEYPAIR**********************
*导出密钥对
********************************************************************/
TASK_FUNC(do_SD_TASK_EXPORTKEYPAIR)
{

}
TASK_FUNC(do_SD_TASK_GETUSERKEYCHK){}
TASK_FUNC(do_SD_TASK_GETKEKCHK){}
/*************************do_SD_TASK_IMPORTENCKEY**********************
*导入加密密钥
********************************************************************/
TASK_FUNC(do_SD_TASK_IMPORTENCKEY)
{
	uint16_t index = 0;
	if(DevStatusNo(ManagementStatus)){   //状态检测  
		mcuheader->result = ERR_DVES_MANGSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	index = mcuheader->arg1;
	uint8_t *ECC_data = pvPortMalloc(sizeof(EnvelopedECCKey)+16);
	memcpy(ECC_data, (uint8_t*)indata, (sizeof(EnvelopedECCKey)+16));
	mcuheader->result = importkeypair(index, ECC_data);
	mcuheader->length = FPGA_MCUHEAD_LEN;
	vPortFree(ECC_data);
}
TASK_FUNC(do_SD_TASK_IMPORTKEK){}
TASK_FUNC(do_SD_TASK_DEVKEKENC){}
TASK_FUNC(do_SD_TASK_DEVKEKDEC){}
TASK_FUNC(do_SD_TASK_DEVKEKSIGN){}
TASK_FUNC(do_SD_TASK_DEVKEKVERIFY){}
/*************************do_SD_TASK_DESTORYDEV**********************
*开盖功能
********************************************************************/
#define ENSHIELD  1
#define DISSHIELD 2
#define DESTORY   3
TASK_FUNC(do_SD_TASK_DESTORYDEV)
{
	uint8_t temp;
	//判断是否重复设置
	if((((eFlash.DATA_STATUS>>16) & 0xffff)== 0xA5A5) && (mcuheader->arg1 == ENSHIELD)){   //高4位表示是否启用开盖保护功能,!0xA5A5 关闭,0xA5A5 开启;低4位已经首次上电0x0000 -- 新出厂设备 0x0001 -- 已首次上电设备
		mcuheader->result = ERR_DVES_ENSHIELD;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	else if((((eFlash.DATA_STATUS>>16) & 0xffff)!= 0xA5A5) && (mcuheader->arg1 == DISSHIELD)){
		mcuheader->result = ERR_DVES_DISSHIELD;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	//设置打开或者关闭
	switch(mcuheader->arg1){
		case ENSHIELD:
			eFlash.DATA_STATUS |= (DETECT_FLAG<<16);
			break;
		case DISSHIELD:
			eFlash.DATA_STATUS &= 0xffff;
			break;
		case DESTORY:
			cleanmcu_toboot();
			break;
		default:
			mcuheader->result = ERR_COMM_INPUT;
			mcuheader->length=FPGA_MCUHEAD_LEN;
			return;
	}
	if(mcuheader->arg1>0 && mcuheader->arg1<DESTORY){
		temp = eFlash.DEV_STATE;
		eFlash.DEV_STATE = ReadyStatus;
		WriteFlashData();
		eFlash.DEV_STATE = temp;
	}
	mcuheader->result = 0;
	mcuheader->length=FPGA_MCUHEAD_LEN;
}
/*************************SD_TASK_CLEARUKEY**********************
*清空Ukey信息
********************************************************************/	
TASK_FUNC(do_SD_TASK_CLEARUKEY)
{
	if(DevStatusNo(WorkStatus)){   //状态检测  
		mcuheader->result = ERR_DVES_WORKSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}	
	if(mcuheader->arg1 >16){
		mcuheader->result = ERR_MANG_PINLEN;
	}
	else 
	mcuheader->result = CleanUkeyWithPin(mcuheader->arg1,(char*)indata);
	mcuheader->arg1=0;
	mcuheader->arg2=0;
}
TASK_FUNC(do_SD_MANU_UPDATEDEV){}
	
/*************************SD_MANU_CLEARMCU**********************
*擦除MCU	returntoboot
********************************************************************/	
TASK_FUNC(do_SD_MANU_CLEARMCU)
{
	
	mcuheader->result = cleanmcu_toboot();
	mcuheader->length = FPGA_MCUHEAD_LEN;
	mcuheader->arg1=0;
	mcuheader->arg2=0;

}
/*************************SD_MANU_SETDEVINFO**********************
*设置设备信息
********************************************************************/
TASK_FUNC(do_SD_MANU_SETDEVINFO)
{
	DEVICEINFO data_backup;
	DEVICEINFO data_buff;
	DEVICEINFO data_check;
	uint8_t info[4] = {0};
	memset(&data_buff, 0, sizeof(data_buff));
	memset(&data_check, 0, sizeof(data_check));
	memset(&data_backup, 0, sizeof(data_backup));
	//设置参数判断 1：设置；2：清空
	if(DEVICE_RESET == mcuheader->arg1){
		memset(data_buff.DeviceName, 0, 16);
		memset(data_buff.DeviceSerial, 0, 16);
		info[0] = 0;
	}
	else if(DEVICE_SET == mcuheader->arg1){
		memcpy((uint8_t*)data_buff.DeviceName, indata,16);
		memcpy((uint8_t*)data_buff.DeviceSerial, indata+16,16);
		info[0] = INFO_FLAG;
	}
	else{
		mcuheader->result = ERR_COMM_INPUT;
		mcuheader->length = FPGA_MCUHEAD_LEN;
		return;
	}
	//备份
	//print(PRINT_CIPH,"start to write info!\r\n");
	at24cxx_read_bytes(DEVICE_INFO_ADDR, info, 4);
	if(INFO_FLAG == info[0]) at24cxx_read_bytes(DEVICE_DATA_ADDR, (uint8_t*)data_backup.DeviceName, 32);
	//写入
	at24cxx_write_bytes(DEVICE_DATA_ADDR, (uint8_t*)data_buff.DeviceName, 32);
	//校验
	at24cxx_read_bytes(DEVICE_DATA_ADDR, (uint8_t*)data_check.DeviceName, 32);
	if(memcmp(data_check.DeviceName, data_buff.DeviceName, 16) || memcmp(data_check.DeviceSerial, data_buff.DeviceSerial, 16)){
		//错误恢复
		if(INFO_FLAG == info[0]){
			info[0] = INFO_FLAG;
			at24cxx_write_bytes(DEVICE_INFO_ADDR, info, 4);
			at24cxx_write_bytes(DEVICE_DATA_ADDR, (uint8_t*)data_backup.DeviceName, 32);
		}
		mcuheader->result = SDR_FILEWERR;
		mcuheader->length = FPGA_MCUHEAD_LEN;
		return;
	}
	info[0] = INFO_FLAG;
	at24cxx_write_bytes(DEVICE_INFO_ADDR, info, 4);
	print(PRINT_INTERFACE,"device info %s\r\n",data_buff.DeviceName);
	print(PRINT_INTERFACE,"device info %s\r\n",data_buff.DeviceSerial);
	mcuheader->result = 0;
	mcuheader->length = FPGA_MCUHEAD_LEN;
	mcuheader->arg1=0;
	mcuheader->arg2=0;
	
}
/*************************SD_MANU_CLEARUKEY**********************
*直接清除Ukey，不进行身份验证。
********************************************************************/
TASK_FUNC(do_SD_MANU_CLEARUKEY)
{
	if(DevStatusNo(WorkStatus)){   //状态检测
	mcuheader->result = ERR_DVES_WORKSTATE;
	mcuheader->length=FPGA_MCUHEAD_LEN;
	return;
	}
	mcuheader->result = CleanUkey();
}
/*************************SD_TASK_HASHSHA1**********************
*SHA1
********************************************************************/
TASK_FUNC(do_SD_TASK_HASHSHA1)
{
	uint16_t ret = 0;
	uint32_t out_len = 0;
	uint16_t in_len 	 = mcuheader->arg1;
	//uint16_t key_index = mcuheader->arg2;
	uint16_t iven = mcuheader->arg2;
	uint8_t iv[SHA1_HASH_LEN] = {0};
	uint8_t *ivp = NULL;
	uint16_t ivlen = 0;
	//uint8_t key[32] = {0};
	uint8_t *in_data = NULL;
	uint8_t out_data[SHA1_HASH_LEN] = {0};
	mcuheader->result = 0;
	if(DevStatusNo(WorkStatus)){ //状态检测
		mcuheader->result = ERR_DVES_WORKSTATE;
		mcuheader->length = FPGA_MCUHEAD_LEN;
		return;
	}	
	if(iven){
		memcpy(iv, indata, SHA1_HASH_LEN);
		ivp = iv;
		ivlen = SHA1_HASH_LEN;
		ret  += SHA1_HASH_LEN;
	}
	if(in_len <= 0)
	{
		mcuheader->result = ERR_COMM_INPUT;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	in_data = pvPortMalloc(in_len);
	if (in_data == NULL){
		mcuheader->result = ERR_COMM_MALLOC;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	memcpy(in_data, indata+ret, in_len);
	
	mcuheader->result = sha1_with_iv(ivp, ivlen, in_data, in_len, out_data, &out_len);
	memcpy(outdata, out_data, SHA1_HASH_LEN);
	mcuheader->arg1 = SHA1_HASH_LEN;
	mcuheader->length = FPGA_MCUHEAD_LEN + mcuheader->arg1;	
	vPortFree(in_data);	
	
}
/*************************SD_TASK_HASHSHA256**********************
*SHA256
********************************************************************/	
TASK_FUNC(do_SD_TASK_HASHSHA256)
{
	uint16_t ret = 0;
	uint32_t out_len = 0;
	uint16_t in_len 	 = mcuheader->arg1;
	//uint16_t key_index = mcuheader->arg2;
	uint16_t iven = mcuheader->arg2;
	uint8_t iv[SHA256_HASH_LEN] = {0};
	uint8_t *ivp = NULL;
	uint16_t ivlen = 0;
	//uint8_t key[32] = {0};
	uint8_t *in_data = NULL;
	uint8_t out_data[SHA256_HASH_LEN] = {0};
	mcuheader->result = 0;
	if(DevStatusNo(WorkStatus)){ //状态检测
		mcuheader->result = ERR_DVES_WORKSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}	
	if(iven){
		memcpy(iv, indata, SHA256_HASH_LEN);
		ivp = iv;
		ivlen = SHA256_HASH_LEN;
		ret  += SHA256_HASH_LEN;
	}
	if(in_len <= 0)
	{
		mcuheader->result = ERR_COMM_INPUT;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	in_data = pvPortMalloc(in_len);
	if (in_data == NULL){
		mcuheader->result = ERR_COMM_MALLOC;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	memcpy(in_data, indata+ret, in_len);
	
	mcuheader->result = sha256_with_iv(ivp, ivlen, in_data, in_len, out_data, &out_len);
	memcpy(outdata, out_data, SHA256_HASH_LEN);
	mcuheader->arg1 = SHA256_HASH_LEN;
	mcuheader->length = FPGA_MCUHEAD_LEN + mcuheader->arg1;	
	vPortFree(in_data);
}
/*************************SD_TASK_HASHSHA384**********************
*SHA384
********************************************************************/	
TASK_FUNC(do_SD_TASK_SHA384)								  //SHA384
{
	uint16_t ret = 0;
	uint32_t out_len = 0;
	uint16_t in_len 	 = mcuheader->arg1;
	uint16_t iven = mcuheader->arg2;
	uint8_t iv[SHA384_HASH_LEN] = {0};
	uint8_t *ivp = NULL;
	uint16_t ivlen = 0;
	uint8_t *in_data = NULL;
	uint8_t out_data[SHA384_HASH_LEN] = {0};
	mcuheader->result = 0;
	if(DevStatusNo(WorkStatus)){ //状态检测
		mcuheader->result = ERR_DVES_WORKSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	if(iven){
		memcpy(iv, indata, SHA384_HASH_LEN);
		ivp = iv;
		ivlen = SHA384_HASH_LEN;
		ret  += SHA384_HASH_LEN;
	}
	if(in_len <= 0)
	{
		mcuheader->result = ERR_COMM_INPUT;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	in_data = pvPortMalloc(in_len);
	if (in_data == NULL){
		mcuheader->result = ERR_COMM_MALLOC;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	memcpy(in_data, indata+ret, in_len);
	
	mcuheader->result = sha384_with_iv(ivp, ivlen, in_data, in_len, out_data, &out_len);
	memcpy(outdata, out_data, SHA384_HASH_LEN);
	mcuheader->arg1 = SHA384_HASH_LEN;
	mcuheader->length = FPGA_MCUHEAD_LEN + mcuheader->arg1;	
	vPortFree(in_data);
}
/*************************SD_TASK_HASHSHA512**********************
*SHA512
********************************************************************/	
TASK_FUNC(do_SD_TASK_SHA512)							    //SHA512
{
	uint16_t ret = 0;
	uint32_t out_len = 0;
	uint16_t in_len 	 = mcuheader->arg1;
	//uint16_t key_index = mcuheader->arg2;
	uint16_t iven = mcuheader->arg2;
	uint8_t iv[SHA512_HASH_LEN] = {0};
	uint8_t *ivp = NULL;
	uint16_t ivlen = 0;
	//uint8_t key[32] = {0};
	uint8_t *in_data = NULL;
	uint8_t out_data[SHA512_HASH_LEN] = {0};
	mcuheader->result = 0;
	if(DevStatusNo(WorkStatus)){ //状态检测
		mcuheader->result = ERR_DVES_WORKSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}	
	if(iven){
		memcpy(iv, indata, SHA512_HASH_LEN);
		ivp = iv;
		ivlen = SHA512_HASH_LEN;
		ret  += SHA512_HASH_LEN;
	}
	if(in_len <= 0)
	{
		mcuheader->result = ERR_COMM_INPUT;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	in_data = pvPortMalloc(in_len);
	if (in_data == NULL){
		mcuheader->result = ERR_COMM_MALLOC;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	memcpy(in_data, indata+ret, in_len);
	
	mcuheader->result = sha512_with_iv(ivp, ivlen, in_data, in_len, out_data, &out_len);
	memcpy(outdata, out_data, SHA512_HASH_LEN);
	mcuheader->arg1 = SHA512_HASH_LEN;
	mcuheader->length = FPGA_MCUHEAD_LEN + mcuheader->arg1;	
	vPortFree(in_data);
}

/*************************SD_TASK_EXCHDIGENVELOP_RSA**********************
*基于RSA的数字信封
********************************************************************/	
TASK_FUNC(do_SD_TASK_EXCHDIGENVELOP_RSA)
{
	uint16_t ret = 0;
	uint32_t out_len = 0;
	uint16_t RSA_index = mcuheader->arg1;
	uint16_t in_len = mcuheader->arg2;
	uint8_t out_data[256]={0};
	uint8_t in_data[256]={0};
	uint8_t RSA_key[1408]={0};
	uint16_t RSA_bits = in_len*8;
	mcuheader->result = 0;
	if(DevStatusNo(WorkStatus)){ //状态检测
		mcuheader->result = ERR_DVES_WORKSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}	
	if(RSA_bits != 1024 && RSA_bits != 2048){
		mcuheader->result = ERR_CIPN_RSAINLEN;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	memcpy(RSA_key,indata,in_len*2);
	memcpy(in_data, indata+in_len*2, in_len);
	ret = MUC_RSA_Prikey_Operation_internal(RSA_index, in_data, in_len, out_data, &out_len);
	if(ret){
		mcuheader->result = ret;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	memcpy(in_data,out_data,in_len);
	ret = MUC_RSA_Pubkey_Operation_external(RSA_key, in_data, in_len, out_data, &out_len);
	if(ret){
		mcuheader->result = ret;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	memcpy(outdata, out_data, in_len);
	mcuheader->arg1 = in_len;
	mcuheader->length = FPGA_MCUHEAD_LEN + mcuheader->arg1;
	
}
/*************************SD_TASK_EXCHDIGENVELOP_ECC**********************
*基于ECC的数字信封
********************************************************************/
TASK_FUNC(do_SD_TASK_EXCHDIGENVELOP_ECC)
{
	uint16_t ret = 0;
	uint32_t out_len = 0;
	uint16_t SM2_index = mcuheader->arg1;
	uint16_t in_len = mcuheader->arg2;
	uint8_t out_data[256]={0};
	uint8_t in_data[256]={0};
	uint8_t SM2_key[64]={0};
	//uint16_t RSA_bits = in_len*8;
	mcuheader->result = 0;
	if(DevStatusNo(WorkStatus)){  //状态检测
		mcuheader->result = ERR_DVES_WORKSTATE;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	if(in_len < 96){
		mcuheader->result = ERR_COMM_INPUTLEN;
		mcuheader->length = FPGA_MCUHEAD_LEN;
		return;
	}
	memcpy(SM2_key,indata,64);
	memcpy(in_data, indata+64, in_len);
	ret = fpga_sm2_decrypt_internal(SM2_index, in_data, in_len, out_data, &out_len);
	if(ret){
		mcuheader->result = ret;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	in_len = out_len;
	memcpy(in_data,out_data,in_len);
	ret = fpga_sm2_encrypt_external((SM2PublicKey *)SM2_key,in_data, in_len, out_data, &out_len);
	if(ret){
		mcuheader->result = ret;
		mcuheader->length=FPGA_MCUHEAD_LEN;
		return;
	}
	memcpy(outdata, out_data, out_len);
	mcuheader->arg1 = out_len;
	mcuheader->length = FPGA_MCUHEAD_LEN + mcuheader->arg1;
}
/*************************SD_TASK_GOTOFACTORY**********************
*恢复出厂态
********************************************************************/
TASK_FUNC(do_SD_TASK_GOTOFACTORY)
{
	mcuheader->result = go_to_factory();
	mcuheader->length = FPGA_MCUHEAD_LEN;
	mcuheader->arg1=0;
	mcuheader->arg2=0;
}
/*************************do_SD_TASK_GOTOFACTORY_NOADMIN**********************
*恢复出厂态无管理员
********************************************************************/
TASK_FUNC(do_SD_TASK_GOTOFACTORY_NOADMIN)
{
	mcuheader->result = go_to_factory();
	mcuheader->length = FPGA_MCUHEAD_LEN;
	mcuheader->arg1=0;
	mcuheader->arg2=0;
}


//MCU主动发送给驱动的函数
int32_t mcutodriver_LOGINSTATUS(void)
{
	FPGAHeader fpga_header;
	uint8_t *data_ptr = NULL;
	// mcu header 数据
	MCUHeader mcuheader;
	memset(&mcuheader, 0, sizeof(MCUHeader));
	memset(&fpga_header, 0, sizeof(FPGAHeader));
	fpga_header.mark = FPGA_HEAD_MARK;
	fpga_header.src = FPGA_DATA_DRIVER;//FPGA_DATA_ARM; //驱动要求改成0x80

	fpga_header.dst = FPGA_DATA_HOST_DMA0;
	fpga_header.channel = 0;
	fpga_header.pkglen = FPGA_DATAHEAD_LEN + FPGA_MCUHEAD_LEN;
	fpga_header.retpkglen = 0;
	
	mcuheader.cmd = SD_TASK_GETLOGINSTATUS;
	mcuheader.check  = 0xa0f5;
	mcuheader.length = FPGA_MCUHEAD_LEN;
	mcuheader.arg1   = Get_DevState();
	mcuheader.result = 0;
	
	//设置设备状态寄存器
	*(unsigned short *)FPGA_MCU_DRIVER_WRITE = (0x0001<<(mcuheader.arg1));
	
	if(fpga_write_start()==REG_REST) return ERR_COMM_OUTTIME;
	data_ptr = set_fpga_header((uint8_t *)FPGA_DATA_WRITE_ADDR, &fpga_header);
	data_ptr = set_mcu_header(data_ptr, &mcuheader);
	fpga_write_finish(fpga_header.pkglen);
	return 0;
}

