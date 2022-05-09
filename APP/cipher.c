/***********************************************************************
 * Copyright (c)  2020, beijing shudun Co.,Ltd .
 * All rights reserved.
 * Filename    : cipher.c
 * Description : user cipher function c file
 *							 	1.read/write cipher pin from fatfs(spiflash)
 *							 	2.read/write cipher from fatfs
 * Author(s)   : jaime
 * version     : V1.0
 * Modify date : 2020-10-26
 ***********************************************************************/


#include <stdint.h>
#include <string.h>
#include "fpga.h"
#include "ff.h"
#include "internal_alg.h"
#include "FreeRTOS.h"
#include "fpga_sm2.h"
#include "fpga_sm4.h"
#include "sl811_usb.h"
#include <math.h>
#include "fatfs_file.h"
#include "type_code.h"
#include "cipher.h"
#include "mcu_algorithm.h"
#include "interface.h"
#include "test.h"

//#define SESSIONKEY					0x60000000
uint8_t SESSIONKEY[SKEYNUM * (SKEYSIZE + 2)]  __attribute__((at(0x60000000)));   //

//uint8_t USERSAKEYPAIR[32*(1408+2)]  __attribute__((at(0x60046000)));   //
#define PRINT_CIPH 2

extern unsigned char main_key[16];
extern char kekdir[7];
extern char cipherdir[10];//="1:/cipher";//����û���Կ��������֤���ļ���
//#define SIGN		0xF000  �ŵ�ͷ�ļ�
//#define R_2048	0x0800 

#define LEAVE_OPEN(res){\
	if(res == FR_NO_FILE || res == FR_NO_PATH) return SDR_KEYNOTEXIST; \
	else if(res !=FR_OK) return ERR_CIPN_OPENKEYFILE;\
}

extern FlashData eFlash;
int sram_kek_delkey(uint16_t kek_index);
//�������������У���� SM3Hmac
int GenUserKeyCheck(uint8_t* data_buff,uint32_t data_len,uint32_t*OutLen){
	uint32_t padding_size =0;
	uint32_t tmp =0;
	unsigned char mac_data[32] = {0};
	unsigned char *data_with_pading = pvPortMalloc(data_len+64);
	memcpy(data_with_pading,data_buff,data_len);
	fill_hash_padding(HASH_BLOCK_LEN,64+data_len,data_with_pading+data_len, &padding_size);
	*OutLen = data_len+32;
	data_len = data_len+padding_size;
	
	if(hmac_one_step(HASH_ALG_SM3,eFlash.MAINKEY_MCU,16,data_with_pading,data_len,data_buff+*OutLen-32,&tmp)){
		vPortFree(data_with_pading);
		return -1;
	}
	vPortFree(data_with_pading);
	return 0;
}
//��������������У��
int GetUserKeyCheck(uint8_t* data_buff,uint32_t data_len,uint32_t*OutLen){
	unsigned char mac_data0[32] = {0};
	unsigned char mac_data1[32] = {0};
	uint32_t padding_size =0;
	unsigned char *data_with_pading = pvPortMalloc(data_len+64);
	memcpy(mac_data0,data_buff+data_len-32,32);
	memcpy(data_with_pading,data_buff,data_len-32);
	fill_hash_padding(HASH_BLOCK_LEN,64+data_len-32,data_with_pading+data_len-32, &padding_size);
	data_len = padding_size + data_len-32;
	
	if(hmac_one_step(HASH_ALG_SM3,eFlash.MAINKEY_MCU,16,data_with_pading,data_len,mac_data1,OutLen)){
		vPortFree(data_with_pading);
		return -1;
	}
	if(memcmp(mac_data1,mac_data0,32)){
		vPortFree(data_with_pading);
		return -2;
	}
	vPortFree(data_with_pading);
	return 0;
}


uint8_t RSA_CIPH_BUFF[1408];
//check_cipher_access
//�������ܣ�			�Ա���֤��Կ ( ��ȡ��Կ����Ȩ�� ) 
//���룺index			��Կ����
//			pin_len		��֤�볤��
//			*pin			��֤��ָ��
//����� 	0 			��֤�ɹ�
//				1				��֤ʧ��
int check_cipher_access(uint16_t index,uint8_t pin_len,char * pin)
{
	FRESULT res;
	FIL  file_c;
	uint8_t btr=32;				//pin max length is 16
	uint32_t br=0;
	uint8_t access_len=0;
	uint8_t pin_buff_enc[32]={0};
	uint8_t pin_buff[32]={0};
	char cipher_pin_name[17]= "1:cipher/pin";//12+3+1
	char index_str[4]={0};

	sprintf(index_str,"%d",index);
	strcat(cipher_pin_name,index_str);
	res = f_open(&file_c,cipher_pin_name,FA_READ);
	LEAVE_OPEN(res)
	res = f_read(&file_c,pin_buff_enc,btr,&br);
	f_close(&file_c);
	if(res != FR_OK)
		return ERR_CIPN_READKEYFILE;
//	print(PRINT_CIPH," read file enc is :\r\r\n");
//	printf_byte(pin_buff_enc,32);
	//���ܼ��ܵ�pin
	if(Sym_Crypt_WithKey(pin_buff_enc, 32, main_key, 16, 0, 0, \
					   SYM_ALG_SM4, SYM_DECRYPTION, SYM_ECB_MODE, pin_buff))
		return ERR_CIPN_DECKEYFILE;
//	print(PRINT_CIPH,"dec pin is :\r\n");
//	printf_byte(pin_buff,32);
//	print(PRINT_CIPH,"input pin is :\r\n");
//	printf_byte(pin,32);
	
	if(pin_buff[16] != pin_len)
		return ERR_MANG_PINCHECK;		//pin�������볤�ȴ���
	if(memcmp(pin_buff, pin, pin_len))
		return ERR_MANG_PINCHECK;	//pin����
	else
		return 0;
}

//�������ܣ��޸���Կ��֤��Կ�ļ�
//���룺index			��Կ����
//			pin_len		��֤�볤��
//			*pin			��֤��ָ��
//����� 0				д��ɹ�
//			 1	
int change_cipher_access(uint16_t index,uint8_t pin_len,char* pin)
{
	FRESULT res;
	FIL  file_c;
	uint32_t btr=32;				//pin max length is 16
	uint32_t br=0;	
	uint8_t pin_buff_enc[32+32]={0};
	uint8_t pin_buff[32]={0};
	char cipher_pin_name[17]= "1:cipher/pin";//12+3+1
	char index_str[4]={0};

	sprintf(index_str,"%d",index);
	strcat(cipher_pin_name,index_str);
	res = f_open(&file_c,cipher_pin_name,FA_CREATE_ALWAYS | FA_WRITE);
	LEAVE_OPEN(res)
	memcpy(pin_buff,pin,pin_len);
	pin_buff[16]=pin_len;
//	print(PRINT_CIPH,"pin is :\r\n");
//	printf_byte(pin_buff,32);
	//����pin
	if(Sym_Crypt_WithKey(pin_buff,32,main_key,16,0, 0, \
					 SYM_ALG_SM4, SYM_ENCRYPTION , SYM_ECB_MODE, pin_buff_enc)){
		f_close(&file_c);
		return ERR_CIPN_DECKEYFILE;
	 }
//	print(PRINT_CIPH,"pinenc is :\r\n");
//	printf_byte(pin_buff_enc,32);
	 
	//�����ԿУ����,��Կ������У�顣
	if(GenUserKeyCheck(pin_buff_enc,32,&btr)){
		return ERR_MANG_CHECKCODE;
	}
	 
	//����pinд���ļ���
	res = f_write(&file_c,pin_buff_enc,btr,&br);
  f_close(&file_c);
	if(res !=FR_OK){
		return ERR_CIPN_DECKEYFILE;
	}
	return res;
}

//read_cipher_access
//�������ܣ�			�Ա���֤��Կ ( ��ȡ��Կ����Ȩ�� ) 
//���룺index			��Կ����
//			pin_len		��֤�볤��
//			*pin			��֤��ָ��
//����� 	0 			��֤�ɹ�
//				1				��֤ʧ��
int read_cipher_access(uint16_t index,uint8_t *pin_len,char * pin)
{
	FRESULT res;
	FIL  file_c;
	uint8_t btr=32;				//pin max length is 16
	uint32_t br=0;
	uint8_t access_len=0;
	uint8_t pin_buff_enc[32]={0};
	uint8_t pin_buff[32]={0};
	char cipher_pin_name[17]= "1:cipher/pin";//12+3+1
	char index_str[4]={0};

	sprintf(index_str,"%d",index);
	strcat(cipher_pin_name,index_str);
	res = f_open(&file_c,cipher_pin_name,FA_READ);
	LEAVE_OPEN(res)
	res = f_read(&file_c,pin_buff_enc,btr,&br);
	f_close(&file_c);
	if(res != FR_OK)
		return ERR_CIPN_READKEYFILE;
//	print(PRINT_CIPH," read file enc is :\r\n");
//	printf_byte(pin_buff_enc,32);
	//���ܼ��ܵ�pin
	if(Sym_Crypt_WithKey(pin_buff_enc, 32, main_key, 16, 0, 0, \
					   SYM_ALG_SM4, SYM_DECRYPTION, SYM_ECB_MODE, pin_buff))
		return ERR_CIPN_DECKEYFILE;

	*pin_len = pin_buff[16];
	memcpy(pin, pin_buff, *pin_len);
	return 0;
}

//
//�������ܣ�������Կ��֤��Կ�ļ�
//���룺index			��Կ����
//			pin_len		��֤�볤��
//			*pin			��֤��ָ��
//			force			1���滻ԭ�ļ���0�����滻ԭ�ļ�
//����� 0				д��ɹ�
//			 1	
int write_cipher_access(uint16_t index,uint8_t pin_len,char* pin,uint8_t force)
{
	FRESULT res;
	FIL  file_c;
	uint32_t btr=32;				//pin max length is 16
	uint32_t br=0;	
	uint8_t pin_buff_enc[32+32]={0};
	uint8_t pin_buff[32]={0};
	char cipher_pin_name[17]= "1:cipher/pin";//12+3+1
	char index_str[4]={0};

	sprintf(index_str,"%d",index);
	strcat(cipher_pin_name,index_str);
	if(!force)
		res = f_open(&file_c,cipher_pin_name,FA_CREATE_NEW|FA_WRITE);
	else
		res = f_open(&file_c,cipher_pin_name,FA_CREATE_ALWAYS|FA_WRITE);
	LEAVE_OPEN(res)
	memcpy(pin_buff,pin,pin_len);
	pin_buff[16]=pin_len;
//	print(PRINT_CIPH,"pin is :\r\n");
//	printf_byte(pin_buff,32);
	//����pin
	if(Sym_Crypt_WithKey(pin_buff,32,main_key,16,0, 0, \
					 SYM_ALG_SM4, SYM_ENCRYPTION , SYM_ECB_MODE, pin_buff_enc)){
		f_close(&file_c);
		f_unlink (cipher_pin_name);
		return ERR_CIPN_DECKEYFILE;
	 }
	print(PRINT_CIPH,"pinenc:\r\n");
	printf_buff_byte(pin_buff_enc,32);
	 
	//�����ԿУ����,��Կ������У�顣
	if(GenUserKeyCheck(pin_buff_enc,32,&btr)){
		f_close(&file_c);
		f_unlink (cipher_pin_name);		
		return ERR_MANG_CHECKCODE;
	}

	//����pinд���ļ���
	res = f_write(&file_c,pin_buff_enc,btr,&br);
  f_close(&file_c);
	if(res !=FR_OK){
		return ERR_CIPN_DECKEYFILE;
	}
	return res;
}

//�������ܣ��������ɵ��û���Կ
//���룺index			��Կ����
//			data_len	��Կ����
//			*data			��Կָ��
//����� 0				д��ɹ�
//			 1				д��ʧ��
int write_cipher(uint16_t index, uint16_t data_len, uint8_t * data,uint8_t force)
{
	FRESULT res;
	FIL  file_c;
	uint32_t btr=data_len;				//pin max length is 16
	uint32_t br=0;
	char cipher_name[14]= "1:cipher/";//9+3+1	
	char index_str[6]={0};
	
	sprintf(index_str,"%d",index);
	strcat(cipher_name,index_str);
	if(!force)
		res = f_open(&file_c,cipher_name,FA_CREATE_NEW|FA_WRITE);
	else
		res = f_open(&file_c,cipher_name,FA_CREATE_ALWAYS|FA_WRITE);
	LEAVE_OPEN(res)
	uint8_t *data_buff=pvPortMalloc(data_len+16+32);
	if(data_buff == NULL)//�ڴ�����ʧ��
		return ERR_COMM_MALLOC;	
	//������Կ
	if(Sym_Crypt_WithKey(data,data_len,main_key,16,0, 0, \
					 SYM_ALG_SM4, SYM_ENCRYPTION, SYM_ECB_MODE, data_buff)){
		vPortFree(data_buff);
		f_close(&file_c);
		f_unlink (cipher_name);
		return ERR_CIPN_ENCKEYFILE;
	}
	//�����ԿУ����,��Կ������У�顣
	if(GenUserKeyCheck(data_buff,data_len,&btr)){
		vPortFree(data_buff);
		f_close(&file_c);
		f_unlink (cipher_name);
		return ERR_MANG_CHECKCODE;
	}
	//������Կд���ļ���
	res = f_write(&file_c, data_buff, btr, &br);
	vPortFree(data_buff);
	f_close(&file_c);	
	return 0;
}

//read_cipher
//�������ܣ�			��ȡ�û���Կ
//���룺index			��Կ����
//		data_len		�����ȡ����Կ����
//�����*data			��Կָ��
//		*Byte_read		ʵ�ʶ��������ݳ���
//����ֵ��
//		0 				��ȡ�ɹ�
//		1				  ��ȡʧ��
int32_t read_cipher(uint16_t index, uint32_t data_len, uint32_t *byte_read, uint8_t *data)
{
	FRESULT res;
	FIL  file_c;
	uint32_t btr=256;				//pin max length is 16
	uint32_t br=0;
	uint8_t data_buff[256]={0};
	*byte_read=0;
	uint8_t *datatmp= NULL;//pvPortMalloc(data_len+16+32);
	char cipher_name[14] = "1:cipher/";//9+3+1
	char index_str[6] = {0};

	sprintf(index_str,"%d",index);
	strcat(cipher_name, index_str);
	res = f_open(&file_c, cipher_name, FA_READ);
	LEAVE_OPEN(res)
	
	uint8_t *datamalloc = pvPortMalloc(data_len+16+32);
	datatmp = datamalloc;
	for(;;){
		res = f_read(&file_c, data_buff, btr, &br);
		if(res != FR_OK){
			f_close(&file_c);
			vPortFree(datamalloc);
			return ERR_CIPN_READKEYFILE;
		}
		if(br == 0)		//�ļ���ȡ����
			break;
		*byte_read += br;
		if(Sym_Crypt_WithKey(data_buff,br,main_key,16,0, 0, \
					   SYM_ALG_SM4, SYM_DECRYPTION , SYM_ECB_MODE, datatmp))
		{
			f_close(&file_c);
			vPortFree(datamalloc);
			return ERR_CIPN_DECKEYFILE;
		}
		datatmp += btr;
		if(*byte_read >= data_len){
			*byte_read = data_len;
			memcpy(data,datamalloc,data_len);
			break;
		}
	}
	vPortFree(datamalloc);
	f_close(&file_c);
	return 0;
}


//�������ܣ��������ɵ�KEK
//���룺index			��Կ����
//			data_len	��Կ����
//			*data			��Կָ��
//����� 0				д��ɹ�
//			 1				д��ʧ��
//ע�⣺ȷ����SM4���ܲ�λ���⣬������ܺ�����û�в�λ����Ҫ���¼��벹λ��Ϣ
int32_t write_kek(uint16_t index,uint16_t data_len,uint8_t * data)
{
	FRESULT res;
	FIL  file_c;
	uint32_t btr=data_len;				//pin max length is 16
	uint32_t br=0;
	char kek_name[10]= "1:kek/";//6+3+1
	char index_str[4]={0};
	sprintf(index_str,"%d",index);
	strcat(kek_name,index_str);
	res = f_open(&file_c,kek_name,FA_CREATE_NEW|FA_WRITE);
	LEAVE_OPEN(res)
	uint8_t *data_buff=pvPortMalloc(data_len+32);			//SM4����16�ֽڶ���
	if(data_buff == NULL)//�ڴ�����ʧ��
		return ERR_COMM_MALLOC;
	//����pin
	if(Sym_Crypt_WithKey(data,data_len,main_key,16,0, 0, \
					 SYM_ALG_SM4, SYM_ENCRYPTION , SYM_ECB_MODE,data_buff)){
		vPortFree(data_buff);
		f_close(&file_c);
		f_unlink(kek_name);
		return ERR_CIPN_ENCKEYFILE;
	}
	//�����ԿУ����,��Կ������У�顣
	if(GenUserKeyCheck(data_buff,data_len,&btr)){
		vPortFree(data_buff);
		f_close(&file_c);
		f_unlink (kek_name);
		return ERR_MANG_CHECKCODE;
	}
	//����pinд���ļ���
	res = f_write(&file_c,data_buff,btr,&br);
	vPortFree(data_buff);
	f_close(&file_c);	
	if(res)
		return ERR_CIPN_WRITKEYFILE;
	return 0;
}

//read_kek
//���룺index			��Կ����
//����� 	0 			��֤�ɹ�
//				1				��֤ʧ��
int32_t read_kek(uint16_t index,uint8_t *kek_data,uint8_t *kek_len)
{
	FRESULT res;
	FIL  file_c;
	uint8_t btr=16;				//pin max length is 32
	uint32_t br=0;
	uint8_t buff_enc[48]={0};
	uint8_t buff_dnc[48]={0};
	char kek_name[10]= "1:kek/";//6+3+1
	char index_str[4]={0};

	sprintf(index_str,"%d",index);
	strcat(kek_name,index_str);
	res = f_open(&file_c,kek_name,FA_READ);
	LEAVE_OPEN(res)
	res = f_read(&file_c,buff_enc,btr,&br);
	f_close(&file_c);
	if(res != FR_OK)
		return ERR_CIPN_READKEYFILE;
	//���ܼ��ܵ�pin
	if(Sym_Crypt_WithKey(buff_enc,48,main_key,16,0, 0, \
					   SYM_ALG_SM4, SYM_DECRYPTION , SYM_ECB_MODE, buff_dnc))
		{
			return ERR_CIPN_DECKEYFILE;
		}
	else{
			*kek_len = buff_dnc[0];
			memcpy(kek_data,buff_dnc+16,32);
			return 0;
		}
}


//GenRSA
//����RSA��Կ,��������ת��
//output :	*RSA_CIPH_BUFF		RSA��Կ����ָ��
//input	 :	key_bits		1024		RSA1024
//											2048		RSA2048
int32_t GenRSA(uint8_t *RSA_CIPH_BUFF, UINT32 key_bits)
{
	uint8_t rsa_buff[RSA2048_BUFFLEN]={0};
	RSA_KEYGEN_G_STR rsa_ciph;
	memset(&rsa_ciph, 0, sizeof(RSA_KEYGEN_G_STR));
	if(RSA_Keygen_init(&rsa_ciph, key_bits, rsa_buff))
		return ERR_CIPN_GENRSAKEY;
	if(RSA_Gen_Keypair(&rsa_ciph, key_bits))
		return ERR_CIPN_GENRSAKEY;
	memset(RSA_CIPH_BUFF,0,1048);
	RSA_KeyGen_to_Memory(&rsa_ciph, key_bits, RSA_CIPH_BUFF);
//	print(PRINT_CIPH,"KeyGen:\n");
//	printfb(RSA_CIPH_BUFF,512);
	return 0;
}

//GenUsrCiph
//�����û���Կ
//input :		index 	�û���Կ������
//					type		�û���Կ����
//					*Pin		�û���֤��Կ����ָ��
//					PinLen	��֤��Կ����
int32_t GenUsrCiph(uint16_t index,uint16_t type,char *Pin,uint16_t PinLen)
{
	int32_t ret=0;
	uint8_t rsa_buff[RSA2048_BUFFLEN]={0};
	ECC_G_STR sm2_para;
	
	RSA_KEYGEN_G_STR rsa_ciph,rsa_sign;
	SM2KeyPair	SM2_ciph,SM2_sign;
	if(type == USER_KEYTYPE_SM2){
		ret=write_cipher_access(index,PinLen,Pin,0);
		if(ret)
			return ret;
		SM2_param_init(&sm2_para);
		if(SM2_Gen_Keypair(&sm2_para,(uint8_t*)(&SM2_ciph.sk), \
											(uint8_t*)(&SM2_ciph.pk.x),(uint8_t*)(&SM2_ciph.pk.y)))		//���ɼ�����Կ
			return ERR_CIPN_GENSM2KEY;
		if(SM2_Gen_Keypair(&sm2_para,(uint8_t*)(&SM2_sign.sk), \
											(uint8_t*)(&SM2_sign.pk.x),(uint8_t*)(&SM2_sign.pk.y)))		//����ǩ����Կ
			return ERR_CIPN_GENSM2KEY;
//		print(PRINT_CIPH,"Gen SM2 Keypair\r\n");
//		printf_byte((uint8_t *)&SM2_ciph,sizeof(SM2KeyPair));
//		print(PRINT_CIPH,"Gen SM2 sign keypair:\r\n");
//		printf_byte((uint8_t *)&SM2_sign,sizeof(SM2KeyPair));
		ret=write_cipher(index,sizeof(SM2KeyPair),(uint8_t *)&SM2_ciph,0);
		if(ret)
			return ret;
		//print(PRINT_CIPH,"save cipher\r\n");
		ret=write_cipher(index|SIGN,sizeof(SM2KeyPair),(uint8_t *)&SM2_sign,0);
		if(ret)
			return ret;
		//print(PRINT_CIPH,"save sign cipher\r\n");

		set_userkey_login(index);
		return 0;
	}
	else if(type == USER_KEYTYPE_RSA1024){
		ret = write_cipher_access(index,PinLen,Pin,0);	//�洢��֤��Կ
		if(ret)
			return ret;
		if(GenRSA(rsa_buff, 1024))		//����RSA������Կ
			return ERR_CIPN_GENRSAKEY;
//		print(PRINT_CIPH,"RSA 1024 cipher is:\r\n");
//		printf_byte(rsa_buff,1408);
		ret = write_cipher(index, RSA1024_BUFFLEN, rsa_buff,0);	//�洢������Կ
		if(ret)
			return ret;
		if(GenRSA(rsa_buff, 1024))		//����RSAǩ����Կ
			return ERR_CIPN_GENRSAKEY;
//		print(PRINT_CIPH,"RSA 1024 signature is:\r\n");
//		printf_byte(rsa_buff,1408);
		ret = write_cipher(index|SIGN, RSA1024_BUFFLEN, rsa_buff,0);//�洢ǩ����Կ
		if(ret)
			return ret;
		set_userkey_login(index);
	}
	else if(type == USER_KEYTYPE_RSA2048){
		ret = write_cipher_access(index,PinLen,Pin,0);	//�洢��֤��Կ
		if(ret)
			return ret;
		if(GenRSA(rsa_buff, 2048))		//����RSA������Կ
			return ERR_CIPN_GENRSAKEY;
//		print(PRINT_CIPH,"RSA 2048 cipher is:\r\n");
//		printf_byte(rsa_buff,1408);
		ret = write_cipher(index | R_2048, RSA2048_BUFFLEN, rsa_buff,0);	//�洢������Կ
		if(ret)
			return ret;
		if(GenRSA(rsa_buff, 2048))		//����RSAǩ����Կ
			return ERR_CIPN_GENRSAKEY;
//		print(PRINT_CIPH,"RSA 2048 signature is:\r\n");
//		printf_byte(rsa_buff,1408);
		ret = write_cipher(index | SIGN | R_2048, RSA2048_BUFFLEN, rsa_buff,0);//�洢ǩ����Կ
		if(ret)
			return ret;
		set_userkey_login(index);
	}
	else
		return ERR_COMM_INPUT;
	return 0;
}

//DelUsrCiphNopin
//ɾ�����ܣ�ǩ����Կ��Կ
//input ��	index		Ҫɾ�����û���Կ���������λΪ1��ʾǩ����Կ�����λΪ0��ʾ������Կ
int32_t DelUsrCiphNopin(uint16_t index)
{
	FRESULT res;
	char cipher_name_ciph[16]= "1:cipher/";
	char name[6]={0};
	char RSA2048name[6]={0};
	uint16_t RSA2048_index=index;
	
	RSA2048_index|=R_2048;
	sprintf(name,"%d",index);
	memset(cipher_name_ciph+9,0,7);
	memcpy(cipher_name_ciph+9,name,6);


	res = f_unlink (cipher_name_ciph);		//ɾ���ļ�
	if(res){
		sprintf(RSA2048name,"%d",RSA2048_index);
		memcpy(cipher_name_ciph+9,RSA2048name,6);
		res = f_unlink (cipher_name_ciph);
		if(res){
			print(PRINT_CIPH,"delete ciph file fail ,res is %d\r\n",res);
			return res;
		}
	}
	else{
		if(index&0xF000){										//ɾ��ǩ����Կ
			sram_rsa_delkey((index&0x0fff)*2+1);
			fpga_sm2_delkey((index&0x0fff)*2+1);
		}
		else{
			sram_rsa_delkey(index*2);					//ɾ��������Կ
			fpga_sm2_delkey(index*2);
		}
	}
	return res;
}


//DelUsrCiph
//ɾ���û���Կ
//input ��	index		Ҫɾ�����û���Կ����
int32_t DelUsrCiph(uint16_t index)
{
	FRESULT res;
	char cipher_name_ciph[16]= "1:cipher/";
	char cipher_pin[19]="1:cipher/pin";
	char name[6]={0};
	char RSA2048name[6]={0};
	uint16_t RSA2048_index=index;
	
	RSA2048_index|=R_2048;
	sprintf(name,"%d",index);
	memset(cipher_name_ciph+9,0,7);
	memcpy(cipher_name_ciph+9,name,6);

	print(PRINT_CIPH,"DL cip_name %s\r\n",cipher_name_ciph);
	res = f_unlink (cipher_name_ciph);		//ɾ��������Կ
	if(res){
		sprintf(RSA2048name,"%d",RSA2048_index);
		memcpy(cipher_name_ciph+9,RSA2048name,6);
		res = f_unlink (cipher_name_ciph);
		if(res)		
			print(PRINT_CIPH,"DL cip file err %d\r\n",res);
		sram_rsa_delkey(index*2);
//		return res;
	}else{
		fpga_sm2_delkey(index*2);
	}
	memset(cipher_pin+12,0,7);
	memcpy(cipher_pin+12,name,6);
	print(PRINT_CIPH,"DL cip_pin %s\r\n",cipher_pin);
	res = f_unlink(cipher_pin);						//ɾ����֤��Կ
	if(res)
		print(PRINT_CIPH,"DL pin file err %d\r\n",res);
//		return res;
	
	index|=0xF000;
	RSA2048_index|=0xF000;
	memset(name,0,6);
	sprintf(name,"%d",index);
	memset(cipher_name_ciph+9,0,7);
	memcpy(cipher_name_ciph+9,name,6);
	res = f_unlink (cipher_name_ciph);	//ɾ��ǩ����Կ
	if(res){
		memset(RSA2048name,0,6);
		sprintf(RSA2048name,"%d",RSA2048_index);
		memcpy(cipher_name_ciph+9,RSA2048name,6);
		res = f_unlink (cipher_name_ciph);
		if(res)		
			print(PRINT_CIPH,"DL sign file err %d\r\n",res);
//		return res;
		sram_rsa_delkey((index&0x0fff)*2+1);
	}else{
		fpga_sm2_delkey((index&0x0fff)*2+1);
	}
		
	if(res)
		return ERR_CIPN_DELKEYFILE;

	return res;
}

//index 1--256
//bits �ֽ���
int32_t GenKEK(uint16_t index,uint16_t bits)
{
	int32_t ret=0;
	uint8_t random_data[32];
	uint16_t bytes = BIT_TO_BYTE(bits);
	uint16_t lens =bytes+16;			//16�ֽڶ��룬16�ֽ���Ϣ
	uint8_t cat_data[48];
	uint8_t message[16] = {0};
	if(16 != bytes && 32 != bytes && 24!= bytes)
		return ERR_CIPN_INDEXLEN;
	if(get_random_MCU(random_data,bytes))
		return ERR_CIPN_GENRANDOM;
	message[0] = (bytes & 0xff);			//��Կ����
	memcpy(cat_data,message,16);
	memcpy(cat_data+16,random_data,bytes);
	ret=write_kek(index,lens,cat_data);
	if(ret == 0)
		set_KEKkey_login(index);
	return ret;
}

//DelKEK
//ɾ��KEK��Կ
//input :		index 	KEK��Կ����
int32_t DelKEK(uint16_t index)
{
	FRESULT res;
	char kek_name[10]= "1:kek/";
	char name[4]={0};
	
	sprintf(name,"%d",index);
	memset(kek_name+6,0,4);
	memcpy(kek_name+6,name,4);
	res = f_unlink (kek_name);		//ɾ��������Կ
	if(res){
		return ERR_CIPN_DELKEYFILE;
	}
	sram_kek_delkey(index);
	return res;
}

//Str_to_Short
//���ļ������ַ���ת��������
//input :		*str 	�ļ���ָ��
unsigned short Str_to_Short(char * str)
{
	uint8_t index_arr[5]={0};
	uint16_t  index = 0;
	
	uint8_t i=0,j=0;
	if((*str>'9') || (*str<'0'))			//����Կ�ļ�
		return 0;			
	for(;;){
		if((*(str+i)<='9') && (*(str+i)>='0')){
			index_arr[i]=*(str+i)-'0';
		}
		else
			break;
		i++;
	}
	for(;i>0;i--)
		index += index_arr[j++]*pow(10,(i-1));
	return index;
}

//query_ciph
//��ѯ����Կ״̬
//output :	*ECC_n			SM2��Կ����ָ��
//			*RSA1024_n		RSA1024��Կ����ָ��
//			*RSA2048_n		RSA2048��Կ����ָ��
unsigned char query_ciph(uint16_t *ECC_n,uint16_t *RSA1024_n,uint16_t *RSA2048_n)
{
	FRESULT res = 0;
	DIR dir;
	FILINFO fno;
	uint16_t index=0;
//	uint16_t i=0, j=0;
	*ECC_n = 0;
	*RSA1024_n = 0;
	*RSA2048_n = 0;
	fno.lfsize=138;		//128+1+9
	fno.lfname=pvPortMalloc(fno.lfsize);
	if(fno.lfname==NULL){
		f_closedir(&dir);
		return FR_MALLOC_ERROR;
	}		
	memset(fno.lfname,0,fno.lfsize);
	memset(fno.fname,0,13);

	res = f_opendir(&dir,cipherdir);
	if (res == FR_OK ){
		for(;;){
			res = f_readdir(&dir,&fno);
			if (res != FR_OK ) break;	//��ȡ�ļ�����Ϣʧ��
			if(*fno.lfname){					//���ļ���
				if(*fno.lfname =='.')
					continue;
				index=Str_to_Short(fno.lfname); 
				if(index < 0xF000){					//����ǩ����Կ
					if(index>0 && index<257)	//1-256  SM2��Կ��
						(*ECC_n)++;
					else if(index > 256 && index < 289)
						(*RSA1024_n)++;
					else if(index > (256|R_2048) && index < (289|R_2048))
						(*RSA2048_n)++;
				}
				memset(fno.lfname,0,fno.lfsize);
			}else{									//���ļ���
				if(*fno.fname =='.')
					continue;
				if(*fno.fname == 0)	//�ļ���Ϊ��			
					break;
				index = Str_to_Short(fno.fname);
				if(index < 0xF000){					//����ǩ����Կ
					if(index>0 && index<257)	//1-256  SM2��Կ��
						(*ECC_n)++;
					else if(index > 256 && index < 289)
						(*RSA1024_n)++;
					else if(index > (256|R_2048) && index < (289|R_2048))
						(*RSA2048_n)++;
				}
				memset(fno.fname,0,13);
			}
		}
	}
	vPortFree(fno.lfname);
	f_closedir(&dir);
	return res;
}

//Get_cipher_status
//��ȡcipher��Կ״̬
//output :	*data �����Կ״̬�ڴ�ָ�� 
unsigned char query_kek(uint16_t *KEK_n)
{
	FRESULT res = 0;
	DIR dir;
	FILINFO fno;
	uint16_t index=0;
	//uint16_t i=0, j=0;
	*KEK_n = 0;
//	fno.lfsize=138;		//128+1+9			kek��û���õ����ļ���
//	fno.lfname=pvPortMalloc(fno.lfsize);
//	memset(fno.lfname,0,fno.lfsize);
//	memset(fno.fname,0,13);
//	if(fno.lfname==NULL){
//		f_closedir(&dir);
//		return FR_MALLOC_ERROR;
//	}		
	res = f_opendir(&dir,kekdir);
	if (res == FR_OK ){
		for(;;){
			res = f_readdir(&dir,&fno);
			if (res != FR_OK ) break;	//��ȡ�ļ�����Ϣʧ��
//			if(*fno.lfname){					//���ļ���
//				if(*fno.lfname =='.')
//					continue;
//				index=Str_to_Short(fno.lfname); 
//				if(index < 0xF000){				
//					if(index>0 && index<257)	//1-256 
//						(*KEK_n)++;
//				}
//				memset(fno.lfname,0,fno.lfsize);
//			}else{									//���ļ���
				if(*fno.fname =='.')
					continue;
				if(*fno.fname == 0)	//�ļ���Ϊ��
					break;
				index = Str_to_Short(fno.fname);
				if(index>0 && index<257)	//1-256 KEK
					(*KEK_n)++;
				memset(fno.fname,0,13);
//			}
		}
	}
//	vPortFree(fno.lfname);
	f_closedir(&dir);
	return res;
}

//Get_Cipher_Num
//��ȡ�û���Կ����
//output :  *data 	����û���Կ�����ڴ�ָ��
int32_t Get_Cipher_Num(unsigned char *data)
{
	int32_t res;
	res = (query_ciph((uint16_t *)data,(uint16_t *)(data+2),(uint16_t *)(data+4))  \
						|| query_kek((uint16_t *)(data+6)));
	return res;
	
}

//Get_cipher_status
//��ȡcipher��Կ״̬
//output :	*data �����Կ״̬�ڴ�ָ�� 
int32_t Get_cipher_status(uint8_t *data)
{
	FRESULT res = 0;
	DIR dir;
	FILINFO fno={0};
	uint16_t index=0;
	uint8_t Cipher_Status[288]={0};		//256+32
//	uint16_t i=0, j=0;
	fno.lfsize=138;		//128+1+9
	fno.lfname=pvPortMalloc(fno.lfsize);
	if(fno.lfname==NULL){
		f_closedir(&dir);
		return FR_MALLOC_ERROR;
	}	
	memset(fno.lfname,0,fno.lfsize);
	memset(fno.fname,0,13);
	
	res = f_opendir(&dir,cipherdir);
	if (res == FR_OK ){
		for(;;){
			res = f_readdir(&dir,&fno);
			if (res != FR_OK ) break;	//��ȡ�ļ�����Ϣʧ��
			if(*fno.lfname){					//���ļ���
				if(*fno.lfname =='.')
					continue;
				index=Str_to_Short(fno.lfname); 
				if(index < 0xF000 && index > 0){					//����ǩ����Կ
					if(index>0 && index<257)	//1-256  SM2��Կ��
						Cipher_Status[index-1]=1;
					else if(index > 256 && index < 289)
						Cipher_Status[index-1]=2;
					else if(index > (256|R_2048) && index < (289|R_2048))
						Cipher_Status[(index&(~R_2048))-1]=3;
				}
				memset(fno.lfname,0,fno.lfsize);
			}else{									//���ļ���
				if(*fno.fname =='.')
					continue;
				if(*fno.fname == 0)	//�ļ���Ϊ��
					break;
				index = Str_to_Short(fno.fname);
				if(index < 0xF000 && index > 0){					//����ǩ����Կ
					if(index>0 && index<257)	//1-256  SM2��Կ��
						Cipher_Status[index-1]=1;
					else if(index > 256 && index < 289)
						Cipher_Status[index-1]=2;			//RSA1024 ��Կ
					else if(index > (256|R_2048) && index < (289|R_2048))
						Cipher_Status[(index&(~R_2048))-1]=3;			//RSA2048
				}
				memset(fno.fname,0,13);
			}
		}
	}
	vPortFree(fno.lfname);
	f_closedir(&dir);
	memcpy(data,Cipher_Status,288);
	if(res)
		return ERR_CIPN_READKEYFILE;
	return res;//res
}
//Get_KEK_status
//��ȡKEK��Կ״̬
//output :	*data �����Կ״̬�ڴ�ָ��

int32_t read_KEK_len(uint16_t kek_index,uint8_t *kek_len){
	int32_t rtval;
	uint8_t KEK_buff[32]={0};
	if (kek_index == 0 || kek_index > KEK_NUM )
	{
		return -1;
	}
	if(kek_index <= KEK_NUM){ //KEK��Կ
		rtval = read_kek(kek_index,KEK_buff,kek_len);
		if (rtval)
		{
			return -1;
		}
	}
	return 0;
}

int32_t Get_KEK_status(uint8_t *data)
{
	FRESULT res = 0;
	DIR dir;
	FILINFO fno={0};
	uint16_t index=0;
	uint8_t kek_len=0;
	uint8_t KEK_Status[256]={0};		//256+32
//	uint16_t i=0, j=0;
	fno.lfsize=138;		//128+1+9
	fno.lfname=pvPortMalloc(fno.lfsize);
	memset(fno.lfname,0,fno.lfsize);
	memset(fno.fname,0,13);
	if(fno.lfname==NULL){
		f_closedir(&dir);
		return ERR_COMM_MALLOC;
	}		
	res = f_opendir(&dir,kekdir);
	if (res == FR_OK ){
		for(;;){
			res = f_readdir(&dir,&fno);
			if (res != FR_OK ) break;	//��ȡ�ļ�����Ϣʧ��
			if(*fno.lfname){					//���ļ���
				if(*fno.lfname =='.')
					continue;
				index=Str_to_Short(fno.lfname); 
				if(read_KEK_len(index,&kek_len))
					break;
				KEK_Status[index-1]=(kek_len & 0xff);
				memset(fno.lfname,0,fno.lfsize);
			}else{									//���ļ���
				if(*fno.fname =='.')
					continue;
				if(*fno.fname == 0)	//�ļ���Ϊ��
					break;
				index = Str_to_Short(fno.fname);
				if(read_KEK_len(index,&kek_len))
					break;
				KEK_Status[index-1]=(kek_len & 0xff);;
				memset(fno.fname,0,13);
			}
		}
	}
	vPortFree(fno.lfname);
	f_closedir(&dir);
	memcpy(data,KEK_Status,256);
	if(res)
		return ERR_CIPN_READKEYFILE;
	return 0;
}

void init_sessionkey(void)
{
	memset(SESSIONKEY, 0, SKEYNUM); //SKEYADD
}

unsigned short read_sessionkey_mcu(unsigned short *len,unsigned char *sesskey,unsigned int index)
{
	if(index >= SKEYNUM)
		return ERR_CIPN_SKEYINDEXERR;
	if((SESSIONKEY[index]&0x80) == 0){
		return ERR_CIPN_SKEYINDEXNULL;
	}
	*len = SESSIONKEY[index]&0x7f;
	memcpy(sesskey,SESSIONKEY+SKEYNUM+index*SKEYSIZE,*len);
	return 0;
}


unsigned short writer_sessionkey_mcufpga(unsigned short len, unsigned char *sesskey, unsigned int *index)
{
	uint16_t i=0;
	int ret = 0;
	if(len > 32){
		return ERR_CIPN_SKEYLEN;
	}
	
	for(i = 0; i < SKEYNUM; i++){
		if((SESSIONKEY[i] & 0x80) == 0){
			*index = i;
			//MCU��д��Ự��Կ
			SESSIONKEY[i]= 0x80 | len;
			memcpy(SESSIONKEY + SKEYNUM + i * SKEYSIZE, sesskey, len);
			//д��FPGA��
			if(len == 16){
				//д��FPGA SM4 �Ự��Կ
				ret = fpga_set_symkey(FPGA_DATA_SM4, *index, sesskey, len);
				if(ret != 0){
					return ERR_CIPN_SKEYINFPGA;
				}
				if(!HSMD1){
				ret = fpga_set_symkey(FPGA_DATA_SM4_1, *index, sesskey, len);
				if(ret != 0){
					return ERR_CIPN_SKEYINFPGA;
				}
			}
				//д��FPGA SM1 �Ự��Կ
				ret = fpga_set_symkey(FPGA_DATA_SM1, *index, sesskey, len);
				if(ret != 0){
					return ERR_CIPN_SKEYINFPGA;
				}
			}
			return 0;
		}
	}
	return ERR_CIPN_SKEYFULL;
}


unsigned short destory_sessionkey_mcufpga(unsigned int index_num, unsigned char *index_data){
	//unsigned short keylen = 0;
	unsigned short *keyindex = (unsigned short *)index_data;
	
	if(index_num > SKEYNUM){
		return ERR_CIPN_SKEYINDEXERR;
	}
	for(int i=0; i<index_num; i++){
		if(keyindex[i] >= SKEYNUM)
			return ERR_CIPN_SKEYINDEXERR;
		if((SESSIONKEY[keyindex[i]] & 0x80) == 0){
			return ERR_CIPN_SKEYINDEXNULL;
		}
		//����muc�Ự��Կ
		SESSIONKEY[keyindex[i]] = 0;
		memset(SESSIONKEY + SKEYNUM + keyindex[i] * SKEYSIZE, 0, SKEYSIZE);//����
	}
	return 0;
}

int32_t mcu_sm2_setkey(uint16_t key_index, SM2PrivateKey *pri_key, SM2PublicKey *pub_key){
	
	//uint16_t real_index;
	if (key_index < 0 || key_index > 2*(SM2_KEYPAIR_NUM+1))
	{
		return ERR_CIPN_USRKEYERR;
	}
	else{
		*(uint8_t *)(SM2_KEYPAIR_INFO_ADDR + key_index) = USER_KEYTYPE_SM2;
	}
	memcpy((uint8_t *)(SM2_KEYPAIR_DATA_ADDR + SM2_KEYPAIR_LEN * key_index),(uint8_t *)pub_key,sizeof(SM2PublicKey));
	memcpy((uint8_t *)(SM2_KEYPAIR_DATA_ADDR + SM2_KEYPAIR_LEN * key_index+sizeof(SM2PublicKey)),(uint8_t *)pri_key,sizeof(SM2PrivateKey));
	return 0;
}
int32_t mcu_sm2_getkey(uint16_t key_index, SM2PrivateKey *pri_key, SM2PublicKey *pub_key){
	if (key_index < 0 || key_index > 2*(SM2_KEYPAIR_NUM+1))
	{
		return ERR_CIPN_USRKEYERR;
	}
	else if(*(uint8_t *)(SM2_KEYPAIR_INFO_ADDR + key_index) == USER_KEYTYPE_NONE)
	{
		return ERR_CIPN_USRKEYNOEXIT;
	}
	memcpy((uint8_t *)pub_key,(uint8_t *)(SM2_KEYPAIR_DATA_ADDR + SM2_KEYPAIR_LEN * key_index),sizeof(SM2PublicKey));
	memcpy((uint8_t *)pri_key,(uint8_t *)(SM2_KEYPAIR_DATA_ADDR + SM2_KEYPAIR_LEN * key_index+sizeof(SM2PublicKey)),sizeof(SM2PrivateKey));
	return 0;
}
int32_t mcu_sm2_delkey(uint16_t key_index){
	if (key_index < 0 || key_index > 2*(SM2_KEYPAIR_NUM+1))
	{
		return ERR_CIPN_USRKEYERR;
	}
	*(uint8_t *)(SM2_KEYPAIR_INFO_ADDR + key_index) = USER_KEYTYPE_NONE;
	return 0;
}

int32_t sram_rsa_setkey(uint16_t rsa_index, uint16_t keypair_len, uint8_t *keypair_buff)
{
	
	uint16_t real_index;
	real_index = rsa_index - (SM2_KEYPAIR_NUM + 1) * 2;
	if (keypair_len == RSA1024_BUFFLEN)
	{
		*(uint8_t *)(RSA_KEYPAIR_INFO_ADDR + real_index) = USER_KEYTYPE_RSA1024;
	}
	else if (keypair_len == RSA2048_BUFFLEN)
	{
		*(uint8_t *)(RSA_KEYPAIR_INFO_ADDR + real_index) = USER_KEYTYPE_RSA2048;
	}
	else
	{
		*(uint8_t *)(RSA_KEYPAIR_INFO_ADDR + real_index) = USER_KEYTYPE_NONE;
	}
	memcpy((uint8_t *)(RSA_KEYPAIR_DATA_ADDR + RSA2048_BUFFLEN * real_index), keypair_buff, keypair_len);
	return 0;
}

int32_t sram_ras_get_prikey(uint16_t rsa_index, uint8_t *prikey_buff, uint16_t *pubkey_bits)
{
	uint8_t key_type;
	uint16_t real_index = rsa_index - (SM2_KEYPAIR_NUM + 1) * 2;
	
	key_type = *(uint8_t *)(RSA_KEYPAIR_INFO_ADDR + real_index);
	if (key_type == USER_KEYTYPE_NONE)
	{
		print(PRINT_CIPH,"RAS get pubkey id NULL\r\n");
		return -1;
	}
	else if (key_type == USER_KEYTYPE_RSA1024)
	{
		*pubkey_bits = 1024; 
		memcpy(prikey_buff, (uint8_t *)(RSA_KEYPAIR_DATA_ADDR + RSA2048_BUFFLEN * real_index), RSA1024_BUFFLEN);
	}
	else if (key_type == USER_KEYTYPE_RSA2048)
	{
		*pubkey_bits = 2048; 
		memcpy(prikey_buff, (uint8_t *)(RSA_KEYPAIR_DATA_ADDR + RSA2048_BUFFLEN * real_index), RSA2048_BUFFLEN);
	}
	else
	{
		return -2;
	}
	return 0;
}

int32_t sram_ras_get_pubkey(uint16_t rsa_index, uint8_t *pubkey_buff, uint16_t *pubkey_bits)
{
	uint8_t key_type;
	uint16_t real_index = rsa_index - (SM2_KEYPAIR_NUM + 1) * 2;
	
	key_type = *(uint8_t *)(RSA_KEYPAIR_INFO_ADDR + real_index);
	if (key_type == USER_KEYTYPE_NONE)
	{
		print(PRINT_CIPH,"RAS get pubkey id NULL\r\n");
		return ERR_CIPN_USRKEYNOEXIT;
	}
	else if (key_type == USER_KEYTYPE_RSA1024)
	{
		*pubkey_bits = 1024; 
	}
	else if (key_type == USER_KEYTYPE_RSA2048)
	{
		*pubkey_bits = 2048; 
	}
	else
	{
		return ERR_COMM_INDATA;
	}
	memcpy(pubkey_buff, (uint8_t *)(RSA_KEYPAIR_DATA_ADDR + RSA2048_BUFFLEN * real_index), (*pubkey_bits / 8 * 2));
	return 0;
}

static int32_t sram_rsa_delkey(uint16_t rsa_index)
{
	uint16_t real_index;
	
	real_index = rsa_index - (SM2_KEYPAIR_NUM + 1) * 2;
	*(uint8_t *)(RSA_KEYPAIR_INFO_ADDR + real_index) = 0;
	
	return 0;
}

int sram_kek_setkey(uint16_t kek_index, uint8_t *kek_buff, uint8_t kek_len){
	
	*(uint8_t *)(KEK_INFO_ADDR + kek_index) = ((1U << 7) | (kek_len & 0x7f));
	//print(PRINT_CIPH,"SET KEK_INFO_ADDR = %x\r\n",*(uint8_t *)(KEK_INFO_ADDR + kek_index));
	memcpy((uint8_t *)(KEK_DATA_ADDR + kek_index * KEK_LEN_MAX), kek_buff, KEK_LEN_MAX);
	return 0;
}

int sram_kek_getkey(uint16_t kek_index, uint16_t *keyid, uint8_t *kek_buff, uint8_t *kek_len){
	uint8_t lens = 0;
	//print(PRINT_CIPH,"GET KEK_INFO_ADDR = %x\r\n",*(uint8_t *)(KEK_INFO_ADDR + kek_index));
	if((*(uint8_t *)(KEK_INFO_ADDR + kek_index) & 0x80) != 0x80){
		return ERR_CIPN_SKEYINDEXNULL;
	}
	lens = (*(uint8_t *)(KEK_INFO_ADDR + kek_index) & 0x7f);
	
	//�жϼ���ģʽΪECBģʽ,��ECB����
	if(!(*keyid & SGD_ECB)){
		return SDR_KEYTYPEERR;
	}
	//�жϼ�����Կ�����Ƿ�ƥ��
	switch(*keyid & SGD_ALG){
	case SGD_SM4:
	case SGD_SM1:
	case SGD_AES128:
		if(BIT_TO_BYTE(128) != lens)
			return SDR_KEYTYPEERR;
		break;
	case SGD_AES192:
		if(BIT_TO_BYTE(192) != lens)
			return SDR_KEYTYPEERR;
		break;
	case SGD_AES256:
		if(BIT_TO_BYTE(256) != lens)
			return SDR_KEYTYPEERR;
		break;
	default:
		return SDR_ALGNOTSUPPORT;
	}
		if((*keyid & SGD_ALG) == SGD_SM1)
			*keyid = SYM_ALG_SM1;
		else if((*keyid & SGD_ALG) == SGD_SM4)
			*keyid = SYM_ALG_SM4;
		else if((*keyid & SGD_ALG) == SGD_AES128 || (*keyid & SGD_ALG) == SGD_AES192 || (*keyid & SGD_ALG) == SGD_AES256)
			*keyid = SYM_ALG_AES;
	*kek_len = (uint16_t)lens;
	memcpy(kek_buff, (uint8_t *)(KEK_DATA_ADDR + kek_index * KEK_LEN_MAX), KEK_LEN_MAX);
	//memcpy((uint8_t *)(KEK_DATA_ADDR + kek_index * 2), kek_buff, KEK_LEN_MAX);
	return 0;
}

int sram_kek_delkey(uint16_t kek_index){

	*(uint8_t *)(KEK_INFO_ADDR + kek_index) = 0;
	return 0;
}


int32_t set_KEKkey_login(uint16_t kek_index){
	int32_t rtval;
	uint8_t *KEK_buff;
	uint8_t kek_len;
	if (kek_index == 0 || kek_index > KEK_NUM )
	{
		return -1;
	}
	KEK_buff = pvPortMalloc(KEK_LEN_MAX);
	if (KEK_buff == NULL)
	{
		return -3;
	}
	if(kek_index <= KEK_NUM){ //KEK��Կ
		rtval = read_kek(kek_index,KEK_buff,&kek_len);
		if (rtval)
		{
			vPortFree(KEK_buff);
			return -1;
		}
	}	
	sram_kek_setkey(kek_index, KEK_buff,kek_len);
	vPortFree(KEK_buff);
	return 0;
}


 int32_t set_userkey_login(uint16_t keypair_index)
{
	int32_t rtval;
	uint32_t need_read;
	uint32_t indeed_read;
	SM2KeyPair sm2_keypair;
	uint8_t *rsa_keybuff;
	
	if (keypair_index == 0 || keypair_index > SM2_KEYPAIR_NUM + RSA_KEYPAIR_NUM )
	{
		return -1;
	}
	if (keypair_index > 0 && keypair_index <= SM2_KEYPAIR_NUM)			//SM2 key
	{
		//set to fpga, even num is encrypt keypair, odd num is sign keypair
		//������Կ��
		rtval = read_cipher(keypair_index, sizeof(SM2KeyPair), &indeed_read, (uint8_t *)&sm2_keypair);
		if (rtval || indeed_read != sizeof(SM2KeyPair))
		{
			return -1;
		}
		//printfb((uint8_t *)&sm2_keypair, sizeof(SM2KeyPair));
		fpga_sm2_setkey(keypair_index * 2, &sm2_keypair.sk, &sm2_keypair.pk);
		
		//ǩ����Կ��
		rtval = read_cipher(keypair_index | SIGN, sizeof(SM2KeyPair), &indeed_read, (uint8_t *)&sm2_keypair);
		if (rtval)
		{
			return -2;
		}
		fpga_sm2_setkey(keypair_index * 2 + 1, &sm2_keypair.sk, &sm2_keypair.pk);
	}
	else													//RSA key
	{
		//set to external SRAM
		//from 280K, size  90K
		rsa_keybuff = pvPortMalloc(RSA2048_BUFFLEN);
		if (rsa_keybuff == NULL)
		{
			return -3;
		}
		
		rtval = read_cipher(keypair_index, RSA1024_BUFFLEN, &indeed_read, rsa_keybuff);
		if (rtval || indeed_read != RSA1024_BUFFLEN)
		{
			rtval = read_cipher(keypair_index | R_2048, RSA2048_BUFFLEN, &indeed_read, rsa_keybuff);
			if (rtval || indeed_read != RSA2048_BUFFLEN)
			{
				vPortFree(rsa_keybuff);
				return -4;
			}
		}
		sram_rsa_setkey(keypair_index * 2, indeed_read, rsa_keybuff);
		
		rtval = read_cipher(keypair_index | SIGN, RSA1024_BUFFLEN, &indeed_read, rsa_keybuff);
		if (rtval || indeed_read != RSA1024_BUFFLEN)
		{
			rtval = read_cipher(keypair_index | SIGN | R_2048, RSA2048_BUFFLEN, &indeed_read, rsa_keybuff);
			if (rtval || indeed_read != RSA2048_BUFFLEN)
			{
				vPortFree(rsa_keybuff);
				return -5;
			}
		}
		sram_rsa_setkey(keypair_index * 2 + 1, indeed_read, rsa_keybuff);
		vPortFree(rsa_keybuff);
	}
	
	return 0;
}

//����ͬһ��������Կ
int32_t importkeypair(uint16_t index, uint8_t *indata)
{
	int32_t rtval,SyID = 0;
	uint32_t sy_len;
	uint8_t Sydata[64]={0};
	uint8_t Pridata[64]={0};
	SM2KeyPair outdata={0};
	EnvelopedECCKey *ECCKey = (EnvelopedECCKey*)indata;
	
	SM2KeyPair *ciph =NULL;
	/****�����ж�****/
	if(index > SM2_KEYPAIR_NUM)//RSA_KEYPAIR_NUM
		return ERR_CIPN_USRKEYERR;
	if(256 != ECCKey->ulBits)
		return SDR_INARGERR;
	//֧��SM1��SM4
	switch(ECCKey->ulSymmAlgID){
		case SGD_SM1_ECB:
			SyID = SYM_ALG_SM1;
			break;
		case SGD_SM4_ECB:
			SyID = SYM_ALG_SM4;
			break;
		default:
			return SDR_INARGERR;
		}
/****�豸��Կ����****/
	if(0 == index){
		ciph = (SM2KeyPair*)(eFlash.Devkeypair);
		rtval = mcu_sm2_decrypt_external(&ciph->sk, (uint8_t *)&ECCKey->ECCCipherBlob, 32+32+32+16, Sydata, &sy_len);//SM2���ܶԳ���Կ
			if(rtval)return SDR_ENCDATAERR;
		rtval = Sym_Crypt_WithKey(ECCKey->cbEncryptedPriKey,32,Sydata,sy_len,0, 0, \
							SyID, SYM_DECRYPTION , SYM_ECB_MODE, Pridata);//�Գ���Կ����˽Կ����
		if(rtval) return SDR_ENCDATAERR;
/****��֤��Կ��****/
		if(mcu_testsm2_pair((SM2PublicKey *)&(ECCKey->PubKey),(SM2PrivateKey *)Pridata))
			return SDR_KEYERR;
		memcpy(&outdata.pk,(uint8_t*)&ECCKey->PubKey,sizeof(SM2PublicKey));
		memcpy(&outdata.sk,(uint8_t*)Pridata,sizeof(SM2PrivateKey));
		memcpy(eFlash.Devkeypair,(uint8_t*)&outdata,sizeof(SM2KeyPair));
		sy_len = eFlash.DEV_STATE;
		eFlash.DEV_STATE = ReadyStatus;
		//����eflash���� ��Ӳ���Ա��Ϣ
		WriteFlashData();
		eFlash.DEV_STATE = sy_len;
	}
/****������Կ�Ե���****/
	else{
		rtval = mcu_sm2_decrypt_internal(index, (uint8_t *)&ECCKey->ECCCipherBlob, 32+32+32+16, Sydata, &sy_len);//SM2���ܶԳ���Կ,���Լ�����Կ
		if(rtval){
			rtval = mcu_sm2_decrypt_internal(index | SIGN, (uint8_t *)&ECCKey->ECCCipherBlob, 32+32+32+16, Sydata, &sy_len);//SM2���ܶԳ���Կ,����ǩ����Կ
				if(rtval) return SDR_ENCDATAERR;
		}
		rtval = Sym_Crypt_WithKey(ECCKey->cbEncryptedPriKey,32,Sydata,sy_len,0, 0, \
					SyID, SYM_DECRYPTION , SYM_ECB_MODE, Pridata);//�Գ���Կ����˽Կ����
		if(rtval) return SDR_ENCDATAERR;
		/****��֤��Կ��****/
		if(mcu_testsm2_pair((SM2PublicKey *)&(ECCKey->PubKey),(SM2PrivateKey *)Pridata))
			return SDR_KEYERR;
		memcpy(&outdata.pk,(uint8_t*)&ECCKey->PubKey,sizeof(SM2PublicKey));
		memcpy(&outdata.sk,(uint8_t*)Pridata,sizeof(SM2PrivateKey));
		rtval = DelUsrCiphNopin(index);		//ɾ��ԭ��Կ
		if(rtval) return ERR_CIPN_USRKEYNOEXIT;
		rtval = write_cipher(index,sizeof(SM2KeyPair),(uint8_t*)&outdata,0); //�洢����Կ
		if(rtval) return SDR_FILEWERR;
		rtval = set_userkey_login(index); //���ص�����
		//if(rtval) return rtval;
	}
	return 0;
}
//����ǩ���������Կ
int32_t importkeypair1(uint16_t index_use, uint16_t index_in, uint8_t *indata)
{
	int32_t rtval,SyID = 0;
	uint32_t sy_len;
	uint8_t Sydata[64]={0};
	uint8_t Pridata[64]={0};
	SM2KeyPair outdata={0};
	EnvelopedECCKey *ECCKey = (EnvelopedECCKey*)indata;
	
	SM2KeyPair *ciph =NULL;
	/****�����ж�****/
	if((index_use & 0x7fff) > SM2_KEYPAIR_NUM || (index_in & 0x7fff) > SM2_KEYPAIR_NUM) //RSA_KEYPAIR_NUM
		return ERR_CIPN_USRKEYERR;
	if(256 != ECCKey->ulBits)
		return SDR_INARGERR;
	//֧��SM1��SM4
	switch(ECCKey->ulSymmAlgID){
		case SGD_SM1_ECB:
			SyID = SYM_ALG_SM1;
			break;
		case SGD_SM4_ECB:
			SyID = SYM_ALG_SM4;
			break;
		default:
			return SDR_INARGERR;
		}
/****�豸��Կ����****/
	if(0 == index_use && 0 == index_in){
		ciph = (SM2KeyPair*)(eFlash.Devkeypair);
		rtval = mcu_sm2_decrypt_external(&ciph->sk, (uint8_t *)&ECCKey->ECCCipherBlob, 32+32+32+16, Sydata, &sy_len);//SM2���ܶԳ���Կ
		if(rtval) return SDR_ENCDATAERR;
		rtval = Sym_Crypt_WithKey(ECCKey->cbEncryptedPriKey,32,Sydata,sy_len,0, 0, \
							SyID, SYM_DECRYPTION , SYM_ECB_MODE, Pridata);//�Գ���Կ����˽Կ����
		if(rtval) return SDR_ENCDATAERR;
/****��֤��Կ��****/
		if(mcu_testsm2_pair((SM2PublicKey *)&(ECCKey->PubKey),(SM2PrivateKey *)Pridata))
			return SDR_KEYERR;
		memcpy(&outdata.pk,(uint8_t*)&ECCKey->PubKey,sizeof(SM2PublicKey));
		memcpy(&outdata.sk,(uint8_t*)Pridata,sizeof(SM2PrivateKey));
		memcpy(eFlash.Devkeypair,(uint8_t*)&outdata,sizeof(SM2KeyPair));
		sy_len = eFlash.DEV_STATE;
		eFlash.DEV_STATE = ReadyStatus;
		//����eflash���� ��Ӳ���Ա��Ϣ
		WriteFlashData();
		eFlash.DEV_STATE = sy_len;
	}
/****��Կ�Ե���****/
	else if(0 != index_use && 0 != index_in){
		//index_use = ((index_use & 0xefff)*2) | 0x8000;
		if(index_use & 0x8000) index_use |= SIGN;
		if(index_in & 0x8000) index_in |= SIGN;
		rtval = mcu_sm2_decrypt_internal(index_use, (uint8_t *)&ECCKey->ECCCipherBlob, 32+32+32+16, Sydata, &sy_len);//SM2���ܶԳ���Կ
		if(rtval) return SDR_ENCDATAERR;
		rtval = Sym_Crypt_WithKey(ECCKey->cbEncryptedPriKey,32,Sydata,sy_len,0, 0, \
					SyID, SYM_DECRYPTION , SYM_ECB_MODE, Pridata);//�Գ���Կ����˽Կ����
		if(rtval) return SDR_ENCDATAERR;
		/****��֤��Կ��****/
		if(mcu_testsm2_pair((SM2PublicKey *)&(ECCKey->PubKey),(SM2PrivateKey *)Pridata))
			return SDR_KEYERR;
		memcpy(&outdata.pk,(uint8_t*)&ECCKey->PubKey,sizeof(SM2PublicKey));
		memcpy(&outdata.sk,(uint8_t*)Pridata,sizeof(SM2PrivateKey));
		rtval = DelUsrCiphNopin(index_in);		//ɾ��ԭ��Կ��ǩ���������Կ
		if(rtval) return ERR_CIPN_USRKEYNOEXIT;
		rtval = write_cipher(index_in,sizeof(SM2KeyPair),(uint8_t*)&outdata,0); //�洢����Կ
		if(rtval) return SDR_FILEWERR;
		rtval = set_userkey_login(index_in & 0x0fff); //���ص�����
		//if(rtval) return rtval;
	}
	else{
		return SDR_INARGERR;
	}
	return 0;
}


int32_t clear_userkey_logout(void)
{
	int32_t i;
	
	for (i = 1; i <= SM2_KEYPAIR_NUM; i++)
	{
		fpga_sm2_delkey(i * 2);
		fpga_sm2_delkey(i * 2 + 1);
	}
	
	for (i = SM2_KEYPAIR_NUM + 1; i <= SM2_KEYPAIR_NUM + RSA_KEYPAIR_NUM; i++)
	{
		sram_rsa_delkey(i * 2);
		sram_rsa_delkey(i * 2 + 1);
	}
		for (i = 1; i <= KEK_NUM; i++)
	{
		sram_kek_delkey(i);
	}
	return 0;
}

int32_t export_ras_prikey(uint16_t pubkey_index, uint32_t pubkey_type, uint8_t *rsa_pubkey, uint16_t *pubkey_bits)
{
	uint32_t rtval;
	uint16_t wanted_index;
	
	if (pubkey_index <= SM2_KEYPAIR_NUM || pubkey_index > SM2_KEYPAIR_NUM + RSA_KEYPAIR_NUM)
	{
		return ERR_CIPN_USRKEYERR;
	}
	if (pubkey_type == ASYM_KEYPAIR_CRYPT)
	{
		wanted_index = pubkey_index * 2;
	}
	else
	{
		wanted_index = pubkey_index * 2 + 1;
	}
	
	rtval = sram_ras_get_prikey(wanted_index, rsa_pubkey, pubkey_bits);
	if(rtval) return ERR_CIPN_GETRSAKEY;
	return rtval;
}
int32_t export_ras_pubkey(uint16_t pubkey_index, uint32_t pubkey_type, uint8_t *rsa_pubkey, uint16_t *pubkey_bits)
{
	uint32_t rtval;
	uint16_t wanted_index;
	
	if (pubkey_index <= SM2_KEYPAIR_NUM || pubkey_index > SM2_KEYPAIR_NUM + RSA_KEYPAIR_NUM)
	{
		return ERR_CIPN_USRKEYERR;
	}
	
	if (pubkey_type == ASYM_KEYPAIR_CRYPT)
	{
		wanted_index = pubkey_index * 2;
	}
	else
	{
		wanted_index = pubkey_index * 2 + 1;
	}
	
	rtval = sram_ras_get_pubkey(wanted_index, rsa_pubkey, pubkey_bits);
	
//	print(PRINT_CIPH,"export rsa_pubkey\r\n");
//	printfb(rsa_pubkey,(*pubkey_bits)/4);
	
	if(rtval) return ERR_CIPN_GETRSAKEY;
	return rtval;
}

int32_t export_sm2_pubkey(uint16_t pubkey_index, uint32_t pubkey_type, SM2PublicKey *sm2_pubkey)
{
	uint32_t rtval;
	uint16_t wanted_index;
	SM2PrivateKey dummy_prikey;
	
	if (pubkey_index < 1 || pubkey_index > SM2_KEYPAIR_NUM)
	{
		return ERR_CIPN_USRKEYERR;
	}
	if (pubkey_type == ASYM_KEYPAIR_CRYPT)
	{
		wanted_index = pubkey_index * 2;
	}
	else
	{
		wanted_index = pubkey_index * 2 + 1;
	}
	
	rtval = fpga_sm2_getkey(wanted_index, &dummy_prikey, sm2_pubkey);
	if (rtval)
	{
		return ERR_CIPN_GETSM2KEY;
	}
	
	return 0;
}

int32_t kek_encrypt(uint16_t kek_index, uint16_t ArgId,uint8_t *in_data, uint32_t in_len, uint8_t *out_data, uint32_t *out_len){
	unsigned char key[32]={0};
	unsigned char data_buff[64]={0};
	uint8_t kek_len;
	uint16_t fill_len;
	uint16_t buff_len;
	int ret = sram_kek_getkey(kek_index, &ArgId, key, &kek_len);
	if(ret){
		return ret;
	}
	memcpy(data_buff,in_data,in_len);
	if(kek_len >= 16){
		buff_len = 16;
	}else{
		buff_len = kek_len;
	}
	fill_len = buff_len - in_len % buff_len;
	buff_len = in_len+fill_len;
	memset(data_buff+in_len,fill_len,fill_len);
	Sym_Crypt_WithKey(data_buff, buff_len, key, kek_len, NULL, 0, 
					  ArgId, SYM_ENCRYPTION , SYM_ECB_MODE, out_data);
	//printf_buff_byte(data_buff, 64);
	*out_len = buff_len;
	//printf_buff_byte(out_data, *out_len);
	return 0;
}

int32_t kek_decrypt(uint16_t kek_index, uint16_t ArgId,uint8_t *in_data, uint32_t in_len, uint8_t *out_data, uint32_t *out_len){
	
	unsigned char key[32]={0};
	unsigned char data_buff[64]={0};
	uint8_t kek_len;
	uint16_t buff_len;
	int ret = sram_kek_getkey(kek_index, &ArgId, key, &kek_len);
	if(ret){
		return ret;
	}
	if(kek_len >= 16){
		buff_len = 16;
	}else{
		buff_len = kek_len;
	}
	if((in_len % buff_len)||(in_len > 64))
		return ERR_CIPN_SKEYLEN;
	//SM4_Decrypt(key,out_data,in_data,in_len);
	Sym_Crypt_WithKey(in_data, in_len, key, kek_len, NULL, 0, 
					  ArgId, SYM_DECRYPTION , SYM_ECB_MODE, data_buff);
	//detlet the filled data
	buff_len = data_buff[in_len-1];
	for(int i = 1;i <= buff_len;i++){
		if(data_buff[in_len-i] != buff_len)
			return ERR_CIPN_DECDATA;
	}
	//printf_buff_byte(data_buff, 64);
	//fill_len = data_buff[in_len-1];
	kek_len = in_len-buff_len;
	memcpy(out_data,data_buff,kek_len);

	*out_len = kek_len;
	return 0;
}


void loadusrkey(void){
	int i;
		SM2PrivateKey sm2_prikey = {0};
		SM2PublicKey sm2_pubkey = {0};
	memset((uint8_t *)RSA_KEYPAIR_INFO_ADDR, 0, RSA_KEYPAIR_NUM * 2+2);
	memset((uint8_t *)SESSIONKEY, 0, SKEYNUM);
	memset((uint8_t *)KEK_INFO_ADDR, 0, KEK_NUM);
	memset((uint8_t *)SM2_KEYPAIR_INFO_ADDR, 0, SM2_KEYPAIR_NUM * 2+2);
		
		
/************************************************************
		for (i = 1; i <= 1; i++)
	{
		set_userkey_login(i);
	}		
	 fpga_sm2_getkey(2, &sm2_prikey, &sm2_pubkey);
	printf_buff_byte((uint8_t*)&sm2_prikey,sizeof(SM2PrivateKey));
	printf_buff_byte((uint8_t*)&sm2_pubkey,sizeof(SM2PublicKey));
	for (i = 171; i <= 172; i++)
	{
		set_userkey_login(i);
	}
	memset(&sm2_prikey,0,sizeof(SM2PrivateKey));
	memset(&sm2_pubkey,0,sizeof(SM2PrivateKey));
	fpga_sm2_getkey(2, &sm2_prikey, &sm2_pubkey);
	printf_buff_byte((uint8_t*)&sm2_prikey,sizeof(SM2PrivateKey));
	printf_buff_byte((uint8_t*)&sm2_pubkey,sizeof(SM2PublicKey));
	fpga_sm2_getkey(171*2, &sm2_prikey, &sm2_pubkey);
	printf_buff_byte((uint8_t*)&sm2_prikey,sizeof(SM2PrivateKey));
	printf_buff_byte((uint8_t*)&sm2_pubkey,sizeof(SM2PublicKey));
	fpga_sm2_getkey(172*2, &sm2_prikey, &sm2_pubkey);
	printf_buff_byte((uint8_t*)&sm2_prikey,sizeof(SM2PrivateKey));
	printf_buff_byte((uint8_t*)&sm2_pubkey,sizeof(SM2PublicKey));
	***********************************************************************/
	
	/*****************************************************************  ~~~~~ */
	for (i = 1; i <= SM2_KEYPAIR_NUM + RSA_KEYPAIR_NUM; i++)
	{
		set_userkey_login(i);
	}
	/***************************************************************/
	//����KEK
	for (i = 1; i <= KEK_NUM; i++)
	{
		set_KEKkey_login(i);
	}
}
int revcover_usrkey(){
	int i,ret,ki; //keyindex
	for (i = 1; i <= SM2_KEYPAIR_NUM; i++)
	{
		ki = 2*i;
		if(*(uint8_t *)(SM2_KEYPAIR_INFO_ADDR + ki) == USER_KEYTYPE_SM2){
			ret=write_cipher(i,sizeof(SM2KeyPair),(uint8_t *)SM2_KEYPAIR_DATA_ADDR+ki*sizeof(SM2KeyPair),1);
			if(ret)
				return ret;
		}
		ki = 2*i+1;
		if(*(uint8_t *)(SM2_KEYPAIR_INFO_ADDR + ki) == USER_KEYTYPE_SM2){
			ret=write_cipher(i|SIGN,sizeof(SM2KeyPair),(uint8_t *)SM2_KEYPAIR_DATA_ADDR+ki*sizeof(SM2KeyPair),1);
			if(ret)
				return ret;
			set_userkey_login(i);
		}
	}
	for (i = 0; i <= RSA_KEYPAIR_NUM; i++)
	{
		//����
		ki = 2*i;
		if(*(uint8_t *)(RSA_KEYPAIR_INFO_ADDR + ki) == USER_KEYTYPE_RSA1024){
			//�ļ���ʼ257
			ret=write_cipher(i+SM2_KEYPAIR_NUM+1,RSA1024_BUFFLEN,(uint8_t *)RSA_KEYPAIR_DATA_ADDR+ki*RSA2048_BUFFLEN,1);
			if(ret)
				return ret;
		}
		if(*(uint8_t *)(RSA_KEYPAIR_INFO_ADDR + ki) == USER_KEYTYPE_RSA2048){
			//�ļ���ʼ257
			ret=write_cipher((i+SM2_KEYPAIR_NUM+1)|R_2048,RSA2048_BUFFLEN,(uint8_t *)RSA_KEYPAIR_DATA_ADDR+ki*RSA2048_BUFFLEN,1);
			if(ret)
				return ret;
		}
		//ǩ��
		ki = 2*i+1;
		if(*(uint8_t *)(RSA_KEYPAIR_INFO_ADDR + ki) == USER_KEYTYPE_RSA1024){
			//�ļ���ʼ257
			ret=write_cipher((i+SM2_KEYPAIR_NUM+1)|SIGN,RSA1024_BUFFLEN,(uint8_t *)RSA_KEYPAIR_DATA_ADDR+ki*RSA2048_BUFFLEN,1);
			if(ret)
				return ret;
			set_userkey_login(i);
		}
		if(*(uint8_t *)(RSA_KEYPAIR_INFO_ADDR + ki) == USER_KEYTYPE_RSA2048){
			//�ļ���ʼ257
			ret=write_cipher((i+SM2_KEYPAIR_NUM+1)|SIGN|R_2048,RSA2048_BUFFLEN,(uint8_t *)RSA_KEYPAIR_DATA_ADDR+ki*RSA2048_BUFFLEN,1);
			if(ret)
				return ret;
			set_userkey_login(i);
		}
	}
	return 0;
}
int revcover_kekkey(){
	int i,ret;
	uint8_t cat_data[48] = {0};
	uint8_t message[16] = {0};

	for (i = 1; i <= KEK_NUM; i++)
	{
		if(((*(uint8_t *)(KEK_INFO_ADDR + i))&0X80) != 0){
			message[0]=(*(uint8_t *)(KEK_INFO_ADDR + i))&0X7f;
			if(message[0] > 32)
				return ERR_MANG_RECOVER_LEN;
			memcpy(cat_data,message,16);
			memcpy(cat_data+16,(uint8_t *)KEK_DATA_ADDR+i*KEK_LEN_MAX,message[0]);
			ret=write_kek(i,48,cat_data);
			if(ret)
				return ret;
			//set_KEKkey_login(i);
		}
	}
	return 0;
}
int revcover_key_file(uint16_t KeyType){
	int ret;
	if(KeyType == 0XFFF2){
		ret = revcover_usrkey();
		if(ret) return ret;
	}
	if(KeyType == 0XFFF3){
		ret = revcover_kekkey();
		if(ret) return ret;
	}
	if(KeyType == 0XFFF4){
		ret = revcover_usrkey();
		if(ret) return ret;
		ret = revcover_kekkey();
		if(ret) return ret;
	}
	return 0;
}
int revcover_keypin_file(uint8_t *datapin){
	int i,ret;
	for (i = 1; i <= 150; i++)
	{
		if(datapin[20*i]<8 || datapin[20*i]>16){
			continue;
		}
		ret=write_cipher_access(i,datapin[20*i],(char*)&datapin[20*i+2],1);
		if(ret){
			print(PRINT_CIPH,"WE ciph access err\r\n");
			return ret;
		}
	}
	for (i = 151; i <= SM2_KEYPAIR_NUM+RSA_KEYPAIR_NUM; i++)
	{
		if(datapin[20*(i-150)+3072]<8 || datapin[20*(i-150)+3072]>16){		//pinbuff = 2*3072 ָ��ڶ���3072
			continue;
		}
		ret=write_cipher_access(i,datapin[20*(i-150)+3072],(char*)&datapin[20*(i-150)+3072+2],1);
		if(ret){
			print(PRINT_CIPH,"WE cip err\r\n");
			return ret;
		}
	}
	return 0;
}

//У��keypin������
int check_keypin_index(uint16_t index){
	FRESULT res;
	FIL  file_c;
	uint8_t btr=32+32;				//pin max length is 16
	uint32_t br=0;
	//uint8_t access_len=0;
	uint8_t pin_buff_enc[32+32]={0};
	//uint8_t pin_buff[32]={0};
	char cipher_pin_name[17]= "1:cipher/pin";//12+3+1
	char index_str[4]={0};

	sprintf(index_str,"%d",index);
	strcat(cipher_pin_name,index_str);
	res = f_open(&file_c,cipher_pin_name,FA_READ);
	if(res !=FR_OK)
		return FR_OK;
	res = f_read(&file_c,pin_buff_enc,btr,&br);
	f_close(&file_c);
	if(res != FR_OK)
		return ERR_CIPN_READKEYFILE;
	//print(PRINT_CIPH," read file enc is :\r\r\n");
	//printf_byte(pin_buff_enc,btr);
	
	if(GetUserKeyCheck(pin_buff_enc,btr,&br)){
		return ERR_MANG_CHECKCODE;
	}
	print(PRINT_CIPH," %d",index);
	return FR_OK;
}
//У��keypair������
int check_keypair_index(uint16_t index,uint32_t data_len){
	FRESULT res;
	FIL  file_c;
	uint32_t btr=256;				//pin max length is 16
	uint32_t br=0;
	uint8_t* data_buff = NULL;
	uint8_t* Pdata = NULL;
	//
	char cipher_name[14] = "1:cipher/";//9+3+1
	char index_str[6] = {0};
	sprintf(index_str,"%d",index);
	strcat(cipher_name, index_str);
	res = f_open(&file_c, cipher_name, FA_READ);
	if(res !=FR_OK){
		return 99;
	}
data_buff = pvPortMalloc(data_len+16+32);
Pdata = data_buff;
	for(;;){
		res = f_read(&file_c, Pdata, btr, &br);
		if(res != FR_OK){
			vPortFree(data_buff);
			f_close(&file_c);
			return ERR_CIPN_READKEYFILE;
		}
		if(br == 0)		//�ļ���ȡ����
			break;
		Pdata += br;
		if(Pdata-data_buff >= data_len+32)
			break;
	}
	if(GetUserKeyCheck(data_buff,data_len+32,&br)){
		f_close(&file_c);
		vPortFree(data_buff);
		return ERR_MANG_CHECKCODE;
	}
	f_close(&file_c);
	vPortFree(data_buff);
	
	return 0;
}
//У��keykek������
int check_keykek_index(uint16_t index,uint32_t data_len){
	FRESULT res;
	FIL  file_c;
	uint8_t btr=data_len+32;				//pin max length is 16
	uint32_t br=0;
	//uint8_t access_len=0;
	uint8_t kek_buff_enc[64+32]={0};
	//uint8_t pin_buff[32]={0};
	char kek_name[10]= "1:kek/";//12+3+1
	char index_str[4]={0};

	sprintf(index_str,"%d",index);
	strcat(kek_name,index_str);
	res = f_open(&file_c,kek_name,FA_READ);
	LEAVE_OPEN(res)
	res = f_read(&file_c,kek_buff_enc,btr,&br);
	f_close(&file_c);
	if(res != FR_OK)
		return ERR_CIPN_READKEYFILE;
	print(PRINT_CIPH," %d",index);
	//printf_byte(kek_buff_enc,btr);
	
	if(GetUserKeyCheck(kek_buff_enc,btr,&br)){
		return ERR_MANG_CHECKCODE;
	}
	return FR_OK;
}


int check_keypair(uint16_t keypair_index){
	int32_t rtval;
	uint32_t need_read;
	uint32_t indeed_read;
	SM2KeyPair sm2_keypair; 
	//uint8_t *rsa_keybuff;
	
	if (keypair_index > 0 && keypair_index <= SM2_KEYPAIR_NUM)			//SM2 key
	{
		//set to fpga, even num is encrypt keypair, odd num is sign keypair
		//������Կ��������
		rtval = check_keypair_index(keypair_index, sizeof(SM2KeyPair));
		if (rtval && rtval!=99)
		{
			return -1;
		}
		//ǩ����Կ��������
		rtval = check_keypair_index(keypair_index|SIGN, sizeof(SM2KeyPair));
		if (rtval && rtval!=99)
		{
			return -2;
		}
	}
	else		//RSA key
	{
		rtval = check_keypair_index(keypair_index,RSA1024_BUFFLEN);
		if (rtval)
		{
			rtval = check_keypair_index(keypair_index|R_2048,RSA2048_BUFFLEN);
			if (rtval && rtval!=99)
			{
				return -3;
			}
		}
		rtval = check_keypair_index(keypair_index|SIGN,RSA1024_BUFFLEN);
		if (rtval)
		{
			rtval = check_keypair_index(keypair_index|SIGN|R_2048,RSA2048_BUFFLEN);
			if(rtval && rtval!=99)
			{
				//vPortFree(rsa_keybuff);
				return -4;
			}
		}
		//vPortFree(rsa_keybuff);
	}
	if(99 != rtval)
		print(PRINT_CIPH," %d",keypair_index);
	return 0;
}

//У��key������
int chip_check_keypin(void){
	print(PRINT_CIPH,"keypin:");
	for (uint16_t i = 1; i <= SM2_KEYPAIR_NUM + RSA_KEYPAIR_NUM; i++)
	{
		if(check_keypin_index(i)){
			print(PRINT_CIPH,"\r\n");
			return -1;
		}
	}
	print(PRINT_CIPH,"\r\n");
	return 0;
}
int chip_check_keypair(void){
	print(PRINT_CIPH,"userkey:");
	for (uint16_t i = 1; i <= SM2_KEYPAIR_NUM + RSA_KEYPAIR_NUM; i++)
	{
		if(check_keypair(i)){
			print(PRINT_CIPH,"\r\n");
			return -1;
		}
		
	}
	print(PRINT_CIPH,"\r\n");
	return 0;
}
int chip_check_kek(void){
	print(PRINT_CIPH,"KEK:");
	for (uint16_t i = 1; i <= KEK_NUM; i++){
		check_keykek_index(i,48);
	}
	print(PRINT_CIPH,"\r\n");
	return 0;
}
