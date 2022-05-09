#ifndef __CIPHER_H__
#define	__CIPHER_H__

#include <stdint.h>
#include "fpga_sm2.h"
#include "fpga.h"
#include "mcu_algorithm.h"
#include "devmanage.h"

#define SIGN		0xF000
#define R_2048	0x0800 

#define SKEYNUM  						8192   //会话密钥数目
#define SKEYSIZE  						32
		
#define USER_KEYTYPE_NONE				0
#define USER_KEYTYPE_SM2				1
#define USER_KEYTYPE_RSA1024			2
#define USER_KEYTYPE_RSA2048			3
		
#define KEK_NUM					256		
#define KEK_LEN_MAX			32	
#define SM2_KEYPAIR_LEN sizeof(SM2KeyPair)
#define SM2_KEYPAIR_NUM					256
#define RSA_KEYPAIR_NUM					32
#define RSA_KEYPAIR_INFO_ADDR			0x60046000
#define RSA_KEYPAIR_DATA_ADDR			(RSA_KEYPAIR_INFO_ADDR + RSA_KEYPAIR_NUM*2+2)
#define KEK_INFO_ADDR							(RSA_KEYPAIR_DATA_ADDR + 2*1408*(RSA_KEYPAIR_NUM+1))
#define KEK_DATA_ADDR             (KEK_INFO_ADDR + KEK_NUM+1)
#define SM2_KEYPAIR_INFO_ADDR			(KEK_DATA_ADDR + KEK_LEN_MAX*(KEK_NUM+1))
#define SM2_KEYPAIR_DATA_ADDR			(SM2_KEYPAIR_INFO_ADDR + SM2_KEYPAIR_NUM*2+2)
		
#define ASYM_KEYPAIR_CRYPT				0x00
#define ASYM_KEYPAIR_SIGN					0x01

#define RSA_PRIKEY_LEN(key_bits)		(BIT_TO_BYTE(key_bits) * 11 / 2)

int GenUserKeyCheck(uint8_t* data_buff,uint32_t data_len,uint32_t*OutLen);
int GetUserKeyCheck(uint8_t* data_buff,uint32_t data_len,uint32_t*OutLen);

int change_cipher_access(unsigned short index,unsigned char pin_len, char * pin);
int check_cipher_access(unsigned short index,unsigned char pin_len, char * pin);
int read_cipher_access(unsigned short index,unsigned char *pin_len, char * pin);
int write_cipher_access(unsigned short index,unsigned char pin_len, char * pin,uint8_t force);
int write_cipher(unsigned short index,unsigned short data_len,unsigned char * data,uint8_t force);
int read_cipher(unsigned short index,unsigned int data_len,unsigned int *Byte_read,unsigned char *data);

int32_t GenUsrCiph(unsigned short index,unsigned short type,char *Pin,unsigned short PinLen);
int32_t DelUsrCiph(unsigned short index);

int32_t GenRSA(unsigned char *RSA_CIPH_BUFF,unsigned int key_bits);
int32_t GenKEK(unsigned short index,unsigned short bits);

int32_t DelKEK(unsigned short index);

int32_t Get_Cipher_Num(unsigned char *data);
int32_t Get_cipher_status(unsigned char *data);
int32_t Get_KEK_status(unsigned char *data);

void init_sessionkey(void);
unsigned short read_sessionkey_mcu(unsigned short *len,unsigned char *sesskey,unsigned int index);
unsigned short read_sessionkey_frommcu(unsigned short len,unsigned char *sesskey,unsigned int index);
unsigned short writer_sessionkey_mcufpga(unsigned short len,unsigned char *sesskey,unsigned int *index);
unsigned short destory_sessionkey_mcufpga(unsigned int indexnum,unsigned char *indexdata);

int32_t set_userkey_login(uint16_t keypair_index);
int32_t set_KEKkey_login(uint16_t kek_index);
int32_t clear_userkey_logout(void);

int32_t mcu_sm2_setkey(uint16_t key_index, SM2PrivateKey *pri_key, SM2PublicKey *pub_key);
int32_t mcu_sm2_getkey(uint16_t key_index, SM2PrivateKey *pri_key, SM2PublicKey *pub_key);
int32_t mcu_sm2_delkey(uint16_t key_index);

int32_t export_ras_prikey(uint16_t pubkey_index, uint32_t pubkey_type, uint8_t *rsa_pubkey, uint16_t *pubkey_bits);
int32_t export_ras_pubkey(uint16_t pubkey_index, uint32_t pubkey_type, uint8_t *rsa_pubkey, uint16_t *pubkey_bits);
int32_t export_sm2_pubkey(uint16_t pubkey_index, uint32_t pubkey_type, SM2PublicKey *sm2_pubkey);
int32_t sram_rsa_delkey(uint16_t rsa_index);
int32_t kek_encrypt(uint16_t kek_index, uint16_t ArgId,uint8_t *in_data, uint32_t in_len, uint8_t *out_data, uint32_t *out_len);
int32_t kek_decrypt(uint16_t kek_index, uint16_t ArgId,uint8_t *in_data, uint32_t in_len, uint8_t *out_data, uint32_t *out_len);

void loadusrkey(void);
int revcover_key_file(uint16_t KeyType);
int revcover_keypin_file(uint8_t *datapin);

int chip_check_keypin(void);
int chip_check_keypair(void);
int chip_check_kek(void);

int32_t importkeypair(uint16_t index, uint8_t *indata);
int32_t importkeypair1(uint16_t index_use, uint16_t index_in, uint8_t *indata);
unsigned char query_ciph(uint16_t *ECC_n,uint16_t *RSA1024_n,uint16_t *RSA2048_n);
unsigned char query_kek(uint16_t *KEK_n);
#endif
