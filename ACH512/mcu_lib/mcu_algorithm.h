#ifndef __MCU_ALGORITHM_H__
#define __MCU_ALGORITHM_H__
#include "fpga_sm2.h"
#include "rsa_keygen.h"
#include "internal_alg.h"
#include "type_code.h"


#define DG

void printfb(uint8_t *buff, uint32_t len);
unsigned char	get_random_MCU(unsigned char *random_data,unsigned  int data_len);

int MCU_Auth_GenRandom( uint8_t* Random,uint16_t len);
int MCU_Auth_GenAuthCode( uint8_t* Random,uint16_t Randomlen,UINT8 *key,uint8_t* AuthCode);
int MCU_Auth_UkeyAuth( uint8_t* AuthCode,uint16_t AuthCodelen,uint8_t index);

int MUC_RSA_Prikey_Operation_internal(unsigned short pub_key_index, unsigned char *in_data, uint32_t in_len, unsigned char *out_data, unsigned  int *out_len);
int MUC_RSA_Prikey_Operation_external(UINT8 *keypair_buf, unsigned char *in_data, unsigned  int in_len, unsigned char *out_data, unsigned  int *out_len);
int MUC_RSA_Pubkey_Operation_internal(unsigned short pub_key_index, unsigned char *in_data, uint32_t in_len, unsigned char *out_data, unsigned  int *out_len);
int MUC_RSA_Pubkey_Operation_external(UINT8 *keypair_buf, unsigned char *in_data, unsigned  int in_len, unsigned char *out_data, unsigned  int *out_len);	

int MUC_RSA_Pubkey_Enc_internal_pading(unsigned short pub_key_index, unsigned char *in_data, uint32_t in_len, unsigned char *out_data, unsigned  int *out_len);
int MUC_RSA_Pubkey_Enc_external_pading(UINT8 *keypair_buf, unsigned char *in_data, unsigned  int in_len, unsigned char *out_data, unsigned  int *out_len);
int MUC_RSA_Prikey_Dec_internal_pading(unsigned short pub_key_index, unsigned char *in_data, uint32_t in_len, unsigned char *out_data, unsigned  int *out_len);

int32_t mcu_sm2_encrypt_external(SM2PublicKey *pub_key, uint8_t *in_data, uint32_t in_len, uint8_t *out_data, uint32_t *out_len);
int32_t mcu_sm2_decrypt_external(SM2PrivateKey *pri_key, uint8_t *in_data, uint32_t in_len, uint8_t *out_data, uint32_t *out_len);
int32_t mcu_sm2_encrypt_internal(uint16_t pubkeyindex, uint8_t *in_data, uint32_t in_len, uint8_t *out_data, uint32_t *out_len);
int32_t mcu_sm2_decrypt_internal(uint16_t prikeyindex, uint8_t *in_data, uint32_t in_len, uint8_t *out_data, uint32_t *out_len);

int32_t mcu_sm2_sign_external(SM2PrivateKey *pri_key, uint8_t *hash, uint8_t *sign_r, uint8_t *sign_s);
int32_t mcu_sm2_verify_external(SM2PublicKey *pub_key, uint8_t *sign_r, uint8_t *sign_s, uint8_t *hash);
int32_t mcu_sm2_sign_internal(uint16_t prikeyindex, uint8_t *hash, uint8_t *sign_r, uint8_t *sign_s);
int32_t mcu_sm2_verify_internal(uint16_t pubkeyindex, uint8_t *sign_r, uint8_t *sign_s, uint8_t *hash);

int32_t mcu_sm2_agreement_generate_data(uint16_t isk_index, uint32_t key_bits, uint8_t *sponsor_id, uint32_t id_len, SM2PublicKey *sponsor_pubkey, 
												SM2PublicKey *sponsor_tmp_pubkey, void **agreement_handle);
int32_t mcu_sm2_agreement_generate_data_key(uint16_t isk_index, uint32_t key_bits, uint8_t *responsor_id, uint32_t responsor_id_len, 
												uint8_t *sponsor_id, uint32_t sponsor_id_len, SM2PublicKey *sponsor_pubkey, SM2PublicKey *sponsor_temp_pubkey,
												SM2PublicKey *responsor_pubkey, SM2PublicKey *responsor_temp_pubkey, uint32_t *key_index);
int32_t mcu_sm2_agreement_generate_key(uint8_t *response_id, uint32_t response_id_len,SM2PublicKey *response_pubkey, 
												SM2PublicKey *response_temp_pubkey,void *agreement_handle, uint32_t *key_index);

#define RSA_PKCS1_PADDING_SIZE	11
//RSAÇ©ÃûÌî³ä
int adil_padding_add_PKCS1_1(unsigned char *to, int tlen, const unsigned char *from, int flen);
//RSAÇ©ÃûÈ¥Ìî³ä
int adil_padding_check_PKCS1_1(unsigned char *to, int tlen, const unsigned char *from, int flen, int num);
//RSA¼ÓÃÜÌî³ä
int adil_padding_add_PKCS1_2(unsigned char *to, int tlen, const unsigned char *from, int flen);
//RSA¼ÓÃÜÈ¥Ìî³ä
int adil_padding_check_PKCS1_2(unsigned char *to, int tlen, const unsigned char *from, int flen, int num);

#endif
