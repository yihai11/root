#ifndef INTERNAL_ALG_H
#define INTERNAL_ALG_H

#include "hrng.h"
#include "sm1.h"
#include "sm2.h"
#include "sm3.h"
#include "sm4.h"
#include "aes.h"
#include "des.h"
#include "sha1.h"
#include "sha256.h"
#include "sha384.h"
#include "rsa_keygen.h"
 

#define SYM_ALG_SM1				0x01
#define SYM_ALG_SM4				0x02
#define SYM_ALG_AES				0x03
#define SYM_ALG_DES				0x04
#define SYM_ALG_3DES			0x05

#define HASH_ALG_SM3				0x11
#define HASH_ALG_SHA1				0x12
#define HASH_ALG_SHA256			0x13
#define HASH_ALG_SHA384			0x14
#define HASH_ALG_SHA512			0x15

#define SYM_ENCRYPTION    		1
#define SYM_DECRYPTION    		0
#define SYM_ECB_MODE      		0
#define SYM_CBC_MODE      		1

#define RSA1024_BUFFLEN			704
#define RSA2048_BUFFLEN			1408

//#define SM3_HASH_LEN			32
//#define SHA1_HASH_LEN			20
//#define SHA256_HASH_LEN		32
//#define HASH_BLOCK_LEN		64
//#define HASH_MAX_LEN			32

#define SM3_HASH_LEN   		32
#define SHA1_HASH_LEN   	20
#define SHA256_HASH_LEN   32
#define SHA384_HASH_LEN   64
#define SHA512_HASH_LEN   64
#define HASH_BLOCK_LEN   	64
#define SHA3_BLOCK_LEN    128
#define HASH_MAX_LEN   		64


//RNG, just use the original functions
/*
void hrng_initial(void);
UINT8 get_hrng(UINT8 *hdata,UINT32 byte_len);
*/

//SYM_ALG
INT32 Sym_Crypt_WithKey(UINT8 *in_data, UINT32 in_len, UINT8 *key, UINT32 key_len, UINT8 *iv, UINT32 iv_len, 
					  UINT8 alg_id, UINT8 op_crypt, UINT8 op_mode, UINT8 *out_data);
						
INT32 Sym_Set_Key(UINT8 *key, UINT32 key_len, UINT8 alg_id);

INT32 Sym_Crypt_WithoutKey(UINT8 *in_data, UINT32 in_len, UINT8 *iv, UINT32 iv_len, 
					     UINT8 alg_id, UINT8 op_crypt, UINT8 op_mode, UINT8 *out_data);

//SM2 初始化
void SM2_param_init(ECC_G_STR *p_sm2_para);
INT32 SM2_Sign(ECC_G_STR *p_sm2_para, UINT8 *msg_hash, UINT8 *pri_key, UINT8 *sign_r, UINT8 *sign_s);
INT32 SM2_Verify(ECC_G_STR *p_sm2_para, UINT8 *msg_hash, UINT8 *pub_key, UINT8 *sign_r, UINT8 *sign_s);
INT32 SM2_Encrypt(ECC_G_STR *p_sm2_para, UINT8 *in_data, UINT32 in_len, UINT8 *pub_key, 
				UINT8 *C1, UINT8 *C2, UINT8 *C3);
INT32 SM2_Decrypt(ECC_G_STR *p_sm2_para, UINT8 *pri_key, UINT8 *C1, UINT8 *C2, UINT8 *C3,
				UINT32 data_len, UINT8 *out_data);
				
//生成SM2密钥对
//输入 *p_sm2_pata
//输出	*pri_key,*pub_key_x,*pub_key_y
INT32 SM2_Gen_Keypair(ECC_G_STR *p_sm2_para, UINT8 *pri_key, UINT8 *pub_key_x, UINT8 *pub_key_y);

void SM2_getZ(ECC_G_STR *p_sm2_para, UINT8 *id, UINT16 id_len, UINT8 *pub_x, UINT8 *pub_y, UINT8 *Z);

INT32 SM2_Exchange_Key(ECC_G_STR *p_sm2_para, UINT8 role, UINT8 *pri_key, UINT8 *pub_key_other,
					UINT8 *temp_pri_key, UINT8 *tmep_pub_key, UINT8 *temp_pub_key_other,
					UINT8 *ZA, UINT8 *ZB, UINT32 key_len, UINT8 *ex_key, UINT8 *S1, UINT8 *SA);

// SM3 Alg, just use the original functions
/*
void sm3_hash(UINT8 *pDataIn,UINT32 DataLen,UINT8 *pDigest);
void SM3_initial (SM3_CTX *context);
void SM3_update (SM3_CTX *context, UINT8 *input,UINT32 inputLen);
void SM3_final (UINT8 *digest, SM3_CTX *context);
*/

//SHA256 Alg, just use the original functions
/*
void SHA256_hash(UINT8 *pDataIn,UINT32 DataLen,UINT8 *pDigest);
void SHA256_init (SHA256_CTX *context);
void SHA256_update (SHA256_CTX *context,UINT8 *input,UINT32 inputLen);
void SHA256_final (UINT8 *digest, SHA256_CTX *context);
*/

//RSA
INT32 RSA_Keygen_init(RSA_KEYGEN_G_STR *p_rsa_keygen_str, UINT32 key_bits, UINT8 *init_buff);
INT32 RSA_Gen_Keypair(RSA_KEYGEN_G_STR *p_rsa_keygen_str, UINT32 key_bits);
void RSA_KeyGen_to_Memory(RSA_KEYGEN_G_STR *p_rsa_keygen_str, UINT32 key_bits, UINT8 *keypair_buf);

INT32 RSA_Pubkey_Operation(UINT8 *in_data, UINT32 in_len, UINT32 *e_data, UINT32 e_words, UINT32 *n_data, UINT32 n_words,
						UINT8 *out_data, UINT32 *out_len);
INT32 RSA_Prikey_Operation(UINT8 *in_data, UINT32 in_len, UINT32 *e_data, UINT32 e_words, UINT32 *p_data, UINT32 p_words,
						UINT32 *q_data, UINT32 q_words, UINT32 *dp_data, UINT32 dp_words, UINT32 *dq_data, UINT32 dq_words,
						UINT32* qInv_data, UINT32 qInv_words, UINT8 *out_data, UINT32 *out_len);
INT32 fill_hash_padding(UINT32 hash_block_len,UINT32 data_len, UINT8 *padding_buff, UINT32 *padding_size);
INT32 sha1_with_iv(UINT8 *iv, UINT32 iv_len, UINT8 *in_data, UINT32 data_len, UINT8 *hash, UINT32 *hash_len);
INT32 sha256_with_iv(UINT8 *iv, UINT32 iv_len, UINT8 *in_data, UINT32 data_len, UINT8 *hash, UINT32 *hash_len);
INT32 sha384_with_iv(UINT8 *iv, UINT32 iv_len, UINT8 *in_data, UINT32 data_len, UINT8 *hash, UINT32 *hash_len);
INT32 sha512_with_iv(UINT8 *iv, UINT32 iv_len, UINT8 *in_data, UINT32 data_len, UINT8 *hash, UINT32 *hash_len);

INT32 sm3_with_iv(UINT8 *iv, UINT32 iv_len, UINT8 *in_data, UINT32 data_len, UINT8 *hash, UINT32 *hash_len);
INT32 hmac_one_step(UINT32 hash_algid, UINT8 *hmac_key, UINT32 key_len, UINT8 *in_data, UINT32 data_len, UINT8 *hmac, UINT32 *hmac_len);

#endif

