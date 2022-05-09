#ifndef  __FPGA_SM2_H__
#define	 __FPGA_SM2_H__


#include <stdint.h>
#define SM2_REF_LEN				256
#define SM2_BYTE_LEN			((SM2_REF_LEN + 7) / 8)
#define SM3_HASH_LEN			32

#define SM2_CIPHER_LEN(len)		(2 * SM2_BYTE_LEN + SM3_HASH_LEN + (len))
#define SM2_MAX_ID_LEN			256

extern uint8_t HSMD1_NUM;
//ECC
typedef struct ECCCipher_st {
 unsigned char x[32];
 unsigned char y[32];
 unsigned char M[32];
 unsigned char C[1];
} ECCCipher;

typedef struct ECCrefPublicKey_t
{
	uint8_t x[SM2_BYTE_LEN];
	uint8_t y[SM2_BYTE_LEN];
}
ECCrefPublicKey;

typedef struct SM2PublicKey_t
{
	uint8_t x[SM2_BYTE_LEN];
	uint8_t y[SM2_BYTE_LEN];
} SM2PublicKey;

typedef struct SM2PrivateKey_t
{
	uint8_t K[SM2_BYTE_LEN];
} SM2PrivateKey;

typedef SM2PublicKey SM2Point;

typedef struct {
	uint16_t is_initor; 			//本方是否为发起方标记
	uint16_t key_bits;				//协商密钥长度
	SM2PublicKey  pk;    			//本方公钥
	SM2PrivateKey sk;					//本方私钥
	SM2PublicKey  tmppk; 			//本方临时公钥
	SM2PrivateKey tmpsk;			//本方临时私钥
	uint16_t  idlen; 					//对方ID长度
	uint8_t id[SM2_MAX_ID_LEN];	//对方ID
} AgreementData;
int32_t calcKeyExKDF(uint8_t *K, uint8_t klen, SM2Point *v, uint8_t *Za, uint8_t *Zb);
void FPGA_ApplyRandomData(unsigned char *random_data,unsigned short data_len,unsigned char channel);
int32_t fpga_sm2_setkey(uint16_t key_index, SM2PrivateKey *pri_key, SM2PublicKey *pub_key);
int32_t fpga_sm2_getkey(uint16_t key_index, SM2PrivateKey *pri_key, SM2PublicKey *pub_key);
int32_t fpga_sm2_1510_getkey(uint16_t key_index, SM2PrivateKey *pri_key, SM2PublicKey *pub_key);
int32_t fpga_sm2_delkey(uint16_t key_index);
int32_t fpga_sm2_encrypt_external(SM2PublicKey *pub_key, uint8_t *in_data, uint32_t in_len, uint8_t *out_data, uint32_t *out_len);
int32_t fpga_sm2_encrypt_internal(uint16_t pub_key_index, uint8_t *in_data, uint32_t in_len, uint8_t *out_data, uint32_t *out_len);
int32_t fpga_sm2_decrypt_external(SM2PrivateKey *pri_key, uint8_t *in_data, uint32_t in_len, uint8_t *out_data, uint32_t *out_len);
int32_t fpga_sm2_decrypt_internal(uint32_t pri_key_index, uint8_t *in_data, uint32_t in_len, uint8_t *out_data, uint32_t *out_len);
int32_t fpga_sm2_sign_external(SM2PrivateKey *pri_key, uint8_t *hash, uint8_t *sign_r, uint8_t *sign_s);
int32_t fpga_sm2_sign_internal(uint16_t pri_key_index, uint8_t *hash, uint8_t *sign_r, uint8_t *sign_s);
int32_t fpga_sm2_verify_external(SM2PublicKey *pub_key, uint8_t *sign_r, uint8_t *sign_s, uint8_t *hash);
int32_t fpga_sm2_verify_internal(uint16_t pub_key_index, uint8_t *sign_r, uint8_t *sign_s, uint8_t *hash);

//int32_t fpga_sm2_agreement_generate_data(SM2PrivateKey *self_prikey, SM2PublicKey *self_pubkey, uint32_t key_bits, uint8_t *sponsor_id, uint32_t id_len, SM2PublicKey *sponsor_pubkey, SM2PublicKey *sponsor_tmp_pubkey, void **agreement_handle);
int32_t fpga_sm2_agreement_generate_data(uint16_t isk_index, uint32_t key_bits, uint8_t *sponsor_id, uint32_t id_len, SM2PublicKey *sponsor_pubkey, SM2PublicKey *sponsor_tmp_pubkey, void **agreement_handle);
int32_t fpga_sm2_agreement_generate_data_key(uint16_t isk_index, uint32_t key_bits, uint8_t *responsor_id, uint32_t responsor_id_len, 
//int32_t fpga_sm2_agreement_generate_data_key(SM2PrivateKey *self_prikey, SM2PublicKey *self_pubkey, uint32_t key_bits, uint8_t *responsor_id, uint32_t responsor_id_len, 
												uint8_t *sponsor_id, uint32_t sponsor_id_len, SM2PublicKey *sponsor_pubkey, SM2PublicKey *sponsor_temp_pubkey,
												SM2PublicKey *responsor_pubkey, SM2PublicKey *responsor_temp_pubkey, uint32_t *key_index);
int32_t fpga_sm2_agreement_generate_key(uint8_t *response_id, uint32_t response_id_len, 
										SM2PublicKey *response_pubkey, SM2PublicKey *response_temp_pubkey, 
										void *agreement_handle, uint32_t *key_index);

int32_t fpga_ssx1510_sign_external(SM2PrivateKey *pri_key, uint8_t *hash, uint8_t *sign_r, uint8_t *sign_s);
int32_t fpga_ssx1510_verify_external(SM2PublicKey *pub_key, uint8_t *sign_r, uint8_t *sign_s, uint8_t *hash);
int32_t fpga_ssx1510_gen_keypair(SM2PrivateKey *pri_key, SM2PublicKey *pub_key);



#define SM2_BITS				256
// 类型间长度转换
#define BIT_TO_BYTE(bits)		(((bits) +7) /8)
#define BYTE_TO_BIT(byte)		((byte) *8)
#define KB_TO_BYTE(KB)			((KB) *1024)

#define	GENE_LEN				32
#define	RESULT_LEN				16

#define	SIGNATURE_MODE			0x00
#define	VERIFY_MODE				0x01
#define	CALCULATE_MODE			0x02
#define	OTHER_MODE				0x03

#pragma pack(1)
typedef struct {
	unsigned char p[BIT_TO_BYTE(SM2_BITS)];
	unsigned char a[BIT_TO_BYTE(SM2_BITS)];
	unsigned char b[BIT_TO_BYTE(SM2_BITS)];
	unsigned char x[BIT_TO_BYTE(SM2_BITS)];
	unsigned char y[BIT_TO_BYTE(SM2_BITS)];
	unsigned char n[BIT_TO_BYTE(SM2_BITS)];
} SM2Group;

typedef struct {
	SM2PublicKey pk;
	SM2PrivateKey sk;
} SM2KeyPair; 

typedef struct {
	unsigned char r[BIT_TO_BYTE(SM2_BITS)];
	unsigned char s[BIT_TO_BYTE(SM2_BITS)];
} SM2Signature;

typedef struct {
	unsigned int len;
	unsigned char n[1];
} BigNumber;
#pragma pack()


#endif
