#include <stdint.h>
#include "internal_alg.h"
#include "freertos.h"
#include "type_code.h"

#define SM2_CURVE_WORD			8
#define RSA_MUL_MODE			0x01
#define RSA_ME_MODE				0x30

#define BYTE_TO_BIT(byte)		(byte * 8)
#define BIT_TO_BYTE(bit)		((bit + 7) / 8)
#define	BYTE_TO_WORD(byte)		((byte + 3) / 4)
#define WORD_TO_BYTE(word)		(word * 4)
#define BIT_TO_WORD(bit)		((((bit + 7) / 8) + 3) / 4)
#define BYTE_TO_DWORD(byte)		((byte + 7) / 8)
#define BYTE_TO_QWORD(byte)		((byte + 15) / 16)
#define QWORD_TO_BYTE(qword)	(qword * 16)
#define BYTE_SWAP_32(a)			((a << 24) | ((a & 0x0000ff00) << 8) | ((a & 0x00ff0000) >> 8) | (a >> 24))
#define BYTE_SWAP_16(a)			((a & 0xff00) >> 8 | (a & 0x00ff) << 8)

#define PRINT_INALG 2
//SM2 Curve parameters
static const UINT32 a_Array[8] = {0xFFFFFFFE,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0x00000000,0xFFFFFFFF,0xFFFFFFFC};
static const UINT32 b_Array[8] = {0x28E9FA9E,0x9D9F5E34,0x4D5A9E4B,0xCF6509A7,0xF39789F5,0x15AB8F92,0xDDBCBD41,0x4D940E93};
static const UINT32 P_Array[8] = {0xFFFFFFFE,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0x00000000,0xFFFFFFFF,0xFFFFFFFF};
static const UINT32 N_Array[8] = {0xFFFFFFFE,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0x7203DF6B,0x21C6052B,0x53BBF409,0x39D54123};
static const UINT32 BaseX_Array[8] = {0x32C4AE2C,0x1F198119,0x5F990446,0x6A39C994,0x8FE30BBF,0xF2660BE1,0x715A4589,0x334C74C7};
static const UINT32 BaseY_Array[8] = {0xBC3736A2,0xF4F6779C,0x59BDCEE3,0x6B692153,0xD0A9877C,0xC62A4740,0x02DF32E5,0x2139F0A0};

//SYM_ALG
INT32 Sym_Crypt_WithKey(UINT8 *in_data, UINT32 in_len, UINT8 *key, UINT32 key_len, UINT8 *iv, UINT32 iv_len, 
					  UINT8 alg_id, UINT8 op_crypt, UINT8 op_mode, UINT8 *out_data)
{
	INT32 rtval;
	UINT8 internal_key[64];
	UINT8 asemode = 0;

	memset(internal_key, 0, 64);
	memcpy(internal_key, key, key_len);

	switch (alg_id)
	{
	case SYM_ALG_SM1:
		sm1_set_key_u8(internal_key, SM1_INTERPRAR, SM1_SWAP_ENABLE);
		rtval = sm1_crypt_u8(in_data, out_data, BYTE_TO_QWORD(in_len), op_crypt, op_mode, iv, SM1_NORMAL_MODE);
		rtval = (rtval == SM1_PASS ? 0 : -1);
		break;
	case SYM_ALG_SM4:
		sm4_set_key_u8(internal_key, SM4_SWAP_ENABLE);
		rtval = sm4_crypt_u8(in_data, out_data, BYTE_TO_QWORD(in_len), op_crypt, op_mode, iv, SM4_NORMAL_MODE);
		rtval = (rtval == SM4_PASS ? 0 : -1);
		break;
	case SYM_ALG_AES:
		if(key_len == 24){
			asemode = AES_KEY_192;
		}
		if(key_len == 32){
			asemode = AES_KEY_256;
		}
		if(key_len == 16){
			asemode = AES_KEY_128;
		}
		aes_set_key((UINT32 *)key, asemode, AES_SWAP_ENABLE);//BYTE_TO_WORD(key_len)
		rtval = aes_crypt((UINT32 *)in_data, (UINT32 *)out_data, BYTE_TO_QWORD(in_len), op_crypt, op_mode, (UINT32 *)iv, AES_NORMAL_MODE);
		rtval = (rtval == AES_PASS ? 0 : -1);
		break;
	case SYM_ALG_DES:
		if (op_crypt == SYM_ENCRYPTION)
		{
			op_crypt = DES_ENCRYPTION;
		}
		else
		{
			op_crypt = DES_DECRYPTION;
		}
		des_set_key(DES_SINGLE_KEY, (UINT32 *)key, DES_SWAP_ENABLE);
		rtval = des_crypt((UINT32 *)in_data, (UINT32 *)out_data, BYTE_TO_DWORD(in_len), op_crypt, op_mode, (UINT32 *)iv, DES_NORMAL_MODE);
		rtval = (rtval == DES_PASS ? 0 : -1);
		break;
	case SYM_ALG_3DES:
		if (op_crypt == SYM_ENCRYPTION)
		{
			op_crypt = DES_ENCRYPTION;
		}
		else
		{
			op_crypt = DES_DECRYPTION;
		}
		des_set_key(DES_TRIPLE_KEY, (UINT32 *)key, DES_SWAP_ENABLE);
		rtval = des_crypt((UINT32 *)in_data, (UINT32 *)out_data, BYTE_TO_DWORD(in_len), op_crypt, op_mode, (UINT32 *)iv, DES_NORMAL_MODE);
		rtval = (rtval == DES_PASS ? 0 : -1);
		break;		
	default:
		print(PRINT_INALG,"Sym_Cry_WithKey alg_id err\r\n");
		return -1;
	}

	return rtval;
}

INT32 Sym_Set_Key(UINT8 *key, UINT32 key_len, UINT8 alg_id)
{
	UINT8 internal_key[64];	
	UINT8 asemode = 0;
	memset(internal_key, 0, 64);
	memcpy(internal_key, key, key_len);

	switch (alg_id)
	{
	case SYM_ALG_SM1:
		sm1_set_key_u8(internal_key, SM1_INTERPRAR, SM1_SWAP_ENABLE);
		break;
	case SYM_ALG_SM4:
		sm4_set_key_u8(internal_key, SM4_SWAP_ENABLE);
		break;
	case SYM_ALG_AES:
		if(key_len == 24){
			asemode = AES_KEY_192;
		}
		if(key_len == 32){
			asemode = AES_KEY_256;
		}
		if(key_len == 16){
			asemode = AES_KEY_128;
		}
		aes_set_key((UINT32 *)key, asemode, AES_SWAP_ENABLE);
		break;
	case SYM_ALG_DES:
		des_set_key(DES_SINGLE_KEY, (UINT32 *)key, DES_SWAP_ENABLE);
		break;
	case SYM_ALG_3DES:
		des_set_key(DES_TRIPLE_KEY, (UINT32 *)key, DES_SWAP_ENABLE);
		break;
	default:
		print(PRINT_INALG,"Sym_Set_Key alg_id err\r\n");
		return -1;
	}

	return 0;
}

INT32 Sym_Crypt_WithoutKey(UINT8 *in_data, UINT32 in_len, UINT8 *iv, UINT32 iv_len, 
					     UINT8 alg_id, UINT8 op_crypt, UINT8 op_mode, UINT8 *out_data)
{
	INT32 rtval;

	switch (alg_id)
	{
	case SYM_ALG_SM1:
		rtval = sm1_crypt_u8(in_data, out_data, BYTE_TO_QWORD(in_len), op_crypt, op_mode, iv, SM1_NORMAL_MODE);
		rtval = (rtval == SM1_PASS ? 0 : -1);
		break;
	case SYM_ALG_SM4:
		rtval = sm4_crypt_u8(in_data, out_data, BYTE_TO_QWORD(in_len), op_crypt, op_mode, iv, SM4_NORMAL_MODE);
		rtval = (rtval == SM4_PASS ? 0 : -1);
		break;
	case SYM_ALG_AES:
		rtval = aes_crypt((UINT32 *)in_data, (UINT32 *)out_data, BYTE_TO_QWORD(in_len), op_crypt, op_mode, (UINT32 *)iv, AES_NORMAL_MODE);
		rtval = (rtval == AES_PASS ? 0 : -1);
		break;
	default:
		print(PRINT_INALG,"Sym_Crypt_WithKey alg_id err\r\n");
		return -1;
	}

	return rtval;
}

//SM2
void SM2_param_init(ECC_G_STR *p_sm2_para)
{
	static UINT32 has_inited = 0;
	static UINT32 init_a[SM2_CURVE_WORD];
	static UINT32 init_b[SM2_CURVE_WORD];
	static UINT32 init_P[SM2_CURVE_WORD];
	static UINT32 init_N[SM2_CURVE_WORD];
	static UINT32 init_X[SM2_CURVE_WORD];
	static UINT32 init_Y[SM2_CURVE_WORD];
	
	if (has_inited == 0)
	{
		ecc_memcpy(init_a, a_Array, SM2_CURVE_WORD);
		ecc_memcpy(init_b, b_Array, SM2_CURVE_WORD);
		ecc_memcpy(init_P, P_Array, SM2_CURVE_WORD);
		ecc_memcpy(init_N, N_Array, SM2_CURVE_WORD);
		ecc_memcpy(init_X, BaseX_Array, SM2_CURVE_WORD);
		ecc_memcpy(init_Y, BaseY_Array, SM2_CURVE_WORD);
		
		sm2_swap_array(init_a, SM2_CURVE_WORD);
		sm2_swap_array(init_b, SM2_CURVE_WORD);
		sm2_swap_array(init_P, SM2_CURVE_WORD);
		sm2_swap_array(init_N, SM2_CURVE_WORD);
		sm2_swap_array(init_X, SM2_CURVE_WORD);
		sm2_swap_array(init_Y, SM2_CURVE_WORD);
		
		has_inited = 1;
	}
	
	ECC_para_initial(p_sm2_para, SM2_CURVE_WORD, init_P, init_a, init_b, init_N, init_X, init_Y);
}

void SM2_getZ(ECC_G_STR *p_sm2_para, UINT8 *id, UINT16 id_len, UINT8 *pub_x, UINT8 *pub_y, UINT8 *Z)
{
	UINT16 i;
	UINT16 id_len_be;
	SM3_CTX sm3_ctx;
	UINT32 temp_buf[SM2_CURVE_WORD];
		
	SM3_initial(&sm3_ctx);
	//id_len & id
	id_len_be = BYTE_SWAP_16((BYTE_TO_BIT(id_len)));	
	SM3_update(&sm3_ctx, (UINT8 *)&id_len_be, sizeof(UINT16));
	SM3_update(&sm3_ctx, id, id_len);
	//a_Array
	ecc_memcpy(temp_buf, a_Array, SM2_CURVE_WORD);
	for (i = 0; i < SM2_CURVE_WORD; i++)
	{
		temp_buf[i] = BYTE_SWAP_32(temp_buf[i]);
	}
	SM3_update(&sm3_ctx, (UINT8 *)temp_buf, SM2_CURVE_WORD << 2);
	//b_Array
	ecc_memcpy(temp_buf, b_Array, SM2_CURVE_WORD);
	for (i = 0; i < SM2_CURVE_WORD; i++)
	{
		temp_buf[i] = BYTE_SWAP_32(temp_buf[i]);
	}
	SM3_update(&sm3_ctx, (UINT8 *)temp_buf, SM2_CURVE_WORD << 2);
	//BaseX_Array
	ecc_memcpy(temp_buf, BaseX_Array, SM2_CURVE_WORD);
	for (i = 0; i < SM2_CURVE_WORD; i++)
	{
		temp_buf[i] = BYTE_SWAP_32(temp_buf[i]);
	}
	SM3_update(&sm3_ctx, (UINT8 *)temp_buf, SM2_CURVE_WORD << 2);
	//BaseY_Array
	ecc_memcpy(temp_buf, BaseY_Array, SM2_CURVE_WORD);
	for (i = 0; i < SM2_CURVE_WORD; i++)
	{
		temp_buf[i] = BYTE_SWAP_32(temp_buf[i]);
	}
	SM3_update(&sm3_ctx, (UINT8 *)temp_buf, SM2_CURVE_WORD << 2);
	//Pub_x
	SM3_update(&sm3_ctx, pub_x, SM2_CURVE_WORD << 2);
	//Pub_y
	SM3_update(&sm3_ctx, pub_y, SM2_CURVE_WORD << 2);

	SM3_final(Z, &sm3_ctx);
}

INT32 SM2_Sign(ECC_G_STR *p_sm2_para, UINT8 *msg_hash, UINT8 *pri_key, UINT8 *sign_r, UINT8 *sign_s)
{
	INT32 rtval;
	MATH_G_STR math_str;
//	UINT16 sm2len = WORD_TO_BYTE(SM2_CURVE_WORD);
//	UINT8 msg_hashtmp[WORD_TO_BYTE(SM2_CURVE_WORD)];
//	UINT8 pri_keytmp[WORD_TO_BYTE(SM2_CURVE_WORD)];
//	memcpy(msg_hash,msg_hash,sm2len);
//	memcpy(pri_key,pri_key,sm2len);

//	reverse_memory(pri_key, sm2len);
//	reverse_memory(pri_key, sm2len);
//	reverse_memory(pri_key, sm2len);
//	reverse_memory(pri_key, sm2len);
	
	rtval = sm2_sign(p_sm2_para, &math_str, msg_hash, pri_key, sign_r, sign_s, SM2_NORMAL);
	rtval = (rtval == 0 ? 0 : -1);

	return rtval;
}

INT32 SM2_Verify(ECC_G_STR *p_sm2_para, UINT8 *msg_hash, UINT8 *pub_key, UINT8 *sign_r, UINT8 *sign_s)
{
	INT32 rtval;
	MATH_G_STR math_str;

	rtval = sm2_verify(p_sm2_para, &math_str, msg_hash, pub_key, sign_r, sign_s);
	rtval = (rtval == 0 ? 0 : -1);

	return rtval;
}

INT32 SM2_Encrypt(ECC_G_STR *p_sm2_para, UINT8 *in_data, UINT32 in_len, UINT8 *pub_key, 
				UINT8 *C1, UINT8 *C2, UINT8 *C3)
{
	INT32 rtval;
	SM2_CRYPT_CTX sm2_ctx;
	SM3_CTX sm3_ctx;

	rtval = sm2_encrypt(p_sm2_para, &sm2_ctx, &sm3_ctx, in_data, in_len, pub_key, C1, C2, C3);
	rtval = (rtval == 0 ? 0 : -1);

	return rtval;
}

INT32 SM2_Decrypt(ECC_G_STR *p_sm2_para, UINT8 *pri_key, UINT8 *C1, UINT8 *C2, UINT8 *C3,
				UINT32 data_len, UINT8 *out_data)
{
	INT32 rtval;
	SM2_CRYPT_CTX sm2_ctx;
	SM3_CTX sm3_ctx;

	rtval = sm2_decrypt(p_sm2_para, &sm2_ctx, &sm3_ctx, pri_key, C1, C2, C3, data_len, out_data, SM2_NORMAL);
	rtval = (rtval == 0 ? 0 : -1);

	return rtval;
}

INT32 SM2_Gen_Keypair(ECC_G_STR *p_sm2_para, UINT8 *pri_key, UINT8 *pub_key_x, UINT8 *pub_key_y)
{
	INT32 rtval;

	rtval = ECDSA_keypair(p_sm2_para, (UINT32 *)pri_key, (UINT32 *)pub_key_x, (UINT32 *)pub_key_y);
	if (rtval)
	{
		return -1;
	}
	reverse_memory(pri_key, WORD_TO_BYTE(SM2_CURVE_WORD));
	reverse_memory(pub_key_x, WORD_TO_BYTE(SM2_CURVE_WORD));
	reverse_memory(pub_key_y, WORD_TO_BYTE(SM2_CURVE_WORD));

	return 0;
}

INT32 SM2_Exchange_Key(ECC_G_STR *p_sm2_para, UINT8 role, UINT8 *pri_key, UINT8 *pub_key_other,
					UINT8 *temp_pri_key, UINT8 *tmep_pub_key, UINT8 *temp_pub_key_other,
					UINT8 *ZA, UINT8 *ZB, UINT32 key_len, UINT8 *ex_key, UINT8 *S1, UINT8 *SA)
{
	INT32 rtval;

	rtval = sm2_Exchange_Key(p_sm2_para, role, pri_key, pub_key_other, temp_pri_key, tmep_pub_key, temp_pub_key_other, ZA, ZB, key_len, ex_key, S1, SA);
	rtval = (rtval == 0 ? 0 : -1);

	return rtval;
}

//RSA
INT32 RSA_Keygen_init(RSA_KEYGEN_G_STR *p_rsa_keygen_str, UINT32 key_bits, UINT8 *init_buff)
{
	UINT32 key_words;
	UINT32 key_hwords;

	if (init_buff == NULL)
	{
		print(PRINT_INALG,"RSA_kgen_ini buff NULL\r\n");
		return -1;
	}

	key_words = BIT_TO_WORD(key_bits);
	key_hwords = (key_words + 1) / 2;
	p_rsa_keygen_str->RSA_n    = ((UINT32 *)init_buff);
	p_rsa_keygen_str->RSA_e    = ((UINT32 *)init_buff + (key_words));
	p_rsa_keygen_str->RSA_d    = ((UINT32 *)init_buff + 2 * (key_words));
	p_rsa_keygen_str->RSA_p    = ((UINT32 *)init_buff + 3 * (key_words));
	p_rsa_keygen_str->RSA_q    = ((UINT32 *)init_buff + 3 * (key_words) + (key_hwords));
	p_rsa_keygen_str->RSA_dp   = ((UINT32 *)init_buff + 4 * (key_words));
	p_rsa_keygen_str->RSA_dq   = ((UINT32 *)init_buff + 4 * (key_words) + (key_hwords));
	p_rsa_keygen_str->RSA_qInv = ((UINT32 *)init_buff + 5 * (key_words));

	reverse_memory((UINT8 *)p_rsa_keygen_str->RSA_n, key_words * 4);
	reverse_memory((UINT8 *)p_rsa_keygen_str->RSA_d, key_words * 4);
	reverse_memory((UINT8 *)p_rsa_keygen_str->RSA_e, key_words * 4);
	reverse_memory((UINT8 *)p_rsa_keygen_str->RSA_p, key_words * 2);
	reverse_memory((UINT8 *)p_rsa_keygen_str->RSA_q, key_words * 2);
	reverse_memory((UINT8 *)p_rsa_keygen_str->RSA_dp, key_words * 2);
	reverse_memory((UINT8 *)p_rsa_keygen_str->RSA_dq, key_words * 2);
	reverse_memory((UINT8 *)p_rsa_keygen_str->RSA_qInv, key_words * 2);
	
	return 0;
}

//INT32 RSA_Gen_Keypair(RSA_KEYGEN_G_STR *p_rsa_keygen_str, UINT32 key_bits, UINT8 *keypair_buf)
INT32 RSA_Gen_Keypair(RSA_KEYGEN_G_STR *p_rsa_keygen_str, UINT32 key_bits)
{
	INT32 rtval;
//	UINT8 *ptr;
//	UINT32 offset;
	UINT32 key_words;
	MATH_G_STR math_str;

	key_words = BIT_TO_WORD(key_bits);
	p_rsa_keygen_str->RSA_e[0] = 0x10001;
	rtval = RSA_keygen_CRT(p_rsa_keygen_str, &math_str, key_words);
	if (rtval != 0)
	{
		print(PRINT_INALG,"RSA_keygen_CRT err\r\n");
		return -1;
	}

	return 0;
}

void RSA_KeyGen_to_Memory(RSA_KEYGEN_G_STR *p_rsa_keygen_str, UINT32 key_bits, UINT8 *keypair_buf)
{
	UINT32 key_words;
	UINT8 *ptr;

	key_words = BIT_TO_WORD(key_bits);
	ptr = keypair_buf;
	memcpy(ptr, (UINT8 *)p_rsa_keygen_str->RSA_n, key_words * 4);
	reverse_memory(ptr, key_words * 4);
	ptr += key_words * 4;
	memcpy(ptr, (UINT8 *)p_rsa_keygen_str->RSA_e, key_words * 4);
	reverse_memory(ptr, key_words * 4);
	ptr += key_words * 4;
	memcpy(ptr, (UINT8 *)p_rsa_keygen_str->RSA_d, key_words * 4);
	reverse_memory(ptr, key_words * 4);
	ptr += key_words * 4;
	memcpy(ptr, (UINT8 *)p_rsa_keygen_str->RSA_p, key_words * 2);
	reverse_memory(ptr, key_words * 2);
	ptr += key_words * 2;
	memcpy(ptr, (UINT8 *)p_rsa_keygen_str->RSA_q, key_words * 2);
	reverse_memory(ptr, key_words * 2);
	ptr += key_words * 2;
	memcpy(ptr, (UINT8 *)p_rsa_keygen_str->RSA_dp, key_words * 2);
	reverse_memory(ptr, key_words * 2);
	ptr += key_words * 2;
	memcpy(ptr, (UINT8 *)p_rsa_keygen_str->RSA_dq, key_words * 2);
	reverse_memory(ptr, key_words * 2);
	ptr += key_words * 2;
	memcpy(ptr, (UINT8 *)p_rsa_keygen_str->RSA_qInv, key_words * 2);
	reverse_memory(ptr, key_words * 2);
	ptr += key_words * 2;
}

INT32 RSA_Pubkey_Operation(UINT8 *in_data, UINT32 in_len, UINT32 *e_data, UINT32 e_words, UINT32 *n_data, UINT32 n_words,
						UINT8 *out_data, UINT32 *out_len)
{
	UINT8 out_word;
	INT32 rtval;
	UINT8 *tmp_data;

	tmp_data = pvPortMalloc(in_len);
	if (tmp_data == NULL)
	{
		print(PRINT_INALG,"RSA_Pub_OP malloc err\r\n");
		return -1;
	}
	memcpy(tmp_data, in_data, in_len);
	reverse_memory(tmp_data, in_len);
	
	rtval = rsa_mul_me((UINT32 *)tmp_data, BYTE_TO_WORD(in_len), e_data, e_words, n_data, n_words,
			(UINT32 *)out_data, &out_word, RSA_ME_MODE);
	if (rtval != 0)
	{
		print(PRINT_INALG,"rsa_mul_me err\r\n");
		vPortFree(tmp_data);
		return  -2;
	}
	vPortFree(tmp_data);
	
	*out_len = WORD_TO_BYTE(out_word);
	reverse_memory(out_data, *out_len);

	return 0;
}

INT32 RSA_Prikey_Operation(UINT8 *in_data, UINT32 in_len, UINT32 *e_data, UINT32 e_words, UINT32 *p_data, UINT32 p_words,
						UINT32 *q_data, UINT32 q_words, UINT32 *dp_data, UINT32 dp_words, UINT32 *dq_data, UINT32 dq_words,
						UINT32* qInv_data, UINT32 qInv_words, UINT8 *out_data, UINT32 *out_len)
{
	UINT8 out_word;
	INT32 rtval;
	RSA_G_STR rsa_str;
	MATH_G_STR math_str;
	UINT8 *tmp_data;

	tmp_data = pvPortMalloc(in_len);
	if (tmp_data == NULL)
	{
		print(PRINT_INALG,"RSA_Pub_OP malloc err\r\n");
		return -1;
	}
	memcpy(tmp_data, in_data, in_len);
	reverse_memory(tmp_data, in_len);
	
	rtval =  rsa_decrypt_CRT((UINT32 *)tmp_data, BYTE_TO_WORD(in_len), p_data, p_words, q_data, q_words,
							dp_data, dp_words, dq_data, dq_words, qInv_data, qInv_words,
							(UINT32 *)out_data, &out_word, &rsa_str, &math_str, e_data, e_words, RSA_NORMAL);
	if (rtval != 0)
	{
		print(PRINT_INALG,"rsa_dec_CRT err\r\n");
		vPortFree(tmp_data);
		return -2;
	}
	vPortFree(tmp_data);

	*out_len = WORD_TO_BYTE(out_word);
	reverse_memory(out_data, *out_len);

	return 0;
}


INT32 fill_hash_padding(UINT32 hash_block_len, UINT32 data_len, UINT8 *padding_buff, UINT32 *padding_size)
{
	UINT32 left_size;
	UINT32 size_buff_len;
	uint64_t fill_padding_size;
//	UINT8 padding_size_buff[16];

//	left_size = data_len % HASH_BLOCK_LEN;
//	if (HASH_BLOCK_LEN - 8 < left_size)
//	{
//		*padding_size = HASH_BLOCK_LEN * 2 - left_size;
//	}
//	else
//	{
//		*padding_size = HASH_BLOCK_LEN - left_size;
//	}

//	memset(padding_buff, 0, *padding_size);
//	padding_buff[0] = 0x80;
//	fill_padding_size = ((uint64_t)(data_len * 8));
//	reverse_memory((UINT8 *)&fill_padding_size, 8);
//	memcpy(padding_buff + *padding_size - 8, &fill_padding_size, sizeof(UINT64));
	
	left_size = data_len % hash_block_len;
	if (hash_block_len == HASH_BLOCK_LEN)
	{
		size_buff_len = 8;
	}
	else if (hash_block_len == SHA3_BLOCK_LEN)
	{
		size_buff_len = 16;
	}
	
	if (hash_block_len - size_buff_len < left_size)
	{
		*padding_size = hash_block_len * 2 - left_size;
	}
	else
	{
		*padding_size = hash_block_len - left_size;
	}

	memset(padding_buff, 0, *padding_size);
	padding_buff[0] = 0x80;
	fill_padding_size = ((uint64_t)(data_len * 8));
	reverse_memory((UINT8 *)&fill_padding_size, sizeof(uint64_t));
	memcpy(padding_buff + *padding_size - sizeof(uint64_t), &fill_padding_size, sizeof(uint64_t));

	return 0;
}


INT32 sm3_with_iv(UINT8 *iv, UINT32 iv_len, UINT8 *in_data, UINT32 data_len, UINT8 *hash, UINT32 *hash_len)
{
	INT32 i;
	SM3_CTX sm3_ctx;
	
	if (iv == NULL && iv_len != 0)
	{
		return ERR_CIPN_INDEXLEN;
	}
	else if (iv != NULL && iv_len != SM3_HASH_LEN)
	{
		return ERR_CIPN_INDEXLEN;
	}
	
	if (data_len % HASH_BLOCK_LEN != 0)
	{
		return ERR_CIPN_INDEXLEN;
	}

	if (iv != NULL)
	{
		memset(&sm3_ctx, 0, sizeof(SM3_CTX));
		memcpy(sm3_ctx.state, iv, iv_len);
		for (i = 0; i < SM3_HASH_LEN / 4;  i++)
		{
			sm3_ctx.state[i] = SM3_SWAP32(sm3_ctx.state[i]); 
		}
	}
	else
	{
		SM3_initial(&sm3_ctx);
	}
	
	SM3_update(&sm3_ctx, in_data, data_len);
	for (i = 0; i < SM3_HASH_LEN / 4;  i++)
	{
		sm3_ctx.state[i] = SM3_SWAP32(sm3_ctx.state[i]); 
	}
	memcpy(hash, sm3_ctx.state, SM3_HASH_LEN);
	*hash_len = SM3_HASH_LEN;
	return 0;
}

INT32 sha1_with_iv(UINT8 *iv, UINT32 iv_len, UINT8 *in_data, UINT32 data_len, UINT8 *hash, UINT32 *hash_len)
{
	INT32 i;
	SHA1_CTX sha1_ctx;
	
	if (iv == NULL && iv_len != 0)
	{
		return ERR_CIPN_INDEXLEN;
	}
	else if (iv != NULL && iv_len != SHA1_HASH_LEN)
	{
		return ERR_CIPN_INDEXLEN;
	}
	
	if (data_len % HASH_BLOCK_LEN != 0)
	{
		return ERR_CIPN_INDEXLEN;
	}
	
	if (iv != NULL)
	{
		memset(&sha1_ctx, 0, sizeof(SHA1_CTX));
		memcpy(sha1_ctx.state, iv, iv_len);
		for (i = 0; i < SHA1_HASH_LEN / 4;  i++)
		{
			sha1_ctx.state[i] = SM3_SWAP32(sha1_ctx.state[i]); 
		}
	}
	else
	{
		SHA1_init(&sha1_ctx);
	}
	
	SHA1_update(&sha1_ctx, in_data, data_len);
	for (i = 0; i < SHA1_HASH_LEN / 4;  i++)
	{
		sha1_ctx.state[i] = SM3_SWAP32(sha1_ctx.state[i]); 
	}
	memcpy(hash, sha1_ctx.state, SHA1_HASH_LEN);
	*hash_len = SHA1_HASH_LEN;
	
	return 0;
}

INT32 sha256_with_iv(UINT8 *iv, UINT32 iv_len, UINT8 *in_data, UINT32 data_len, UINT8 *hash, UINT32 *hash_len)
{
	INT32 i;
	SHA256_CTX sha256_ctx;
	
	if (iv == NULL && iv_len != 0)
	{
		return ERR_CIPN_INDEXLEN;
	}
	else if (iv != NULL && iv_len != SHA256_HASH_LEN)
	{
		return ERR_CIPN_INDEXLEN;
	}
	
	if (data_len % HASH_BLOCK_LEN != 0)
	{
		return ERR_CIPN_INDEXLEN;
	}
	
	if (iv != NULL)
	{
		memset(&sha256_ctx, 0, sizeof(SHA256_CTX));
		memcpy(sha256_ctx.state, iv, iv_len);
		for (i = 0; i < SHA256_HASH_LEN / 4;  i++)
		{
			sha256_ctx.state[i] = SM3_SWAP32(sha256_ctx.state[i]); 
		}
	}
	else
	{
		SHA256_init(&sha256_ctx);
	}
	
	SHA256_update(&sha256_ctx, in_data, data_len);
	for (i = 0; i < SHA256_HASH_LEN / 4;  i++)
	{
		sha256_ctx.state[i] = SM3_SWAP32(sha256_ctx.state[i]); 
	}
	memcpy(hash, sha256_ctx.state, SHA256_HASH_LEN);
	*hash_len = SHA256_HASH_LEN;
	
	return 0;
}

INT32 sha384_with_iv(UINT8 *iv, UINT32 iv_len, UINT8 *in_data, UINT32 data_len, UINT8 *hash, UINT32 *hash_len)
{
	INT32 i;
	SHA384_CTX sha384_ctx;
	
	if (iv == NULL && iv_len != 0)
	{
		return ERR_CIPN_INDEXLEN;
	}
	else if (iv != NULL && iv_len != SHA384_HASH_LEN)
	{
		return -2;
	}
	
	if (data_len % SHA3_BLOCK_LEN != 0)
	{
		return ERR_CIPN_INDEXLEN;
	}
	
	if (iv != NULL)
	{
		memset(&sha384_ctx, 0, sizeof(SHA384_CTX));
		memcpy(sha384_ctx.state, iv, iv_len);
		for (i = 0; i < SHA384_HASH_LEN / 4;  i++)
		{
			sha384_ctx.state[i] = SM3_SWAP32(sha384_ctx.state[i]); 
		}
	}
	else
	{
		SHA384_init(&sha384_ctx);
	}
	
	SHA384_update(&sha384_ctx, in_data, data_len);
	for (i = 0; i < SHA384_HASH_LEN / 4;  i++)
	{
		sha384_ctx.state[i] = SM3_SWAP32(sha384_ctx.state[i]); 
	}
	memcpy(hash, sha384_ctx.state, SHA384_HASH_LEN);
	*hash_len = SHA384_HASH_LEN;
	
	return 0;
}

INT32 sha512_with_iv(UINT8 *iv, UINT32 iv_len, UINT8 *in_data, UINT32 data_len, UINT8 *hash, UINT32 *hash_len)
{
	INT32 i;
	SHA384_CTX sha384_ctx;
	
	if (iv == NULL && iv_len != 0)
	{
		return ERR_CIPN_INDEXLEN;
	}
	else if (iv != NULL && iv_len != SHA512_HASH_LEN)
	{
		return ERR_CIPN_INDEXLEN;
	}
	
	if (data_len % SHA3_BLOCK_LEN != 0)
	{
		return ERR_CIPN_INDEXLEN;
	}
	
	if (iv != NULL)
	{
		memset(&sha384_ctx, 0, sizeof(SHA384_CTX));
		memcpy(sha384_ctx.state, iv, iv_len);
		for (i = 0; i < SHA512_HASH_LEN / 4;  i++)
		{
			sha384_ctx.state[i] = SM3_SWAP32(sha384_ctx.state[i]); 
		}
	}
	else
	{
		SHA512_init(&sha384_ctx);
	}
	
	SHA384_update(&sha384_ctx, in_data, data_len);
	for (i = 0; i < SHA512_HASH_LEN / 4;  i++)
	{
		sha384_ctx.state[i] = SM3_SWAP32(sha384_ctx.state[i]); 
	}
	memcpy(hash, sha384_ctx.state, SHA512_HASH_LEN);
	*hash_len = SHA512_HASH_LEN;
	
	return 0;
}

void hmac_ipad_key(UINT8 *hmac_key, UINT32 key_len, UINT8 *ipad_key)
{
	INT32 i;
	UINT8 buff[SHA3_BLOCK_LEN];
	
	memset(buff, 0, SHA3_BLOCK_LEN);
	memcpy(buff, hmac_key, key_len);
	for (i = 0; i < SHA3_BLOCK_LEN; i++)
	{
		buff[i] = buff[i] ^ 0x36;
	}
	memcpy(ipad_key, buff, SHA3_BLOCK_LEN);
}

void hmac_opad_key(UINT8 *hmac_key, UINT32 key_len, UINT8 *opad_key)
{
	INT32 i;
	UINT8 buff[SHA3_BLOCK_LEN];
	
	memset(buff, 0, SHA3_BLOCK_LEN);
	memcpy(buff, hmac_key, key_len);
	for (i = 0; i < SHA3_BLOCK_LEN; i++)
	{
		buff[i] = buff[i] ^ 0x5C;
	}
	memcpy(opad_key, buff, SHA3_BLOCK_LEN);
}


INT32 hmac_first_step(UINT32 hash_algid, UINT8 *hmac_key, UINT32 key_len, UINT8 *in_data, UINT32 data_len, UINT8 *hash, UINT32 *hash_len)
{
	INT32 rtval;
	UINT8 ipad_key[SHA3_BLOCK_LEN];
	UINT8 ipadkey_hash[HASH_MAX_LEN];
	UINT32 ipadkey_hash_len;
	
	if (key_len != 16 && key_len != 32)
	{
		return -1;
	}
	
	hmac_ipad_key(hmac_key, key_len, ipad_key);
	if (hash_algid == HASH_ALG_SHA1)
	{
		rtval = sha1_with_iv(NULL, 0, ipad_key, HASH_BLOCK_LEN, ipadkey_hash, &ipadkey_hash_len);
		if (rtval)
		{
			return -2;
		}
		rtval = sha1_with_iv(ipadkey_hash, ipadkey_hash_len, in_data, data_len, hash, hash_len);
		if (rtval)
		{
			return -3;
		}
	}
	else if (hash_algid == HASH_ALG_SHA256)
	{
		rtval = sha256_with_iv(NULL, 0, ipad_key, HASH_BLOCK_LEN, ipadkey_hash, &ipadkey_hash_len);
		if (rtval)
		{
			return -2;
		}
		rtval = sha1_with_iv(ipadkey_hash, ipadkey_hash_len, in_data, data_len, hash, hash_len);
		if (rtval)
		{
			return -3;
		}
	}
	else if (hash_algid == HASH_ALG_SM3)
	{
		rtval = sm3_with_iv(NULL, 0, ipad_key, HASH_BLOCK_LEN, ipadkey_hash, &ipadkey_hash_len);
		if (rtval)
		{
			return -2;
		}
		rtval = sm3_with_iv(ipadkey_hash, ipadkey_hash_len, in_data, data_len, hash, hash_len);
		if (rtval)
		{
			return -3;
		}
	}
	else if (hash_algid == HASH_ALG_SHA384)
	{
		rtval = sha384_with_iv(NULL, 0, ipad_key, SHA3_BLOCK_LEN, ipadkey_hash, &ipadkey_hash_len);
		if (rtval)
		{
			return -2;
		}
		rtval = sha384_with_iv(ipadkey_hash, ipadkey_hash_len, in_data, data_len, hash, hash_len);
		if (rtval)
		{
			return -3;
		}
	}
	else if (hash_algid == HASH_ALG_SHA512)
	{
		rtval = sha512_with_iv(NULL, 0, ipad_key, SHA3_BLOCK_LEN, ipadkey_hash, &ipadkey_hash_len);
		if (rtval)
		{
			return -2;
		}
		rtval = sha512_with_iv(ipadkey_hash, ipadkey_hash_len, in_data, data_len, hash, hash_len);
		if (rtval)
		{
			return -3;
		}
	}
	else
	{
		return -4;
	}
	
	return 0;
}

INT32 hmac_middle_step(UINT32 hash_algid, UINT8 *iv, UINT32 iv_len, UINT8 *in_data, UINT32 data_len, UINT8 *hash, UINT32 *hash_len)
{
	INT32 rtval;
	
	if (hash_algid == HASH_ALG_SHA1)
	{
		rtval = sha1_with_iv(iv, iv_len, in_data, data_len, hash, hash_len);
		if (rtval)
		{
			return -1;
		}
	}
	else if (hash_algid == HASH_ALG_SHA256)
	{
		rtval = sha256_with_iv(iv, iv_len, in_data, data_len, hash, hash_len);
		if (rtval)
		{
			return -1;
		}
	}
	else if (hash_algid == HASH_ALG_SM3)
	{
		rtval = sm3_with_iv(iv, iv_len, in_data, data_len, hash, hash_len);
		if (rtval)
		{
			return -1;
		}
	}
	else if (hash_algid == HASH_ALG_SHA384)
	{
		rtval = sha384_with_iv(iv, iv_len, in_data, data_len, hash, hash_len);
		if (rtval)
		{
			return -1;
		}
	}
	else if (hash_algid == HASH_ALG_SHA512)
	{
		rtval = sha512_with_iv(iv, iv_len, in_data, data_len, hash, hash_len);
		if (rtval)
		{
			return -1;
		}
	}
	else
	{
		return -4;
	}
	
	return 0;
}

INT32 hmac_last_step(UINT32 hash_algid, UINT8 *hmac_key, UINT32 key_len, UINT8 *in_data, UINT32 data_len, UINT8 *hmac, UINT32 *hmac_len)
{
	INT32 rtval;
	UINT8 opad_key[SHA3_BLOCK_LEN];
	UINT8 opadkey_hash[HASH_MAX_LEN];
	UINT32 opadkey_hash_len;
	
	if (key_len != 16 && key_len != 32)
	{
		return -1;
	}
	
	hmac_opad_key(hmac_key, key_len, opad_key);
	if (hash_algid == HASH_ALG_SHA1)
	{
		rtval = sha1_with_iv(NULL, 0, opad_key, HASH_BLOCK_LEN, opadkey_hash, &opadkey_hash_len);
		if (rtval)
		{
			return -2;
		}
		rtval = sha1_with_iv(opadkey_hash, opadkey_hash_len, in_data, data_len, hmac, hmac_len);
		if (rtval)
		{
			return -3;
		}
	}
	else if (hash_algid == HASH_ALG_SHA256)
	{
		rtval = sha256_with_iv(NULL, 0, opad_key, HASH_BLOCK_LEN, opadkey_hash, &opadkey_hash_len);
		if (rtval)
		{
			return -2;
		}
		rtval = sha1_with_iv(opadkey_hash, opadkey_hash_len, in_data, data_len, hmac, hmac_len);
		if (rtval)
		{
			return -3;
		}
	}
	else if (hash_algid == HASH_ALG_SM3)
	{
		rtval = sm3_with_iv(NULL, 0, opad_key, HASH_BLOCK_LEN, opadkey_hash, &opadkey_hash_len);
		if (rtval)
		{
			return -2;
		}
		rtval = sm3_with_iv(opadkey_hash, opadkey_hash_len, in_data, data_len, hmac, hmac_len);
		if (rtval)
		{
			return -3;
		}
	}
	else if (hash_algid == HASH_ALG_SHA384)
	{
		rtval = sha384_with_iv(NULL, 0, opad_key, SHA3_BLOCK_LEN, opadkey_hash, &opadkey_hash_len);
		if (rtval)
		{
			return -2;
		}
		rtval = sha384_with_iv(opadkey_hash, opadkey_hash_len, in_data, data_len, hmac, hmac_len);
		if (rtval)
		{
			return -3;
		}	
	}
	else if (hash_algid == HASH_ALG_SHA512)
	{
		rtval = sha512_with_iv(NULL, 0, opad_key, SHA3_BLOCK_LEN, opadkey_hash, &opadkey_hash_len);
		if (rtval)
		{
			return -2;
		}
		rtval = sha512_with_iv(opadkey_hash, opadkey_hash_len, in_data, data_len, hmac, hmac_len);
		if (rtval)
		{
			return -3;
		}
	}
	else
	{
		return -4;
	}
	
	return 0;
}

INT32 hmac_one_step(UINT32 hash_algid, UINT8 *hmac_key, UINT32 key_len, UINT8 *in_data, UINT32 data_len, UINT8 *hmac, UINT32 *hmac_len)
{
	INT32 rtval;
	UINT8 hash_first[HASH_BLOCK_LEN];
	UINT32 hash_frist_len;
	UINT8 padding_buff[HASH_BLOCK_LEN * 2];
	UINT32 padding_size = 0;
	
	rtval = hmac_first_step(hash_algid, hmac_key, key_len, in_data, data_len + padding_size, hash_first, &hash_frist_len);
	if (rtval)
	{
		return -1;
	}
	fill_hash_padding(HASH_BLOCK_LEN, HASH_BLOCK_LEN + hash_frist_len, padding_buff, &padding_size);
	memcpy(hash_first + hash_frist_len, padding_buff, padding_size);
	rtval = hmac_last_step(hash_algid, hmac_key, key_len, hash_first, hash_frist_len + padding_size, hmac, hmac_len);
	if (rtval)
	{
		return -2;
	}
	return 0;
}

