#include "mcu_algorithm.h"
#include "hrng.h"
#include "cipher.h"
#include "ukey_oper.h"
extern FlashData eFlash;
#define PRINT_ALG 2
void printfb(uint8_t *buff, uint32_t len){
#ifdef DG
	int i;
	for (i = 0; i < len; i++)
	{
		print(PRINT_ALG,"%02x", buff[i]);
		//print(PRINT_ALG,"0x%02x ", buff[i]);
		if ((i + 1) % 64 == 0)
		{
			print(PRINT_ALG,"\r\n");
		}
	}
	print(PRINT_ALG,"\r\n");
#endif	
}

uint8_t AuthRandom[32]={0};
UINT8 Authalg_id = 0;
//用户身份鉴别函数
//1
int MCU_Auth_GenRandom( uint8_t* Random,uint16_t len){
	memset(AuthRandom,0,32);
	if(len > 32){
		return -1;
	}
	if(get_random_MCU(AuthRandom,len)){
		return -1;
	}
	memcpy(Random,AuthRandom,len);
	return 0;
}
//2
int MCU_Auth_GenAuthCode( uint8_t* Random,uint16_t Randomlen,UINT8 *key,uint8_t* AuthCode){
	if(Randomlen != 16){
		return -1;
	}
	return Ukey_Enc_WithKey(Random,Randomlen,key,16,AuthCode);
}
//3
int MCU_Auth_UkeyAuth( uint8_t* AuthCode,uint16_t AuthCodelen,uint8_t index){
	uint8_t dataout[32]={0};
	if(AuthCodelen != 16){
		return -1;
	}
	if(Sym_Crypt_WithKey(AuthCode,AuthCodelen,eFlash.AUTHKEY[index],16,NULL,0,SYM_ALG_SM4,SYM_DECRYPTION,SYM_ECB_MODE,dataout)){
		return -1;
	}
	if(memcmp(dataout,AuthRandom,16)){
		return -1;
	}
	return 0;
}

unsigned char get_random_MCU(unsigned char *random_data,unsigned int data_len)
{
	unsigned char res=0;
	hrng_initial();
	res = get_hrng(random_data, data_len);
	hrng_source_disable();//UINT8 get_hrng(UINT8 *hdata, UINT32 byte_len);
	return res;
}
uint16_t rsa_get_pading_mode(UINT8 *data_buf){
	if(data_buf[0] == 0 && data_buf[1]==2){
		return ASYM_KEYPAIR_CRYPT;
	}
	if(data_buf[0] == 0 && data_buf[1]==2){
		return ASYM_KEYPAIR_SIGN;
	}
	return 10;
}

int MUC_RSA_Prikey_Operation_internal(unsigned short pub_key_index, unsigned char *in_data, uint32_t in_len, unsigned char *out_data, unsigned  int *out_len){
	RSA_KEYGEN_G_STR pri_key;	
	uint8_t rsa_pubkey[RSA2048_BUFFLEN]={0};
	uint16_t pubkey_bits=0;
//	uint16_t ASYM_KEYPAIR_MODE = rsa_get_pading_mode(in_data);
//	if(ASYM_KEYPAIR_MODE != ASYM_KEYPAIR_CRYPT && ASYM_KEYPAIR_MODE != ASYM_KEYPAIR_SIGN){
//		return ERR_COMM_INPUT;
//	}
	if(export_ras_prikey(pub_key_index, ASYM_KEYPAIR_CRYPT, rsa_pubkey, &pubkey_bits))
		return ERR_CIPN_EXPRSAPUBKEY;
	
//	printfs("rsa_key\n");
//	printfb(rsa_pubkey, in_len*3);
	
	RSA_Keygen_init(&pri_key, pubkey_bits, rsa_pubkey );
	if((in_len != 256 && in_len != 128) || in_len*8 != pubkey_bits){
		return ERR_CIPN_RSAINLEN;
	}
//	printfs("in_data\n");
//	printfb(in_data, in_len);		
	if (RSA_Prikey_Operation(in_data, in_len, pri_key.RSA_e, 1, pri_key.RSA_p, in_len/8, pri_key.RSA_q, in_len/8, pri_key.RSA_dp, in_len/8,
													 pri_key.RSA_dq, in_len/8, pri_key.RSA_qInv, in_len/8, out_data, out_len)){
			print(PRINT_ALG,"RSA_Pub_OP err\r\n");
			return ERR_CIPN_RSAPUBKEYOP;
	}
//	printfs("out_data\n");
//	printfb(out_data, *out_len);													 
	
	return 0;
}
int MUC_RSA_Prikey_Operation_external(UINT8 *keypair_buf, unsigned char *in_data, unsigned  int in_len, unsigned char *out_data, unsigned  int *out_len){
	RSA_KEYGEN_G_STR pri_key;	
	uint16_t pubkey_bits=0;

	if(in_len == 256){
		pubkey_bits = 2048;
	}
	else if(in_len == 128){
		pubkey_bits = 1024;
	}
	else{
		return ERR_CIPN_RSAINLEN;
	}
	RSA_Keygen_init(&pri_key, pubkey_bits, keypair_buf);
	if(in_len != 256 && in_len != 128){
		return ERR_CIPN_RSAINLEN;
	}
	//printfs("keypair_buf\n");
	//printfb(keypair_buf, 704);	
	
//	printfs("in_data\n");
//	printfb(in_data, in_len);	
	if (RSA_Prikey_Operation(in_data, in_len, pri_key.RSA_e, 1, pri_key.RSA_p, in_len/8, pri_key.RSA_q, in_len/8, pri_key.RSA_dp, in_len/8,
													 pri_key.RSA_dq, in_len/8, pri_key.RSA_qInv, in_len/8, out_data, out_len)){
			print(PRINT_ALG,"RSA_Pub_OP err\r\n");
			return ERR_CIPN_RSAPUBKEYOP;
	}
//	printfs("out_data\n");
//	printfb(out_data, *out_len);	
	return 0;
}
//ASYM_KEYPAIR_CRYPT 
int MUC_RSA_Pubkey_Operation_internal(unsigned short pub_key_index, unsigned char *in_data, uint32_t in_len, unsigned char *out_data, unsigned  int *out_len){
	RSA_KEYGEN_G_STR pri_key;	
	uint8_t rsa_pubkey[RSA2048_BUFFLEN]={0};
	uint16_t pubkey_bits=0;
	
	if(export_ras_pubkey(pub_key_index, ASYM_KEYPAIR_CRYPT, rsa_pubkey, &pubkey_bits))
		return ERR_CIPN_EXPRSAPUBKEY;
	RSA_Keygen_init(&pri_key, pubkey_bits, rsa_pubkey);
	if((in_len != 256 && in_len != 128) || in_len*8 != pubkey_bits){
		return ERR_CIPN_RSAINLEN;
	}
//	printfs("in_data\n");
//	printfb(in_data, in_len);	
	
	if (RSA_Pubkey_Operation(in_data, in_len, pri_key.RSA_e, 1, pri_key.RSA_n, in_len/4, out_data, out_len))
	{
			print(PRINT_ALG,"RSA_Pub_OP err\r\n");
			return ERR_CIPN_RSAPUBKEYOP;
	}
	
//	printfs("out_data\n");
//	printfb(out_data, *out_len);	
	
	return 0;
}
int MUC_RSA_Pubkey_Operation_external(UINT8 *keypair_buf, unsigned char *in_data, unsigned  int in_len, unsigned char *out_data, unsigned  int *out_len){
	
	RSA_KEYGEN_G_STR pri_key;	
	uint16_t pubkey_bits=0;

	if(in_len == 256){
		pubkey_bits = 2048;
	}
	else if(in_len == 128){
		pubkey_bits = 1024;
	}
	else{
		return ERR_CIPN_RSAINLEN;
	}
	RSA_Keygen_init(&pri_key, pubkey_bits, keypair_buf);
	if(in_len != 256 && in_len != 128){
		return ERR_CIPN_RSAINLEN;
	}
//	printfs("in_data\n");
//	printfb(in_data, in_len);	
	if (RSA_Pubkey_Operation(in_data, in_len, pri_key.RSA_e, 1, pri_key.RSA_n, in_len/4, out_data, out_len)){
			print(PRINT_ALG,"RSA_Pub_OP err\r\n");
			return ERR_CIPN_RSAPUBKEYOP;
	}
//	printfs("out_data\n");
//	printfb(out_data, *out_len);	
	return 0;
}


int MUC_RSA_Pubkey_Enc_internal_pading(unsigned short pub_key_index, unsigned char *in_data, uint32_t in_len, unsigned char *out_data, unsigned  int *out_len){
	uint8_t tmpdata[RSA2048_BUFFLEN]={0};
	int keylen = 0;
	int ret=0;
	uint16_t pubkey_bits=0;
	
	if(export_ras_pubkey(pub_key_index, ASYM_KEYPAIR_CRYPT, tmpdata, &pubkey_bits))
		return ERR_CIPN_EXPRSAPUBKEY;
	
	keylen = pubkey_bits/8;
//	printfs("rsa_pubkey\n");
//	printfb(tmpdata, keylen*2);
	
//	printfs("in_data\n");
//	printfb(in_data, in_len);
	

	adil_padding_add_PKCS1_2(tmpdata, keylen, in_data, in_len);
	
//	printfs("pading_data\n");
//	printfb(tmpdata, keylen);
	
	ret=MUC_RSA_Pubkey_Operation_internal(pub_key_index, tmpdata, keylen, out_data, out_len);
	if(ret){
		return ret;
	}
//	printfs("out_data\n");
//	printfb(out_data, *out_len);	
	
	return ret;
}
int MUC_RSA_Pubkey_Enc_external_pading(UINT8 *keypair_buf, unsigned char *in_data, unsigned  int in_len, unsigned char *out_data, unsigned  int *out_len){
	
	uint8_t tmpdata[RSA2048_BUFFLEN]={0};
	int keylen = 0;
	int ret=0;
	
//	printfs("rsa_pubkey\n");
//	printfb(keypair_buf, *out_len*2);
	
//	printfs("in_data\n");
//	printfb(in_data, in_len);
	
	keylen = *out_len;
	adil_padding_add_PKCS1_2(tmpdata, keylen, in_data, in_len);

//	printfs("pading_data\n");
//	printfb(tmpdata, keylen);
	
	ret=MUC_RSA_Pubkey_Operation_external(keypair_buf, tmpdata, keylen, out_data, out_len);
	if(ret){
		return ret;
	}
	
//	printfs("out_data\n");
//	printfb(out_data, *out_len);	
	return ret;
}
int MUC_RSA_Prikey_Dec_internal_pading(unsigned short pub_key_index, unsigned char *in_data, uint32_t in_len, unsigned char *out_data, unsigned  int *out_len){
	//RSA_PKCS1_PADDING_SIZE
	uint8_t tmpdata[RSA2048_BUFFLEN]={0};
	int keylen = 0;
	int padlenth = 0;
	int ret=0;
	
//	printfs("in_data\n");
//	printfb(in_data, in_len);
	
	ret=MUC_RSA_Prikey_Operation_internal(pub_key_index, in_data, in_len, tmpdata,out_len);
	if(ret){
		return ret;
	}
	
//	printfs("pading_data\n");	
//	printfb(tmpdata, in_len);
	
	keylen = *out_len;
	padlenth = adil_padding_check_PKCS1_2(out_data, keylen, tmpdata, *out_len, *out_len+1);
	
//	printfs("unpading_data\n");
//	printfb(out_data, padlenth);	
	
	
	*out_len = padlenth;
	return 0;
}



static int GenerateRandom(unsigned char* szRand,int inum)
{
	get_random_MCU(szRand,inum);
	return inum;
}

int adil_padding_add_PKCS1_1(unsigned char *to, int tlen,const unsigned char *from, int flen)
{
	int j;
	unsigned char *p;

	if (flen > (tlen-RSA_PKCS1_PADDING_SIZE))
	{
		return(0);
	}

	p=(unsigned char *)to;

	*(p++)=0;
	*(p++)=1; /* Private Key BT (Block Type) */

	/* pad out with 0xff data */
	j=tlen-3-flen;
	memset(p,0xff,j);
	p+=j;
	*(p++)='\0';
	memcpy(p,from,(unsigned int)flen);
	return(1);
}

int adil_padding_check_PKCS1_1(unsigned char *to, int tlen,
			const unsigned char *from, int flen, int num)
{
	int i,j;
	const unsigned char *p;

	p=from;
	if (num != (flen+1))
	{
		return(-1);
	}
	p++;
	if ((*p) != 01)
		return -1;
	/* scan over padding data */
	j=flen-1; /* one for type. */
	p++;
	for (i=0; i<j; i++)
	{
		if (*p != 0xff) /* should decrypt to 0xff */
		{
			if (*p == 0)
			{ p++; break; }
			else
			{
				return(-1);
			}
		}
		p++;
	}

	if (i == j)
	{
		return(-1);
	}

	if (i < 8)
	{
		return(-1);
	}
	i++; /* Skip over the '\0' */
	j-=i;
	if (j > tlen)
	{
		return(-1);
	}
	j--;
	memcpy(to,p,(unsigned int)j);

	return(j);
}

int adil_padding_add_PKCS1_2(unsigned char *to, int tlen, const unsigned char *from, int flen)
{
	int i,j;
	unsigned char *p;

	if (flen > (tlen-11))
	{
		return(0);
	}

	p=(unsigned char *)to;

	*(p++)=0;
	*(p++)=2; /* Public Key BT (Block Type) */

	/* pad out with non-zero random data */
	j=tlen-3-flen;

	if (GenerateRandom(p,j) == 0)
		return(0);
	for (i=0; i<j; i++)
	{
		if (*p == '\0')
			do
			{
				if (GenerateRandom(p,1) == 0)
					return(0);
			} while (*p == '\0');
		p++;
	}

	*(p++)='\0';

	memcpy(p,from,(unsigned int)flen);
	return(1);
}

int adil_padding_check_PKCS1_2(unsigned char *to, int tlen,const unsigned char *from, int flen, int num)
{
	int i,j;
	const unsigned char *p;

	p=from;
	if (num != (flen+1))
	{
		return(-1);
	}
	p++;
	if ((*p) != 02)
	{
		return(-1);
	}
#ifdef PKCS1_CHECK
	return(num-11);
#endif

	/* scan over padding data */
	j=flen-1; /* one for type. */
	for (i=0; i<j; i++)
		if (*(p++) == 0) break;

	if (i == j)
	{
		return(-1);
	}

	if (i < 8)
	{
		return(-1);
	}

	i++; /* Skip over the '\0' */
	j-=i;
	if (j > tlen)
	{
		return(-1);
	}
	memcpy(to,p,(unsigned int)j);

	return(j);
}



int32_t mcu_sm2_encrypt_external(SM2PublicKey *pub_key, uint8_t *in_data, uint32_t in_len, uint8_t *out_data, uint32_t *out_len){

	int32_t rtval;
	ECC_G_STR sm2_para;
	uint8_t *C1;
	uint8_t *C2;
	uint8_t *C3;
	C1 = out_data;
	C3 = out_data + 2 * SM2_BYTE_LEN;
	C2 = out_data + 2 * SM2_BYTE_LEN + SM3_HASH_LEN;
	
	SM2_param_init(&sm2_para);
	
	rtval = SM2_Encrypt(&sm2_para,in_data,in_len,(UINT8 *)pub_key,C1,C2,C3);
	if (rtval)
	{
		print(PRINT_ALG,"mcu_sm2_enc err\r\n");
		return -1;
	}
	if (out_len != NULL)
	{
		*out_len = SM2_CIPHER_LEN(in_len);
	}
	return rtval;
}

int32_t mcu_sm2_decrypt_external(SM2PrivateKey *pri_key, uint8_t *in_data, uint32_t in_len, uint8_t *out_data, uint32_t *out_len){
	int32_t rtval;
	ECC_G_STR sm2_para;
	uint8_t *C1;
	uint8_t *C2;
	uint8_t *C3;
	uint32_t C2_len;
	C1 = in_data;
	C3 = in_data + 2 * SM2_BYTE_LEN;
	C2 = in_data + 2 * SM2_BYTE_LEN + SM3_HASH_LEN;
	C2_len = in_len - (2 * SM2_BYTE_LEN + SM3_HASH_LEN);
	
	SM2_param_init(&sm2_para);
	
	rtval = SM2_Decrypt(&sm2_para,(UINT8 *)pri_key,C1,C2,C3,C2_len,out_data);
	if (rtval)
	{
		print(PRINT_ALG,"mcu_sm2_dec err\r\n");
		return -1;
	}
	if (out_len != NULL)
	{
		*out_len = C2_len;
	}
	return rtval;
}

int32_t mcu_sm2_encrypt_internal(uint16_t pubkeyindex, uint8_t *in_data, uint32_t in_len, uint8_t *out_data, uint32_t *out_len){
	int32_t rtval;
	uint32_t indeed_read;
	SM2KeyPair sm2_keypair;
	rtval = read_cipher(pubkeyindex,sizeof(SM2KeyPair), &indeed_read, (uint8_t *)&sm2_keypair);
	if (rtval || indeed_read != sizeof(SM2KeyPair))
	{
		return ERR_CIPN_USRKEYNOEXIT;
	}
	return mcu_sm2_encrypt_external(&sm2_keypair.pk,in_data,in_len,out_data,out_len);
}

int32_t mcu_sm2_decrypt_internal(uint16_t prikeyindex, uint8_t *in_data, uint32_t in_len, uint8_t *out_data, uint32_t *out_len){
	int32_t rtval;
	uint32_t indeed_read;
	SM2KeyPair sm2_keypair;
	rtval = read_cipher(prikeyindex,sizeof(SM2KeyPair), &indeed_read, (uint8_t *)&sm2_keypair);
	if (rtval || indeed_read != sizeof(SM2KeyPair))
	{
		return ERR_CIPN_USRKEYNOEXIT;
	}
	return mcu_sm2_decrypt_external(&sm2_keypair.sk,in_data,in_len,out_data,out_len);
}

int32_t mcu_sm2_sign_external(SM2PrivateKey *pri_key, uint8_t *hash, uint8_t *sign_r, uint8_t *sign_s){
	int32_t rtval;
	ECC_G_STR sm2_para;
	SM2_param_init(&sm2_para);
	rtval = SM2_Sign(&sm2_para, hash, (uint8_t *)pri_key, sign_r, sign_s);
	if(rtval){
		return SDR_SIGNERR;
	}
	return 0;
}
int32_t mcu_sm2_verify_external(SM2PublicKey *pub_key, uint8_t *sign_r, uint8_t *sign_s, uint8_t *hash){
	int32_t rtval;
	ECC_G_STR sm2_para;
	SM2_param_init(&sm2_para);
	rtval = SM2_Verify(&sm2_para, hash, (uint8_t *)pub_key, sign_r, sign_s);
	if(rtval){
		return SDR_VERIFYERR;
	}
	return 0;
}
int32_t mcu_sm2_sign_internal(uint16_t prikeyindex, uint8_t *hash, uint8_t *sign_r, uint8_t *sign_s){
	int32_t rtval;
	uint32_t indeed_read;
	SM2KeyPair sm2_keypair;
	rtval = read_cipher(prikeyindex|SIGN,sizeof(SM2KeyPair), &indeed_read, (uint8_t *)&sm2_keypair);
	if (rtval || indeed_read != sizeof(SM2KeyPair))
	{
		return ERR_CIPN_USRKEYNOEXIT;
	}
	return mcu_sm2_sign_external(&sm2_keypair.sk, hash, sign_r, sign_s);
}
int32_t mcu_sm2_verify_internal(uint16_t pubkeyindex, uint8_t *sign_r, uint8_t *sign_s, uint8_t *hash){
	int32_t rtval;
	uint32_t indeed_read;
	SM2KeyPair sm2_keypair;
	rtval = read_cipher(pubkeyindex|SIGN,sizeof(SM2KeyPair), &indeed_read, (uint8_t *)&sm2_keypair);
	if (rtval || indeed_read != sizeof(SM2KeyPair))
	{
		return ERR_CIPN_USRKEYNOEXIT;
	}
	return mcu_sm2_verify_external(&sm2_keypair.pk,  sign_r, sign_s, hash);
}


int32_t mcu_sm2_agreement_genkey(uint8_t modeflag,uint8_t *other_id, uint32_t other_id_len, SM2PublicKey *other_pubkey, 
																 SM2PublicKey *other_temp_pubkey, void *agreement_handler, uint8_t *agreement_key)
{
	int32_t rtval;
	uint8_t ZA[SM3_HASH_LEN];
	uint8_t ZB[SM3_HASH_LEN];
	uint8_t S1[SM3_HASH_LEN] = {0};
	uint8_t SA[SM3_HASH_LEN] = {0};
	ECC_G_STR sm2_para;
	AgreementData *agreement_data = (AgreementData *)agreement_handler;
	SM2_param_init(&sm2_para);

	SM2_getZ(&sm2_para, other_id, other_id_len, other_pubkey->x, other_pubkey->y, ZB);
	SM2_getZ(&sm2_para, agreement_data->id, agreement_data->idlen, agreement_data->pk.x, agreement_data->pk.y, ZA);		

	//role： modeflag 1发起方 0 相应方
	//rtval = HSM2_sm2_exchange_key(&agreement_data->tmpsk, &agreement_data->tmppk, &agreement_data->sk, other_temp_pubkey, other_pubkey, &U);
	rtval = SM2_Exchange_Key(&sm2_para, modeflag, (UINT8 *)&agreement_data->sk, (UINT8 *)other_pubkey,(UINT8 *)&agreement_data->tmpsk, 
					(UINT8 *)&agreement_data->tmppk,(UINT8 *)other_temp_pubkey,ZA,ZB,agreement_data->key_bits,agreement_key,S1,SA);//UINT8 *ex_key, UINT8 *S1, UINT8 *SA)
	if (rtval)
	{
		print(PRINT_ALG,"mcu_sm2_ex_key err %d!!!\r\n", rtval);
		return ERR_CIPN_SM2ARGEEXCHE;
	}
	return 0;
}

int32_t mcu_sm2_agreement_generate_data(uint16_t isk_index, uint32_t key_bits, uint8_t *sponsor_id, uint32_t id_len, SM2PublicKey *sponsor_pubkey, SM2PublicKey *sponsor_tmp_pubkey, void **agreement_handle)
{
	int32_t rtval;
//	uint32_t indeed_read;
	ECC_G_STR sm2_para;
	
	AgreementData *agreement_data;
	
	agreement_data = pvPortMalloc(sizeof(AgreementData) + id_len);
	if (agreement_data == NULL)
	{
		print(PRINT_ALG,"mcu_sm2_ag_gen_data malloc err\r\n");
		return ERR_COMM_MALLOC;
	}
	//rtval = read_cipher(isk_index,sizeof(SM2KeyPair), &indeed_read, (uint8_t *)&agreement_data->pk);
	rtval = mcu_sm2_getkey(2*isk_index, &agreement_data->sk, &agreement_data->pk);
	if (rtval)// || indeed_read != sizeof(SM2KeyPair))
	{
		vPortFree(agreement_data);
		print(PRINT_ALG,"mcu_sm2_ag_gen_data mcu_sm2_gkey err %d\r\n", rtval);
		return rtval;
	}
	SM2_param_init(&sm2_para);
	if(SM2_Gen_Keypair(&sm2_para,(uint8_t*)(&agreement_data->tmpsk), \
											(uint8_t*)(agreement_data->tmppk.x),(uint8_t*)(agreement_data->tmppk.y)))
	{
		vPortFree(agreement_data);
		print(PRINT_ALG,"mcu_sm2_ag_gen_data f_sm2_gen_key err %d\r\n", rtval);
		return ERR_CIPN_GENSM2KEY;
	}
	//printfb((uint8_t *)(&agreement_data->tmppk), 64);
	//printfb((uint8_t *)(&agreement_data->tmpsk), 32);
	agreement_data->is_initor = 1;
	agreement_data->key_bits = key_bits;
	agreement_data->idlen = id_len;
	memcpy(agreement_data->id, sponsor_id, id_len);
	
	memcpy(sponsor_pubkey, &agreement_data->pk, sizeof(SM2PublicKey));
	memcpy(sponsor_tmp_pubkey, &agreement_data->tmppk, sizeof(SM2PublicKey));
	*agreement_handle = agreement_data;

	return 0;
}


int32_t mcu_sm2_agreement_generate_data_key(uint16_t isk_index, uint32_t key_bits, uint8_t *responsor_id, uint32_t responsor_id_len, 
												uint8_t *sponsor_id, uint32_t sponsor_id_len, SM2PublicKey *sponsor_pubkey, SM2PublicKey *sponsor_temp_pubkey,
												SM2PublicKey *responsor_pubkey, SM2PublicKey *responsor_temp_pubkey, uint32_t *key_index)
{
	int32_t rtval;
	AgreementData *agreement_data;
//	uint32_t indeed_read;
	ECC_G_STR sm2_para;
	uint8_t agreement_key[64];
	
	agreement_data = pvPortMalloc(sizeof(AgreementData) + responsor_id_len);
	if (agreement_data == NULL)
	{
		print(PRINT_ALG,"mcu_sm2_ag_gen_data malloc err\r\n");
		return ERR_COMM_MALLOC;
	}
	
	rtval = mcu_sm2_getkey(2*isk_index, &agreement_data->sk, &agreement_data->pk);
	if (rtval)// || indeed_read != sizeof(SM2KeyPair))
	{
		vPortFree(agreement_data);
		print(PRINT_ALG,"mcu_sm2_ag_gen_data_key mcu_sm2_gkey err %d!!!\r\n", rtval);
		return rtval;
	}

	SM2_param_init(&sm2_para);
	if(SM2_Gen_Keypair(&sm2_para,(uint8_t*)(&agreement_data->tmpsk), \
											(uint8_t*)(agreement_data->tmppk.x),(uint8_t*)(agreement_data->tmppk.y)))	
	{
		vPortFree(agreement_data);
		print(PRINT_ALG,"mcu_sm2_ag_gen_data fpga_sm2_gen_key err %d!!!\r\n", rtval);
		return ERR_CIPN_GENSM2KEY;
	}
	
	agreement_data->is_initor = 0;
	agreement_data->key_bits = key_bits;
	agreement_data->idlen = responsor_id_len;
	memcpy(agreement_data->id, responsor_id, responsor_id_len);
	
	rtval = mcu_sm2_agreement_genkey(0,sponsor_id, sponsor_id_len, sponsor_pubkey, sponsor_temp_pubkey, agreement_data, agreement_key);
	if (rtval)
	{
		print(PRINT_ALG,"mcu_sm2_ag_gen_data_key sm2_ag_gen err %d\r\n", rtval);
		vPortFree(agreement_data);
		return ERR_CIPN_SM2ARGENKEY;
	}
	
	memcpy(responsor_pubkey, &agreement_data->pk, sizeof(SM2PublicKey));
	memcpy(responsor_temp_pubkey, &agreement_data->tmppk, sizeof(SM2PublicKey));
//	printfs("mcu_sm2_agreement_generate_data_key agreement_key is: \n");
//	printfb(agreement_key, BIT_TO_BYTE(key_bits));
	rtval = writer_sessionkey_mcufpga(BIT_TO_BYTE(key_bits), agreement_key, key_index);
	vPortFree(agreement_data);
	return rtval;
}


int32_t mcu_sm2_agreement_generate_key(uint8_t *response_id, uint32_t response_id_len, 
										SM2PublicKey *response_pubkey, SM2PublicKey *response_temp_pubkey, 
										void *agreement_handle, uint32_t *key_index)
{
	int32_t rtval;
	ECC_G_STR sm2_para;
	uint8_t agreement_key[64];
	AgreementData *agreement_data = (AgreementData *)agreement_handle;
	SM2_param_init(&sm2_para);	
	rtval = mcu_sm2_agreement_genkey(1,response_id, response_id_len, response_pubkey, response_temp_pubkey, agreement_handle, agreement_key);
	if (rtval)
	{
		print(PRINT_ALG,"mcu_sm2_ag_gen_data_key sm2_ag_gen err %d\r\n", rtval);
		vPortFree(agreement_handle);
		return ERR_CIPN_SM2ARGENKEY;
	}
//	printfs("mcu_sm2_ag_gen_data_key agreement_key is: \n");
//	printfb(agreement_key, BIT_TO_BYTE(agreement_data->key_bits));
	rtval = writer_sessionkey_mcufpga(BIT_TO_BYTE(agreement_data->key_bits), agreement_key, key_index);
	vPortFree(agreement_handle);
	return rtval;
}





