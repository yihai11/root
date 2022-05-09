#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "cipher.h"
#include "fpga.h"
#include "internal_alg.h"
#include "fpga_sm2.h"
#include "freertos.h"

#define OK_FIRST		0x00	//高4位表示次数，低4位表示成功失败
#define OK_SECOND		0x10
#define ERR_FIRST		0x01
#define ERR_SECOND	0x02


extern uint8_t ArgFlag;
void * sd_malloc(uint32_t size)
{
	return pvPortMalloc(size);
}

void sd_free(void *mem)
{
	vPortFree(mem);
}
uint8_t HSMD1_NUM;
uint8_t find_hsmd1(void){

	static uint8_t i = 0;
//	uint8_t temp = 0;
	if(i >= HSM2_NUM ) i = 0;
	do{
		if(HSMD1 & (0x01<<i)){					//bit0:HSMD1_CHIP1; bit1:HSMD1_CHIP2; bit2:HSMD1_CHIP3; bit3:HSMD1_CHIP4;
			break;
		}
		i++;
		if(i >= HSM2_NUM ) i = 0;
	}while(i < HSM2_NUM);
	HSMD1_NUM = i;
	return i++;
}

uint8_t hsmd1err_repeat(uint8_t cmd, uint8_t *buff_start, uint16_t len){
	uint32_t * temp = (uint32_t *)(buff_start + len - 4);
	//first send
	if(!(cmd & 0xf0)){
		if(*temp) return ERR_FIRST;
		else return OK_FIRST;
	}
	//second send
	else{
		if(*temp) return ERR_SECOND;
		else return OK_SECOND;
	}
	
}

void FPGA_ApplyRandomData(unsigned char *random_data,unsigned short data_len,unsigned char channel)
{
	FPGAHeader header; 
//	unsigned char result;
	unsigned char *ptr = NULL;
	memset(&header, 0, sizeof(FPGAHeader));
	header.src = FPGA_DATA_ARM;
	header.dst = FPGA_DATA_RANDOM;
	header.pkglen = FPGA_DATAHEAD_LEN ;
	header.retpkglen = FPGA_DATAHEAD_LEN + data_len;
	header.keytype = KEY_TYPE_INPACK;
	header.keyindex = 0;
	header.channel = channel;//FPGA_CHANNEL_DEF;
	//print(PRINT_FPGA,"channel is %d\r\n",channel);
	if(fpga_write_start()==REG_REST) return;
	
	ptr = set_fpga_header((unsigned char *)FPGA_DATA_WRITE_ADDR, &header);
	
	fpga_write_finish(header.pkglen);
	ptr = fpga_read_start_ex();
	if( ptr == NULL){ 
		return;
	}
	//ptr = (unsigned char *)FPGA_DATA_READ_ADDR;
	memcpy(random_data,ptr+FPGA_DATAHEAD_LEN,data_len);

	fpga_read_finish();
}


unsigned int chgBELE_32(unsigned int i);
extern uint8_t g_random[32];

void print_byte(uint8_t *buff, uint32_t len)
{
	int i;
	
	for (i = 0; i < len; i++)
	{
		print(PRINT_FPGA,"0x%02x ", buff[i]);
		if ((i + 1) % 16 == 0)
		{
			print(PRINT_FPGA,"\r\n");
		}
	}
	print(PRINT_FPGA,"\r\n");
}

int32_t calcKeyExKDF(uint8_t *K, uint8_t klen, SM2Point *v, uint8_t *Za, uint8_t *Zb)
{
	SM3_CTX sm3_ctx;
	unsigned char hash[SM3_HASH_LEN];
	uint32_t ct;
	unsigned int i;
	unsigned int count = klen / SM3_HASH_LEN + ((0 == klen %SM3_HASH_LEN) ? 0 : 1);
	
	for (i = 1; i <= count; i++) {
		SM3_initial(&sm3_ctx);
		SM3_update(&sm3_ctx, v->x, SM2_BYTE_LEN);
		SM3_update(&sm3_ctx, v->y, SM2_BYTE_LEN);
		SM3_update(&sm3_ctx, Za, SM3_HASH_LEN);
		SM3_update(&sm3_ctx, Zb, SM3_HASH_LEN);
		ct = chgBELE_32(i);
		SM3_update(&sm3_ctx, (uint8_t *)&ct, sizeof(ct));
		SM3_final(hash, &sm3_ctx);
		if (i != count) {
			memcpy(K + (i - 1) * SM3_HASH_LEN, hash, SM3_HASH_LEN);
		} else {
			memcpy(K + (i - 1) * SM3_HASH_LEN, hash, klen - (i -1) * SM3_HASH_LEN);
		}
	}
	
	return 0;
}

static int32_t calcEncKDF(uint8_t *K, unsigned int klen, SM2Point *S)
{
	SM3_CTX sm3_ctx;
	uint8_t hash[SM3_HASH_LEN];
	uint32_t i;
	uint32_t ct;
	uint32_t count = klen / SM3_HASH_LEN + ((0 == klen % SM3_HASH_LEN) ? 0 : 1);
	
	for (i = 1; i <= count; i++) {
		SM3_initial(&sm3_ctx);
		SM3_update(&sm3_ctx, S->x, SM2_BYTE_LEN);
		SM3_update(&sm3_ctx, S->y, SM2_BYTE_LEN);
		ct = chgBELE_32(i);
		SM3_update(&sm3_ctx, (uint8_t *)&ct, sizeof(ct));
		SM3_final(hash, &sm3_ctx);
		if (i != count) {
			memcpy(K + (i -1) * SM3_HASH_LEN, hash, SM3_HASH_LEN);
		} else {
			memcpy(K + (i -1) * SM3_HASH_LEN, hash, klen - (i -1) * SM3_HASH_LEN);
		}
	}
	
	return 0;
}

static int32_t HSM2_sm2_encrypt_external(SM2PublicKey *pub_key, uint8_t *random, SM2Point *C1, SM2Point *S)
{
	FPGAHeader fpga_header;
	uint8_t *alg_hdr;
	uint8_t *data_ptr,i = 0,repeat = 0,tail = 0;
if(HSMD1){
	i=find_hsmd1();
	tail = 32;
}
do{
	memset(&fpga_header, 0, sizeof(FPGAHeader));
	fpga_header.mark = FPGA_HEAD_MARK;
	fpga_header.src = FPGA_DATA_ARM;
	fpga_header.dst = FPGA_DATA_SM2_HSM2+i;
	fpga_header.channel = FPGA_CHANNEL_DEF;
	fpga_header.pkglen = FPGA_DATAHEAD_LEN + FPGA_MCUHEAD_LEN + 3 * SM2_BYTE_LEN;
	fpga_header.retpkglen = FPGA_DATAHEAD_LEN + SM2_BYTE_LEN * 4 + tail;
	fpga_header.sm2_cmd = CMD_SM2_ENCRYPT | (repeat & 0x0f);
	fpga_header.keytype = KEY_TYPE_INPACK;
	fpga_header.keyindex = 0;
	//print(PRINT_FPGA,"HSM2_sm2_encrypt_external dst is %x\r\n",fpga_header.dst);
	//print(PRINT_FPGA,"HSM2_sm2_encrypt_external cmd is %x\r\n",fpga_header.sm2_cmd);
	if(fpga_write_start()==REG_REST) return ERR_COMM_OUTTIME;
	alg_hdr = set_fpga_header((uint8_t *)FPGA_DATA_WRITE_ADDR, &fpga_header);
	data_ptr = alg_header(alg_hdr, 0, fpga_header.pkglen - FPGA_DATAHEAD_LEN, ENCRYPT_MODE, SM4_ECB_MODE, FPGA_DISABLE, 0, FPGA_DISABLE, 0);
	memcpy(data_ptr, random, SM2_BYTE_LEN);
	data_ptr += SM2_BYTE_LEN;
	memcpy(data_ptr, pub_key, sizeof(SM2PublicKey));
	data_ptr += sizeof(SM2PublicKey);
	fpga_write_finish(fpga_header.pkglen);
	
	data_ptr = fpga_read_start_ex();
	if( data_ptr == NULL){ 
		print(PRINT_FPGA,"fpga no data %x!\r\n",fpga_header.dst);
		return ERR_COMM_OUTTIME;
	}
	get_fpga_header(&fpga_header, data_ptr);
#ifndef TEST
if(HSMD1){
#if NEW
	repeat = hsmd1err_repeat(fpga_header.sm2_cmd,data_ptr,fpga_header.pkglen);
	if(ERR_SECOND == repeat) return repeat;
#endif
}
	if ((fpga_header.channel & 0xE0) != 0x20 && (fpga_header.channel & 0xE0) != 0x00 && OK_SECOND != repeat && ERR_FIRST != repeat)
	{
		print(PRINT_FPGA,"ch err:%x\r\n",fpga_header.channel);
		fpga_read_finish();
		return ERR_CIPN_FPGASM2ENCIN;
	}
#endif
	}while(repeat & 0x0f);
	data_ptr = (uint8_t *)(data_ptr + FPGA_DATAHEAD_LEN);
	memcpy(C1, data_ptr, sizeof(SM2Point));
	data_ptr += sizeof(SM2Point);
	memcpy(S, data_ptr, sizeof(SM2Point));
	fpga_read_finish();
//	print(PRINT_FPGA,"HSM2_sm2_encrypt_external success.\r\n");
	return 0;
}

static int32_t HSM2_sm2_encrypt_internal(uint16_t pub_key_index, uint8_t *random, SM2Point *C1, SM2Point *S)
{
	FPGAHeader fpga_header;
	uint8_t *alg_hdr;
	uint8_t *data_ptr,i = 0,repeat = 0,tail = 0;;
if(HSMD1){
	i=find_hsmd1();
	tail = 32;
}
do{
	memset(&fpga_header, 0, sizeof(FPGAHeader));
	fpga_header.mark = FPGA_HEAD_MARK;
	fpga_header.src = FPGA_DATA_ARM;
	fpga_header.dst = FPGA_DATA_SM2_HSM2+i;
	fpga_header.channel = FPGA_CHANNEL_DEF;
	fpga_header.pkglen = FPGA_DATAHEAD_LEN + FPGA_MCUHEAD_LEN + SM2_BYTE_LEN;
	fpga_header.retpkglen = FPGA_DATAHEAD_LEN + SM2_BYTE_LEN * 4 + tail;
	fpga_header.sm2_cmd = CMD_SM2_ENCRYPT | (repeat & 0x0f);
	fpga_header.keytype = KEY_TYPE_LOOKUP;
	fpga_header.keyindex = pub_key_index;
//	print(PRINT_FPGA,"HSM2_sm2_encrypt_internal dst is %x\r\n",fpga_header.dst);
	if(fpga_write_start()==REG_REST) return ERR_COMM_OUTTIME;
	alg_hdr = set_fpga_header((uint8_t *)FPGA_DATA_WRITE_ADDR, &fpga_header);
	data_ptr = alg_header(alg_hdr, 0, fpga_header.pkglen - FPGA_DATAHEAD_LEN, ENCRYPT_MODE, SM4_ECB_MODE, FPGA_DISABLE, 0, FPGA_DISABLE, 0);
	memcpy(data_ptr, random, SM2_BYTE_LEN);
	data_ptr += SM2_BYTE_LEN;
	fpga_write_finish(fpga_header.pkglen);
	
	data_ptr=fpga_read_start_ex();
	if( data_ptr == NULL){
		print(PRINT_FPGA,"fpga no data %x!\r\n",fpga_header.dst);
		return ERR_COMM_OUTTIME;
	}
	get_fpga_header(&fpga_header, data_ptr);
#ifndef TEST
if(HSMD1){
#if NEW
	repeat = hsmd1err_repeat(fpga_header.sm2_cmd,data_ptr,fpga_header.pkglen);
//	printf_buff_byte((uint8_t *)data_ptr,fpga_header.pkglen);
	if(ERR_SECOND == repeat) return repeat;
#endif
}
	if ((fpga_header.channel & 0xE0) != 0x20)
	{
		print(PRINT_FPGA,"ch err:%x\r\n",fpga_header.channel);
		fpga_read_finish();
		return ERR_CIPN_FPGASM2ENCIN;
	}
#endif
	}while(repeat & 0x0f);
	data_ptr = (uint8_t *)(data_ptr + FPGA_DATAHEAD_LEN);
	memcpy(C1, data_ptr, sizeof(SM2Point));
	data_ptr += sizeof(SM2Point);
	memcpy(S, data_ptr, sizeof(SM2Point));
	fpga_read_finish();
//	print(PRINT_FPGA,"HSM2_sm2_encrypt_internal success.\r\n");
	return 0;
}

static int32_t HSM2_sm2_decrypt_external(SM2PrivateKey *pri_key, SM2Point *C1, SM2Point *S)
{
	FPGAHeader fpga_header;
	uint8_t *alg_hdr;
	uint8_t *data_ptr,i = 0,repeat = 0,tail = 0;
if(HSMD1){
	i=find_hsmd1();
	tail = 32;
}
	do{
	memset(&fpga_header, 0, sizeof(FPGAHeader));
	fpga_header.mark = FPGA_HEAD_MARK;
	fpga_header.src = FPGA_DATA_ARM;
	fpga_header.dst = FPGA_DATA_SM2_HSM2+i;
	fpga_header.channel = FPGA_CHANNEL_DEF;
	fpga_header.pkglen = FPGA_DATAHEAD_LEN + FPGA_MCUHEAD_LEN + 3 * SM2_BYTE_LEN;
	fpga_header.retpkglen = FPGA_DATAHEAD_LEN + SM2_BYTE_LEN * 2 + tail;
	fpga_header.sm2_cmd = CMD_SM2_DECRYPT | (repeat & 0x0f);
	fpga_header.keytype = KEY_TYPE_INPACK;
	fpga_header.keyindex = 0;
//	print(PRINT_FPGA,"HSM2_sm2_decrypt_external dst is %x\r\n",fpga_header.dst);
	if(fpga_write_start()==REG_REST) return ERR_COMM_OUTTIME;
	alg_hdr = set_fpga_header((uint8_t *)FPGA_DATA_WRITE_ADDR, &fpga_header);
	data_ptr = alg_header(alg_hdr, 0, fpga_header.pkglen - FPGA_DATAHEAD_LEN, ENCRYPT_MODE, SM4_ECB_MODE, FPGA_DISABLE, 0, FPGA_DISABLE, 0);
	memcpy(data_ptr, pri_key, sizeof(SM2PrivateKey));
	data_ptr += sizeof(SM2PrivateKey);
	memcpy(data_ptr, C1, sizeof(SM2Point));
	data_ptr += sizeof(SM2Point);
	fpga_write_finish(fpga_header.pkglen);
		
	data_ptr=fpga_read_start_ex();
	if( data_ptr == NULL){
		print(PRINT_FPGA,"fpga no data %x!\r\n",fpga_header.dst);
		return ERR_COMM_OUTTIME;
	}
	get_fpga_header(&fpga_header, data_ptr);
#ifndef TEST
if(HSMD1){
#if NEW
	repeat = hsmd1err_repeat(fpga_header.sm2_cmd,data_ptr,fpga_header.pkglen);
	//printf_buff_byte((uint8_t *)data_ptr,fpga_header.pkglen);
	if(ERR_SECOND == repeat) return repeat;
#endif
}
	if ((fpga_header.channel & 0xE0) != 0x20 && (fpga_header.channel & 0xE0) != 0x00)
	{
		print(PRINT_FPGA,"ch err:%x\r\n",fpga_header.channel);
		fpga_read_finish();
		return ERR_CIPN_FPGASM2DECIN;
	}
#endif
	}while(repeat & 0x0f);
	data_ptr = (uint8_t *)(data_ptr + FPGA_DATAHEAD_LEN);
	memcpy(S, data_ptr, sizeof(SM2Point));
	fpga_read_finish();
//	print(PRINT_FPGA,"HSM2_sm2_decrypt_external success.\r\n");
	return 0;
}

static int32_t HSM2_sm2_decrypt_internal(uint32_t pri_key_index, SM2Point *C1, SM2Point *S)
{
	FPGAHeader fpga_header;
	uint8_t *alg_hdr;
	uint8_t *data_ptr,i = 0,repeat = 0,tail = 0;
if(HSMD1){
	i=find_hsmd1();
	tail = 32;
}
do{
	memset(&fpga_header, 0, sizeof(FPGAHeader));
	fpga_header.mark = FPGA_HEAD_MARK;
	fpga_header.src = FPGA_DATA_ARM;
	fpga_header.dst = FPGA_DATA_SM2_HSM2+i;
	fpga_header.channel = FPGA_CHANNEL_DEF;
	fpga_header.pkglen = FPGA_DATAHEAD_LEN + FPGA_MCUHEAD_LEN + 2 * SM2_BYTE_LEN;
	fpga_header.retpkglen = FPGA_DATAHEAD_LEN + SM2_BYTE_LEN * 2 + tail;
	fpga_header.sm2_cmd = CMD_SM2_DECRYPT | (repeat & 0x0f);
	fpga_header.keytype = KEY_TYPE_LOOKUP;
	fpga_header.keyindex = pri_key_index;
//	print(PRINT_FPGA,"HSM2_sm2_decrypt_internal dst is %x\r\n",fpga_header.dst);
	if(fpga_write_start()==REG_REST) return ERR_COMM_OUTTIME;
	alg_hdr = set_fpga_header((uint8_t *)FPGA_DATA_WRITE_ADDR, &fpga_header);
	data_ptr = alg_header(alg_hdr, 0, fpga_header.pkglen - FPGA_DATAHEAD_LEN, ENCRYPT_MODE, SM4_ECB_MODE, FPGA_DISABLE, 0, FPGA_DISABLE, 0);
	memcpy(data_ptr, C1, sizeof(SM2Point));
	data_ptr += sizeof(SM2Point);
	fpga_write_finish(fpga_header.pkglen);
	
	data_ptr = fpga_read_start_ex();
	if( data_ptr == NULL){
		print(PRINT_FPGA,"fpga no data %x!\r\n",fpga_header.dst);
		return ERR_COMM_OUTTIME;
	}	
	get_fpga_header(&fpga_header, data_ptr);
#ifndef TEST
if(HSMD1){
#if NEW
	repeat = hsmd1err_repeat(fpga_header.sm2_cmd,data_ptr,fpga_header.pkglen);
//	print(PRINT_FPGA,"result is :\r\n");
//	printf_buff_byte((uint8_t *)data_ptr,fpga_header.pkglen);
	if(ERR_SECOND == repeat) return repeat;
#endif
}
	if ((fpga_header.channel & 0xE0) != 0x20)
	{
		print(PRINT_FPGA,"ch err:%x\r\n",fpga_header.channel);
		fpga_read_finish();
		return ERR_CIPN_FPGASM2DECIN;
	}
#endif
	}while(repeat & 0x0f);
	data_ptr = (uint8_t *)(data_ptr + FPGA_DATAHEAD_LEN);
	memcpy(S, data_ptr, sizeof(SM2Point));
	fpga_read_finish();
//	print(PRINT_FPGA,"HSM2_sm2_decrypt_internal success.\r\n");
	return 0;
}

static int32_t HSM2_sm2_exchange_key(SM2PrivateKey *self_temp_prikey, SM2PublicKey *self_temp_pubkey, SM2PrivateKey *self_prikey, SM2PublicKey *other_temp_pubkey, SM2PublicKey *other_pubkey, SM2Point *U)
{
	FPGAHeader fpga_header;
	uint8_t *alg_hdr;
	uint8_t *data_ptr,i = 0;
	if(HSMD1){
	i=find_hsmd1();
	}
	memset(&fpga_header, 0, sizeof(FPGAHeader));
	fpga_header.mark = FPGA_HEAD_MARK;
	fpga_header.src = FPGA_DATA_ARM;
	fpga_header.dst = FPGA_DATA_SM2_HSM2+i;
	fpga_header.channel = FPGA_CHANNEL_DEF;
	fpga_header.pkglen = FPGA_DATAHEAD_LEN + FPGA_MCUHEAD_LEN + 3 * SM2_BYTE_LEN + 4 * SM2_BYTE_LEN;
	fpga_header.retpkglen = FPGA_DATAHEAD_LEN + SM2_BYTE_LEN * 2;
	fpga_header.sm2_cmd = CMD_SM2_EXCHGKEY;
	fpga_header.keytype = KEY_TYPE_INPACK;
	fpga_header.keyindex = 0;
	
	if(fpga_write_start()==REG_REST) return ERR_COMM_OUTTIME;
	alg_hdr = set_fpga_header((uint8_t *)FPGA_DATA_WRITE_ADDR, &fpga_header);
	data_ptr = alg_header(alg_hdr, 0, fpga_header.pkglen - FPGA_DATAHEAD_LEN, ENCRYPT_MODE, SM4_ECB_MODE, FPGA_DISABLE, 0, FPGA_DISABLE, 0);
	memcpy(data_ptr, self_temp_prikey, sizeof(SM2PrivateKey));
	data_ptr += sizeof(SM2PrivateKey);
	memcpy(data_ptr, self_temp_pubkey->x, SM2_BYTE_LEN);
	data_ptr += SM2_BYTE_LEN;
	memcpy(data_ptr, self_prikey, sizeof(SM2PrivateKey));
	data_ptr += sizeof(SM2PrivateKey);
	memcpy(data_ptr, other_temp_pubkey, sizeof(SM2PublicKey));
	data_ptr += sizeof(SM2PublicKey);
	memcpy(data_ptr, other_pubkey, sizeof(SM2PublicKey));
	data_ptr += sizeof(SM2PublicKey);
	fpga_write_finish(fpga_header.pkglen);
	
	data_ptr=fpga_read_start_ex();
	if( data_ptr == NULL){
		print(PRINT_FPGA,"fpga no data %x!\r\n",fpga_header.dst);
		return ERR_COMM_OUTTIME;
	}	
	get_fpga_header(&fpga_header, data_ptr);
#ifndef TEST
	if ((fpga_header.channel & 0xE0) != 0x20 && (fpga_header.channel & 0xE0) != 0xa0
		 && (fpga_header.channel & 0xE0) != 0x00)
	{
		fpga_read_finish();
		return -1;
	}
#endif
	data_ptr = (uint8_t *)(data_ptr + FPGA_DATAHEAD_LEN);
	memcpy(U, data_ptr, sizeof(SM2Point));
	data_ptr += sizeof(SM2Point);
	fpga_read_finish();
	
	return 0;
}

int32_t fpga_sm2_setkey(uint16_t key_index, SM2PrivateKey *pri_key, SM2PublicKey *pub_key)
{
	//查看FPGA是否支持 HSM2 SM2 算法  
	if((ArgFlag&0x01) == 0){
		return mcu_sm2_setkey(key_index,pri_key,pub_key); //不支持,改为使用MCU
	}
	mcu_sm2_setkey(key_index,pri_key,pub_key);
	
	FPGAHeader fpga_header;
	uint8_t *data_ptr,i = 0;
	uint8_t select = 1;
if(HSMD1){
	select = HSMD1;
}
	//设置HSM2	
	for(i = 0; i < HSM2_NUM; i++){
		if(!(select & (0x01 << i))){					//bit0:HSMD1_CHIP1; bit1:HSMD1_CHIP2; bit2:HSMD1_CHIP3; bit3:HSMD1_CHIP4;
			continue;
		}
	memset(&fpga_header, 0, sizeof(FPGAHeader));
	fpga_header.mark = FPGA_HEAD_MARK;
	fpga_header.src = FPGA_DATA_ARM;
	fpga_header.dst = FPGA_DATA_SM2_HSM2+i;
	fpga_header.channel = FPGA_CHANNEL_DEF;
	fpga_header.pkglen = FPGA_DATAHEAD_LEN + 3 * SM2_BYTE_LEN;
	fpga_header.retpkglen = 0;
	fpga_header.sm2_cmd = CMD_SM2_SETKEY;
	fpga_header.keytype = KEY_TYPE_LOOKUP;
	fpga_header.keyindex = key_index;
//	print(PRINT_FPGA,"f_sm2_setkey dst is %x\r\n",fpga_header.dst);
//	print(PRINT_FPGA,"key_index is %x\r\n",key_index);
	if(fpga_write_start()==REG_REST) return ERR_COMM_OUTTIME;
	data_ptr = set_fpga_header((uint8_t *)FPGA_DATA_WRITE_ADDR, &fpga_header);
	memcpy(data_ptr, pri_key, sizeof(SM2PrivateKey));
	data_ptr += sizeof(SM2PrivateKey);
	memcpy(data_ptr, pub_key, sizeof(SM2PublicKey));
	data_ptr += sizeof(SM2PublicKey);
	fpga_write_finish(fpga_header.pkglen);
	//printf_buff_byte((uint8_t *)FPGA_DATA_WRITE_ADDR,fpga_header.pkglen);
//	printf_buff_byte((uint8_t *)pri_key,sizeof(SM2PrivateKey));
//	printf_buff_byte((uint8_t *)pub_key,sizeof(SM2PublicKey));

//查看ssx1510 SM2算法  
//	if((ArgFlag&0x02) == 0){
//		return 0; //未使能 返回
//	}
	}
	return 0;
}

int32_t fpga_sm2_getkey(uint16_t key_index, SM2PrivateKey *pri_key, SM2PublicKey *pub_key)
{
	//查看FPGA是否支持 HSM2 SM2 算法
//#ifndef HSMD1
	return mcu_sm2_getkey(key_index,pri_key,pub_key);
//#endif
	if((ArgFlag&0x01) == 0)
	{
		return mcu_sm2_getkey(key_index,pri_key,pub_key); //不支持,改为使用MCU
	}
	
	FPGAHeader fpga_header;
	uint8_t *alg_hdr;
	uint8_t *data_ptr;
	uint8_t tt,i=0;
if(HSMD1){
	i=find_hsmd1();
}
	memset(&fpga_header, 0, sizeof(FPGAHeader));
	fpga_header.mark = FPGA_HEAD_MARK;
	fpga_header.src = FPGA_DATA_ARM;
	fpga_header.dst = FPGA_DATA_SM2_HSM2+i;
	fpga_header.channel = FPGA_CHANNEL_DEF;
	fpga_header.pkglen = FPGA_DATAHEAD_LEN;
	fpga_header.retpkglen = FPGA_DATAHEAD_LEN + 3 * SM2_BYTE_LEN;
	fpga_header.sm2_cmd = CMD_SM2_GETKEY;
	fpga_header.keytype = KEY_TYPE_LOOKUP;
	fpga_header.keyindex = key_index;
//	print(PRINT_FPGA,"f_sm2_getkey dst is %x\r\n",fpga_header.dst);
//	print(PRINT_FPGA,"key_index is %x\r\n",key_index);
	if(fpga_write_start()==REG_REST) return ERR_COMM_OUTTIME;
	alg_hdr = set_fpga_header((uint8_t *)FPGA_DATA_WRITE_ADDR, &fpga_header);
	tt=*(uint8_t *)(FPGA_DATA_WRITE_ADDR+2);
	fpga_write_finish(fpga_header.pkglen);
	

	data_ptr=fpga_read_start_ex();
	if( data_ptr == NULL){
		print(PRINT_FPGA,"fpga no data %x!\r\n",fpga_header.dst);
		return ERR_COMM_OUTTIME;
	}
	get_fpga_header(&fpga_header, data_ptr);
	//printf_buff_byte((uint8_t *)FPGA_DATA_WRITE_ADDR,fpga_header.pkglen);
#ifndef TEST
	if ((fpga_header.channel & 0xE0) != 0x20 && (fpga_header.channel & 0xE0) != 0xa0)
	{
		print(PRINT_FPGA,"fpga no data 0x%x\r\n", fpga_header.channel);
		fpga_read_finish();
		return -1;
	}
#endif
	data_ptr = (uint8_t *)(data_ptr + FPGA_DATAHEAD_LEN);
	memcpy(pri_key, data_ptr, sizeof(SM2PrivateKey));
	data_ptr += sizeof(SM2PrivateKey);
	memcpy(pub_key, data_ptr, sizeof(SM2PublicKey));
	data_ptr += sizeof(SM2PublicKey);
	fpga_read_finish();
//	printf_buff_byte((uint8_t *)pri_key,sizeof(SM2PrivateKey));
//	printf_buff_byte((uint8_t *)pub_key,sizeof(SM2PublicKey));
	return 0;
}
int32_t fpga_sm2_delkey(uint16_t key_index)
{
	//查看FPGA是否支持 HSM2 SM2 算法  
	if((ArgFlag&0x01) == 0){
		return mcu_sm2_delkey(key_index); //不支持,改为使用MCU
	}
	mcu_sm2_delkey(key_index);
	FPGAHeader fpga_header;
	uint8_t *alg_hdr, i = 0;
	uint8_t select = 1;
if(HSMD1){
	select = HSMD1;
}
	//设置HSM2	
	for(i = 0; i < HSM2_NUM; i++){
		if(!(select & (0x01 << i))){					//bit0:HSMD1_CHIP1; bit1:HSMD1_CHIP2; bit2:HSMD1_CHIP3; bit3:HSMD1_CHIP4;
			continue;
		}
	memset(&fpga_header, 0, sizeof(FPGAHeader));
	fpga_header.mark = FPGA_HEAD_MARK;
	fpga_header.src = FPGA_DATA_ARM;
	fpga_header.dst = FPGA_DATA_SM2_HSM2+i;
	fpga_header.channel = FPGA_CHANNEL_DEF;
	fpga_header.pkglen = FPGA_DATAHEAD_LEN;
	fpga_header.retpkglen = FPGA_DATAHEAD_LEN + 3 * SM2_BYTE_LEN;
	fpga_header.sm2_cmd = CMD_SM2_DELKEY;
	fpga_header.keytype = KEY_TYPE_LOOKUP;
	fpga_header.keyindex = key_index;
//	print(PRINT_FPGA,"f_sm2_delkey dst is %x\r\n",fpga_header.dst);
	if(fpga_write_start()==REG_REST) return ERR_COMM_OUTTIME;
	alg_hdr = set_fpga_header((uint8_t *)FPGA_DATA_WRITE_ADDR, &fpga_header);
	fpga_write_finish(fpga_header.pkglen);
	}
	return 0;
}

int32_t fpga_sm2_encrypt_external(SM2PublicKey *pub_key, uint8_t *in_data, uint32_t in_len, uint8_t *out_data, uint32_t *out_len)
{
	//查看FPGA是否支持 HSM2 SM2 算法  
	if((ArgFlag&0x01) == 0){
		return mcu_sm2_encrypt_external(pub_key,in_data,in_len,out_data,out_len); //不支持,改为使用MCU
	}
	
	uint32_t i;
	int32_t rtval;
	uint8_t random[SM2_BYTE_LEN];
	SM2Point S;
	SM2Point *C1;
	uint8_t *C2;
	uint8_t *C3;
	SM3_CTX sm3_ctx;
	
	C1 = (SM2Point *)out_data;
	C3 = out_data + 2 * SM2_BYTE_LEN;
	C2 = out_data + 2 * SM2_BYTE_LEN + SM3_HASH_LEN;
	
	rtval = get_hrng(random, SM2_BYTE_LEN);
	if (rtval)
	{
		print(PRINT_FPGA,"f_sm2_en ghrng err\r\n");
		return ERR_CIPN_RANDOM;
	}
		
	do
	{
		rtval = HSM2_sm2_encrypt_external(pub_key, random, C1, &S);
		if (rtval)
		{
			break;
		}
		rtval = calcEncKDF(C2, in_len, &S);
		if (rtval)
		{
			break;
		}
		for (i = 0; i < in_len; i++)
		{
			C2[i] = C2[i] ^ in_data[i];
		}

		SM3_initial(&sm3_ctx);
		SM3_update(&sm3_ctx, S.x, SM2_BYTE_LEN);
		SM3_update(&sm3_ctx, in_data, in_len);
		SM3_update(&sm3_ctx, S.y, SM2_BYTE_LEN);
		SM3_final(C3, &sm3_ctx);		
		if (out_len != NULL)
		{
			*out_len = SM2_CIPHER_LEN(in_len);
		}
	} while (0);
	
	return rtval;
}

int32_t fpga_sm2_encrypt_internal(uint16_t pub_key_index, uint8_t *in_data, uint32_t in_len, uint8_t *out_data, uint32_t *out_len)
{
	//查看FPGA是否支持 HSM2 SM2 算法  
	if((ArgFlag&0x01) == 0){
		return mcu_sm2_encrypt_internal(pub_key_index,in_data,in_len,out_data,out_len); //不支持,改为使用MCU
	}
	
	uint32_t i;
	int32_t rtval;
	uint8_t random[SM2_BYTE_LEN];
	SM2Point S;
	SM2Point *C1;
	uint8_t *C2;
	uint8_t *C3;
	SM3_CTX sm3_ctx;
	
	C1 = (SM2Point *)out_data;
	C3 = out_data + 2 * SM2_BYTE_LEN;
	C2 = out_data + 2 * SM2_BYTE_LEN + SM3_HASH_LEN;
	
	rtval = get_hrng(random, SM2_BYTE_LEN);
	if (rtval)
	{
		print(PRINT_FPGA,"f_sm2_enc ghrng er\r\n");
		return ERR_CIPN_RANDOM;
	}
	
	do
	{
		rtval = HSM2_sm2_encrypt_internal(pub_key_index*2, random, C1, &S);
		if (rtval)
		{
			break;
		}
		rtval = calcEncKDF(C2, in_len, &S);
		if (rtval)
		{
			break;
		}
		for (i = 0; i < in_len; i++)
		{
			C2[i] = C2[i] ^ in_data[i];
		}
		SM3_initial(&sm3_ctx);
		SM3_update(&sm3_ctx, S.x, SM2_BYTE_LEN);
		SM3_update(&sm3_ctx, in_data, in_len);
		SM3_update(&sm3_ctx, S.y, SM2_BYTE_LEN);
		SM3_final(C3, &sm3_ctx);
		if (out_len != NULL)
		{
			*out_len = SM2_CIPHER_LEN(in_len);
		}
	} while (0);
	
	return rtval;
}

int32_t fpga_sm2_decrypt_external(SM2PrivateKey *pri_key, uint8_t *in_data, uint32_t in_len, uint8_t *out_data, uint32_t *out_len)
{
	//查看FPGA是否支持 HSM2 SM2 算法  
	if((ArgFlag&0x01) == 0){
		return mcu_sm2_decrypt_external(pri_key,in_data,in_len,out_data,out_len); //不支持,改为使用MCU
	}
	
	uint32_t i;
	int32_t rtval;
	SM2Point S;
	SM2Point *C1;
	uint8_t *C2;
	uint8_t *C3;
	uint32_t C2_len;
	uint8_t hash[SM3_HASH_LEN];
	SM3_CTX sm3_ctx;
	
	if ( (2 * SM2_BYTE_LEN + SM3_HASH_LEN >=  in_len) ||  (2 * SM2_BYTE_LEN + SM3_HASH_LEN + 2048 < in_len) ) 
	{
		return ERR_CIPN_INDEXLEN;
	}
	
	C1 = (SM2Point *)in_data;
	C3 = in_data + 2 * SM2_BYTE_LEN;
	C2 = in_data + 2 * SM2_BYTE_LEN + SM3_HASH_LEN;
	C2_len = in_len - (2 * SM2_BYTE_LEN + SM3_HASH_LEN);
	
	do
	{
		rtval = HSM2_sm2_decrypt_external(pri_key, C1, &S);
		if (rtval)
		{
			//rtval = -2;
			break;
		}
		rtval = calcEncKDF(out_data, C2_len, &S);
		if (rtval)
		{
			//rtval = -3;
			break;
		}
		for (i = 0; i < C2_len; i++)
		{
			out_data[i] = out_data[i] ^ C2[i];
		}
		SM3_initial(&sm3_ctx);
		SM3_update(&sm3_ctx, S.x, SM2_BYTE_LEN);
		SM3_update(&sm3_ctx, out_data, C2_len);
		SM3_update(&sm3_ctx, S.y, SM2_BYTE_LEN);
		SM3_final(hash, &sm3_ctx);
		if (memcmp(C3, hash, SM3_HASH_LEN))
		{
			memset(out_data, 0, C2_len);
			//rtval = -4;
			rtval = SDR_ENCDATAERR;
			break;
		}
		if (out_len != NULL)
		{
			*out_len = C2_len;
		}
	} while (0);
	
	return rtval;
}

int32_t fpga_sm2_decrypt_internal(uint32_t pri_key_index, uint8_t *in_data, uint32_t in_len, uint8_t *out_data, uint32_t *out_len)
{
	//查看FPGA是否支持 HSM2 SM2 算法  
	if((ArgFlag&0x01) == 0){
		return mcu_sm2_decrypt_internal(pri_key_index,in_data,in_len,out_data,out_len); //不支持,改为使用MCU
	}
	uint32_t i;
	int32_t rtval;
	SM2Point S;
	SM2Point *C1;
	uint8_t *C2;
	uint8_t *C3;
	uint32_t C2_len;
	uint8_t hash[SM3_HASH_LEN];
	SM3_CTX sm3_ctx;
	
	if ( (2 * SM2_BYTE_LEN + SM3_HASH_LEN >=  in_len) ||  (2 * SM2_BYTE_LEN + SM3_HASH_LEN + 2048 < in_len) ) 
	{
		return ERR_CIPN_INDEXLEN;
	}
	
	C1 = (SM2Point *)in_data;
	C3 = in_data + 2 * SM2_BYTE_LEN;
	C2 = in_data + 2 * SM2_BYTE_LEN + SM3_HASH_LEN;
	C2_len = in_len - (2 * SM2_BYTE_LEN + SM3_HASH_LEN);
	
	do
	{
		rtval = HSM2_sm2_decrypt_internal(pri_key_index*2, C1, &S);
		if (rtval)
		{
			break;
		}
		rtval = calcEncKDF(out_data, C2_len, &S);
		if (rtval)
		{
			break;
		}
		for (i = 0; i < C2_len; i++)
		{
			out_data[i] = out_data[i] ^ C2[i];
		}
		SM3_initial(&sm3_ctx);
		SM3_update(&sm3_ctx, S.x, SM2_BYTE_LEN);
		SM3_update(&sm3_ctx, out_data, C2_len);
		SM3_update(&sm3_ctx, S.y, SM2_BYTE_LEN);
		SM3_final(hash, &sm3_ctx);
		if (memcmp(C3, hash, SM3_HASH_LEN))
		{
			memset(out_data, 0, C2_len);
			rtval = SDR_ENCDATAERR;
			break;
		}
		if (out_len != NULL)
		{
			*out_len = C2_len;
		}
	} while (0);
	
	return rtval;
}

int32_t fpga_sm2_sign_external(SM2PrivateKey *pri_key, uint8_t *hash, uint8_t *sign_r, uint8_t *sign_s)
{
	//查看FPGA是否支持 HSM2 SM2 算法  
	if((ArgFlag&0x01) == 0){
		return mcu_sm2_sign_external(pri_key,hash,sign_r,sign_s); //不支持,改为使用MCU
	}
	FPGAHeader fpga_header;
	int32_t rtval;
	uint8_t *alg_hdr;
	uint8_t *data_ptr,i=0,repeat=0;
	uint8_t random[SM2_BYTE_LEN],tail = 0;
if(HSMD1){
	i=find_hsmd1();
	tail = 32;
}
	do{
	rtval = get_hrng(random, SM2_BYTE_LEN);
	if (rtval)
	{
		print(PRINT_FPGA,"f_sm2_sign_ext ghrng err\r\n");
		return ERR_CIPN_RANDOM;
	}

	memset(&fpga_header, 0, sizeof(FPGAHeader));
	fpga_header.mark = FPGA_HEAD_MARK;
	fpga_header.src = FPGA_DATA_ARM;
	fpga_header.dst = FPGA_DATA_SM2_HSM2+i;
	fpga_header.channel = FPGA_CHANNEL_DEF;
	fpga_header.pkglen = FPGA_DATAHEAD_LEN + FPGA_MCUHEAD_LEN + 2 * SM2_BYTE_LEN + SM3_HASH_LEN;
	fpga_header.retpkglen = FPGA_DATAHEAD_LEN + 2 * SM2_BYTE_LEN + tail;
	fpga_header.sm2_cmd = CMD_SM2_SIGN;
	fpga_header.keytype = KEY_TYPE_INPACK;
	fpga_header.keyindex = 0;
//	print(PRINT_FPGA,"f_sm2_sign_external dst is %x\r\n",fpga_header.dst);
	//print(PRINT_FPGA,"f_sm2_sign_external cmd is %x\r\n",fpga_header.sm2_cmd);
	if(fpga_write_start()==REG_REST) return ERR_COMM_OUTTIME;
	alg_hdr = set_fpga_header((uint8_t *)FPGA_DATA_WRITE_ADDR, &fpga_header);
	data_ptr = alg_header(alg_hdr, 0, fpga_header.pkglen - FPGA_DATAHEAD_LEN, ENCRYPT_MODE, SM4_ECB_MODE, FPGA_DISABLE, 0, FPGA_DISABLE, 0);
if(!HSMD1){
	memcpy(data_ptr, random, SM2_BYTE_LEN);
	data_ptr += SM2_BYTE_LEN;
	memcpy(data_ptr, pri_key, sizeof(SM2PrivateKey));
	data_ptr += sizeof(SM2PrivateKey);
	memcpy(data_ptr, hash, SM3_HASH_LEN);
	data_ptr += SM3_HASH_LEN;
}
else{
	memcpy(data_ptr, hash, SM3_HASH_LEN);
	data_ptr += SM3_HASH_LEN;
	memcpy(data_ptr, pri_key, sizeof(SM2PrivateKey));
	data_ptr += sizeof(SM2PrivateKey);
	memcpy(data_ptr, random, SM2_BYTE_LEN);
	data_ptr += SM2_BYTE_LEN;
}
	fpga_write_finish(fpga_header.pkglen);
		
	data_ptr=fpga_read_start_ex();
	if( data_ptr == NULL){
		print(PRINT_FPGA,"fpga no data %x!\r\n",fpga_header.dst);
		return ERR_COMM_OUTTIME;
	}	
	get_fpga_header(&fpga_header, data_ptr);
	
#ifndef TEST
//if(HSMD1)
//#if NEW
//	repeat = hsmd1err_repeat(fpga_header.sm2_cmd,data_ptr,fpga_header.pkglen);
//	if(ERR_SECOND == repeat) return repeat;
//#endif
//#endif
	if ((fpga_header.channel & 0xE0) != 0x20 && (fpga_header.channel & 0xE0) != 0x00 && OK_SECOND != repeat && ERR_FIRST != repeat)
	{
		fpga_read_finish();
		return -1;
	}
#endif

}while(repeat & 0x0f);
	data_ptr = (uint8_t *)(data_ptr + FPGA_DATAHEAD_LEN);
	memcpy(sign_r, data_ptr, SM2_BYTE_LEN);
	data_ptr += SM2_BYTE_LEN;
	memcpy(sign_s, data_ptr, SM2_BYTE_LEN);
	fpga_read_finish();

	return 0;
}

int32_t fpga_sm2_sign_internal(uint16_t pri_key_index, uint8_t *hash, uint8_t *sign_r, uint8_t *sign_s)
{
	if((ArgFlag&0x01) == 0){
		return mcu_sm2_sign_internal(pri_key_index,hash,sign_r,sign_s); //不支持,改为使用MCU。
	}
	FPGAHeader fpga_header;
	int32_t rtval;
	uint8_t *alg_hdr;
	uint8_t *data_ptr;
	uint8_t random[SM2_BYTE_LEN],i=0,repeat = 0,tail = 0;
if(HSMD1){
	i=find_hsmd1();
	tail = 32;
}
	do{
	rtval = get_hrng(random, SM2_BYTE_LEN);
	if (rtval)
	{
		print(PRINT_FPGA,"f_sm2_sign_ext ghrng err\r\n");
		return ERR_CIPN_RANDOM;
	}
	
	memset(&fpga_header, 0, sizeof(FPGAHeader));
	fpga_header.mark = FPGA_HEAD_MARK;
	fpga_header.src = FPGA_DATA_ARM;
	fpga_header.dst = FPGA_DATA_SM2_HSM2+i;
	fpga_header.channel = FPGA_CHANNEL_DEF;
	fpga_header.pkglen = FPGA_DATAHEAD_LEN + FPGA_MCUHEAD_LEN + SM2_BYTE_LEN + SM3_HASH_LEN;
	fpga_header.retpkglen = FPGA_DATAHEAD_LEN + 2 * SM2_BYTE_LEN + tail;
	fpga_header.sm2_cmd = CMD_SM2_SIGN;
	fpga_header.keytype = KEY_TYPE_LOOKUP;
	fpga_header.keyindex = pri_key_index*2+1;
//	print(PRINT_FPGA,"f_sm2_sign_internal dst is %x\r\n",fpga_header.dst);
	if(fpga_write_start()==REG_REST) return ERR_COMM_OUTTIME;
	alg_hdr = set_fpga_header((uint8_t *)FPGA_DATA_WRITE_ADDR, &fpga_header);
	data_ptr = alg_header(alg_hdr, 0, fpga_header.pkglen - FPGA_DATAHEAD_LEN, ENCRYPT_MODE, SM4_ECB_MODE, FPGA_DISABLE, 0, FPGA_DISABLE, 0);

if(!HSMD1){
	memcpy(data_ptr, random, SM2_BYTE_LEN);
	data_ptr += SM2_BYTE_LEN;
	memcpy(data_ptr, hash, SM3_HASH_LEN);
	data_ptr += SM3_HASH_LEN;
}
else{
	memcpy(data_ptr, hash, SM3_HASH_LEN);
	data_ptr += SM3_HASH_LEN;
	memcpy(data_ptr, random, SM2_BYTE_LEN);
	data_ptr += SM2_BYTE_LEN;
}

	fpga_write_finish(fpga_header.pkglen);
	data_ptr=fpga_read_start_ex();
	if( data_ptr == NULL){
		print(PRINT_FPGA,"fpga no data %x!\r\n",fpga_header.dst);
		return ERR_COMM_OUTTIME;
	}	
	get_fpga_header(&fpga_header, data_ptr);
#ifndef TEST
//if(HSMD1)
//#if NEW
//	repeat = hsmd1err_repeat(fpga_header.sm2_cmd,data_ptr,fpga_header.pkglen);
//	printf_buff_byte((uint8_t *)data_ptr,fpga_header.pkglen);
//	if(ERR_SECOND == repeat) return repeat;
//#endif
//#endif
	if ((fpga_header.channel & 0xE0) != 0x20)
	{
		fpga_read_finish();
		return -2;
	}
#endif
	}while(repeat & 0x0f);
	data_ptr = (uint8_t *)(data_ptr + FPGA_DATAHEAD_LEN);
	memcpy(sign_r, data_ptr, SM2_BYTE_LEN);
	data_ptr += SM2_BYTE_LEN;
	memcpy(sign_s, data_ptr, SM2_BYTE_LEN);
	fpga_read_finish();
	
	return 0;
}

int32_t fpga_sm2_verify_external(SM2PublicKey *pub_key, uint8_t *sign_r, uint8_t *sign_s, uint8_t *hash)
{
	if((ArgFlag&0x01) == 0){
		return mcu_sm2_verify_external(pub_key,sign_r,sign_s,hash); //不支持,改为使用MCU
	}
	FPGAHeader fpga_header;
	uint8_t *alg_hdr;
	uint8_t *data_ptr,i=0,repeat=0,tail = 0;
if(HSMD1){
	i=find_hsmd1();
	tail = 32;
}
do{
	memset(&fpga_header, 0, sizeof(FPGAHeader));
	fpga_header.mark = FPGA_HEAD_MARK;
	fpga_header.src = FPGA_DATA_ARM;
	fpga_header.dst = FPGA_DATA_SM2_HSM2+i;
	fpga_header.channel = FPGA_CHANNEL_DEF;
	fpga_header.pkglen = FPGA_DATAHEAD_LEN + FPGA_MCUHEAD_LEN + 2 * SM2_BYTE_LEN + SM3_HASH_LEN + 2 * SM2_BYTE_LEN;
	fpga_header.retpkglen = FPGA_DATAHEAD_LEN + tail;
	fpga_header.sm2_cmd = CMD_SM2_VERIFY | (repeat & 0x0f);
	fpga_header.keytype = KEY_TYPE_INPACK;
	fpga_header.keyindex = 0;
//	print(PRINT_FPGA,"f_sm2_verify_external dst is %x\r\n",fpga_header.dst);
	if(fpga_write_start()==REG_REST) return ERR_COMM_OUTTIME;
	alg_hdr = set_fpga_header((uint8_t *)FPGA_DATA_WRITE_ADDR, &fpga_header);
	data_ptr = alg_header(alg_hdr, 0, fpga_header.pkglen - FPGA_DATAHEAD_LEN, ENCRYPT_MODE, SM4_ECB_MODE, FPGA_DISABLE, 0, FPGA_DISABLE, 0);
if(!HSMD1){
	memcpy(data_ptr, pub_key, sizeof(SM2PublicKey));
	data_ptr += sizeof(SM2PublicKey);
	memcpy(data_ptr, hash, SM3_HASH_LEN);
	data_ptr += SM3_HASH_LEN;
	memcpy(data_ptr, sign_r, SM2_BYTE_LEN);
	data_ptr += SM2_BYTE_LEN;
	memcpy(data_ptr, sign_s, SM2_BYTE_LEN);
	data_ptr += SM2_BYTE_LEN;
}
else{
	memcpy(data_ptr, hash, SM3_HASH_LEN);
	data_ptr += SM3_HASH_LEN;
	memcpy(data_ptr, pub_key, sizeof(SM2PublicKey));
	data_ptr += sizeof(SM2PublicKey);
	memcpy(data_ptr, sign_r, SM2_BYTE_LEN);
	data_ptr += SM2_BYTE_LEN;
	memcpy(data_ptr, sign_s, SM2_BYTE_LEN);
	data_ptr += SM2_BYTE_LEN;
}
	fpga_write_finish(fpga_header.pkglen);
		
	data_ptr=fpga_read_start_ex();
	if( data_ptr == NULL){
		print(PRINT_FPGA,"fpga no data %x!\r\n",fpga_header.dst);
		return ERR_COMM_OUTTIME;
	}	
	get_fpga_header(&fpga_header, data_ptr);
	#ifndef TEST
if(HSMD1){
#if NEW
	repeat = hsmd1err_repeat(fpga_header.sm2_cmd,data_ptr,fpga_header.pkglen);
	if(ERR_SECOND == repeat) return repeat;
#endif
}
	if ((fpga_header.channel & 0xE0) != 0x20 && (fpga_header.channel & 0xE0) != 0x00)
	{
		fpga_read_finish();
		return -1;
	}
#endif
	}while(repeat & 0x0f);
	fpga_read_finish();
	
	return 0;
}

int32_t fpga_sm2_verify_internal(uint16_t pub_key_index, uint8_t *sign_r, uint8_t *sign_s, uint8_t *hash)
{
	//查看FPGA是否支持 HSM2 SM2 算法 
	if((ArgFlag&0x01) == 0){
		return mcu_sm2_verify_internal(pub_key_index,sign_r,sign_s,hash); //不支持,改为使用MCU
	}
	FPGAHeader fpga_header;
	uint8_t *alg_hdr;
	uint8_t *data_ptr,i=0,repeat = 0,tail = 0;
if(HSMD1){
	i=find_hsmd1();
	tail = 32;
}
	do{
	memset(&fpga_header, 0, sizeof(FPGAHeader));
	fpga_header.mark = FPGA_HEAD_MARK;
	fpga_header.src = FPGA_DATA_ARM;
	fpga_header.dst = FPGA_DATA_SM2_HSM2+i;
	fpga_header.channel = FPGA_CHANNEL_DEF;
	fpga_header.pkglen = FPGA_DATAHEAD_LEN + FPGA_MCUHEAD_LEN + SM3_HASH_LEN + 2 * SM2_BYTE_LEN;
	fpga_header.retpkglen = FPGA_DATAHEAD_LEN + tail;
	fpga_header.sm2_cmd = CMD_SM2_VERIFY | (repeat & 0x0f);
	fpga_header.keytype = KEY_TYPE_LOOKUP;
	fpga_header.keyindex = pub_key_index*2+1;
//	print(PRINT_FPGA,"f_sm2_verify_internal dst is %x\r\n",fpga_header.dst);
	if(fpga_write_start()==REG_REST) return ERR_COMM_OUTTIME;
	alg_hdr = set_fpga_header((uint8_t *)FPGA_DATA_WRITE_ADDR, &fpga_header);
	data_ptr = alg_header(alg_hdr, 0, fpga_header.pkglen - FPGA_DATAHEAD_LEN, ENCRYPT_MODE, SM4_ECB_MODE, FPGA_DISABLE, 0, FPGA_DISABLE, 0);
if(!HSMD1){
	memcpy(data_ptr, hash, SM3_HASH_LEN);
	data_ptr += SM3_HASH_LEN;
	memcpy(data_ptr, sign_r, SM2_BYTE_LEN);
	data_ptr += SM2_BYTE_LEN;
	memcpy(data_ptr, sign_s, SM2_BYTE_LEN);
	data_ptr += SM2_BYTE_LEN;
}else{
	memcpy(data_ptr, hash, SM3_HASH_LEN);
	data_ptr += SM3_HASH_LEN;
	memcpy(data_ptr, sign_r, SM2_BYTE_LEN);
	data_ptr += SM2_BYTE_LEN;
	memcpy(data_ptr, sign_s, SM2_BYTE_LEN);
	data_ptr += SM2_BYTE_LEN;
}
	fpga_write_finish(fpga_header.pkglen);
	data_ptr=fpga_read_start_ex();
	if( data_ptr == NULL){
		print(PRINT_FPGA,"fpga no data %x!\r\n",fpga_header.dst);
		return ERR_COMM_OUTTIME;
	}	
	get_fpga_header(&fpga_header, data_ptr);
#ifndef TEST
if(HSMD1){
#if NEW
	repeat = hsmd1err_repeat(fpga_header.sm2_cmd,data_ptr,fpga_header.pkglen);
//	printf_buff_byte((uint8_t *)data_ptr,fpga_header.pkglen);
	if(ERR_SECOND == repeat) return repeat;
#endif
}
	if ((fpga_header.channel & 0xE0) != 0x20)
	{
		fpga_read_finish();
		return -1;
	}
#endif
	}while(repeat & 0x0f);
	fpga_read_finish();
	
	return 0;
}

int32_t fpga_sm2_generate_keypair(SM2PrivateKey *pri_key, SM2PublicKey *pub_key)
{
	if((ArgFlag&0x01) == 0){
		ECC_G_STR sm2_para;
		SM2_param_init(&sm2_para);
		return SM2_Gen_Keypair(&sm2_para,(uint8_t*)pri_key,(uint8_t*)(pub_key->x),(uint8_t*)(pub_key->y));
	}
	int32_t rtval;
	FPGAHeader fpga_header;
	uint8_t *alg_hdr;
	uint8_t *data_ptr;
	uint8_t random[SM2_BYTE_LEN],i=0;
if(HSMD1){
	i=find_hsmd1();
}
	
	rtval = get_hrng(random, SM2_BYTE_LEN);
	if (rtval)
	{
		print(PRINT_FPGA,"f_sm2_enc ghrng err\r\n");
		return ERR_CIPN_RANDOM;
	}
	
	memset(&fpga_header, 0, sizeof(FPGAHeader));
	fpga_header.mark = FPGA_HEAD_MARK;
	fpga_header.src = FPGA_DATA_ARM;
	fpga_header.dst = FPGA_DATA_SM2_HSM2+i;
	fpga_header.channel = FPGA_CHANNEL_DEF;
	fpga_header.pkglen = FPGA_DATAHEAD_LEN + FPGA_MCUHEAD_LEN + SM2_BYTE_LEN;
	fpga_header.retpkglen = FPGA_DATAHEAD_LEN + 3 * SM2_BYTE_LEN;
	fpga_header.sm2_cmd = CMD_SM2_GENKEY;
	fpga_header.keytype = KEY_TYPE_INPACK;
	fpga_header.keyindex = 0;
	
	if(fpga_write_start()==REG_REST) return ERR_COMM_OUTTIME;
	alg_hdr = set_fpga_header((uint8_t *)FPGA_DATA_WRITE_ADDR, &fpga_header);
	data_ptr = alg_header(alg_hdr, 0, fpga_header.pkglen - FPGA_DATAHEAD_LEN, ENCRYPT_MODE, SM4_ECB_MODE, FPGA_DISABLE, 0, FPGA_DISABLE, 0);
	memcpy(data_ptr, random, SM2_BYTE_LEN);
	data_ptr += SM2_BYTE_LEN;
	fpga_write_finish(fpga_header.pkglen);
	
	data_ptr = fpga_read_start_ex();
	if( data_ptr == NULL){
		print(PRINT_FPGA,"fpga no data %x!\r\n",fpga_header.dst);
		return ERR_COMM_OUTTIME;
	}	
	get_fpga_header(&fpga_header, data_ptr);
#ifndef TEST
	if ((fpga_header.channel & 0xE0) != 0x20 && (fpga_header.channel & 0xE0) != 0x00)
	{
		fpga_read_finish();
		return -2;
	}
#endif
	data_ptr = (uint8_t *)(data_ptr + FPGA_DATAHEAD_LEN);
if(!HSMD1){
	memcpy(pri_key, data_ptr, sizeof(SM2PrivateKey));
	data_ptr += sizeof(SM2PrivateKey);
	memcpy(pub_key, data_ptr, sizeof(SM2PublicKey));
}
else{
	memcpy(pub_key, data_ptr, sizeof(SM2PublicKey));
	data_ptr += sizeof(SM2PublicKey);
	memcpy(pri_key, data_ptr, sizeof(SM2PrivateKey));
}
	fpga_read_finish();
	
	return 0;
}

ECC_G_STR sm2_para;
int32_t sm2_agreement_genkey(uint8_t *other_id, uint32_t other_id_len, SM2PublicKey *other_pubkey, SM2PublicKey *other_temp_pubkey, void *agreement_handler, uint8_t *agreement_key)
{
	int32_t rtval;
	uint8_t ZA[SM3_HASH_LEN];
	uint8_t ZB[SM3_HASH_LEN];
	SM2Point U;
	AgreementData *agreement_data = (AgreementData *)agreement_handler;

	if (agreement_data->is_initor == 0)
	{
		SM2_getZ(&sm2_para, other_id, other_id_len, other_pubkey->x, other_pubkey->y, ZA);
		SM2_getZ(&sm2_para, agreement_data->id, agreement_data->idlen, agreement_data->pk.x, agreement_data->pk.y, ZB);
	}
	else
	{
		SM2_getZ(&sm2_para, other_id, other_id_len, other_pubkey->x, other_pubkey->y, ZB);
		SM2_getZ(&sm2_para, agreement_data->id, agreement_data->idlen, agreement_data->pk.x, agreement_data->pk.y, ZA);		
	}
	
	rtval = HSM2_sm2_exchange_key(&agreement_data->tmpsk, &agreement_data->tmppk, &agreement_data->sk, other_temp_pubkey, other_pubkey, &U);
	if (rtval)
	{
		print(PRINT_FPGA,"sm2_ex_key sm2_ex_key err %d\r\n", rtval);
		return ERR_CIPN_SM2ARGEEXCHE;
	}
	
	rtval = calcKeyExKDF(agreement_key, BIT_TO_BYTE(agreement_data->key_bits), &U, ZA, ZB);
	if (rtval)
	{
		print(PRINT_FPGA,"sm2_ag_genkey calcKeyExKDF err %d\r\n", rtval);
		return 0;
	}
	
	return 0;
}

int32_t fpga_sm2_agreement_generate_data(uint16_t isk_index, uint32_t key_bits, uint8_t *sponsor_id, uint32_t id_len, SM2PublicKey *sponsor_pubkey, SM2PublicKey *sponsor_tmp_pubkey, void **agreement_handle)
{

//if(HSMD1)
	return mcu_sm2_agreement_generate_data(isk_index,key_bits,sponsor_id,id_len,sponsor_pubkey,sponsor_tmp_pubkey,agreement_handle);
//#endif
	//查看FPGA是否支持 HSM2 SM2 算法
	if((ArgFlag&0x01) == 0){
		return mcu_sm2_agreement_generate_data(isk_index,key_bits,sponsor_id,id_len,sponsor_pubkey,sponsor_tmp_pubkey,agreement_handle);
	}
	int32_t rtval;
	AgreementData *agreement_data;
	
	agreement_data = sd_malloc(sizeof(AgreementData) + id_len);
	if (agreement_data == NULL)
	{
		print(PRINT_FPGA,"f_sm2_ag_gen_data malloc err\r\n");
		return ERR_COMM_MALLOC;
	}
	
	print(PRINT_FPGA,"");
	rtval = fpga_sm2_getkey(2*isk_index, &agreement_data->sk, &agreement_data->pk);
	if (rtval)
	{
		sd_free(agreement_data);
		print(PRINT_FPGA,"f_sm2_ag_gen_data fpga_sm2_gkey err %d!!!\r\n", rtval);
		return ERR_CIPN_GETSM2KEY;
	}
//	memcpy(&agreement_data->sk, self_prikey, sizeof(SM2PrivateKey));
//	memcpy(&agreement_data->pk, self_pubkey, sizeof(SM2PublicKey));
	
	rtval = fpga_sm2_generate_keypair(&agreement_data->tmpsk, &agreement_data->tmppk);
	if (rtval)
	{
		sd_free(agreement_data);
		print(PRINT_FPGA,"f_sm2_ag_gen_data fpga_sm2_gen_key err %d!!!\r\n", rtval);
		return ERR_CIPN_GENSM2KEY;
	}
	
	agreement_data->is_initor = 1;
	agreement_data->key_bits = key_bits;
	agreement_data->idlen = id_len;
	memcpy(agreement_data->id, sponsor_id, id_len);
	
	memcpy(sponsor_pubkey, &agreement_data->pk, sizeof(SM2PublicKey));
	memcpy(sponsor_tmp_pubkey, &agreement_data->tmppk, sizeof(SM2PublicKey));
	*agreement_handle = agreement_data;

	return 0;
}

int32_t fpga_sm2_agreement_generate_data_key(uint16_t isk_index, uint32_t key_bits, uint8_t *responsor_id, uint32_t responsor_id_len, 
												uint8_t *sponsor_id, uint32_t sponsor_id_len, SM2PublicKey *sponsor_pubkey, SM2PublicKey *sponsor_temp_pubkey,
												SM2PublicKey *responsor_pubkey, SM2PublicKey *responsor_temp_pubkey, uint32_t *key_index)
{
//if(HSMD1)
	return mcu_sm2_agreement_generate_data_key(isk_index,key_bits,responsor_id,responsor_id_len,sponsor_id,sponsor_id_len,sponsor_pubkey,sponsor_temp_pubkey,responsor_pubkey,responsor_temp_pubkey,key_index);
//#endif
	//查看FPGA是否支持 HSM2 SM2 算法 
	if((ArgFlag&0x01) == 0){
		return mcu_sm2_agreement_generate_data_key(isk_index,key_bits,responsor_id,responsor_id_len,sponsor_id,sponsor_id_len,sponsor_pubkey,sponsor_temp_pubkey,responsor_pubkey,responsor_temp_pubkey,key_index);
	}

	int32_t rtval;
	AgreementData *agreement_data;
	uint8_t agreement_key[64];
	
	agreement_data = sd_malloc(sizeof(AgreementData) + responsor_id_len);
	if (agreement_data == NULL)
	{
		print(PRINT_FPGA,"f_sm2_agr_gen_data malloc err\r\n");
		return ERR_COMM_MALLOC;
	}
	
	rtval = fpga_sm2_getkey(2*isk_index, &agreement_data->sk, &agreement_data->pk);
	if (rtval)
	{
		sd_free(agreement_data);
		print(PRINT_FPGA,"f_sm2_ag_gen_data f_sm2_gkey err %d!!!\r\n", rtval);
		return ERR_CIPN_GETSM2KEY;
	}
	
	rtval = fpga_sm2_generate_keypair(&agreement_data->tmpsk, &agreement_data->tmppk);
	if (rtval)
	{
		sd_free(agreement_data);
		print(PRINT_FPGA,"f_sm2_ag_gen_data f_sm2_gen_key err %d!!!\r\n", rtval);
		return ERR_CIPN_GENSM2KEY;
	}
	
	agreement_data->is_initor = 0;
	agreement_data->key_bits = key_bits;
	agreement_data->idlen = responsor_id_len;
	memcpy(agreement_data->id, responsor_id, responsor_id_len);
	
	rtval = sm2_agreement_genkey(sponsor_id, sponsor_id_len, sponsor_pubkey, sponsor_temp_pubkey, agreement_data, agreement_key);
	if (rtval)
	{
		print(PRINT_FPGA,"f_sm2_ag_gen_data_key sm2_ag_genkey err %d\r\n", rtval);
		sd_free(agreement_data);
		return ERR_CIPN_SM2ARGENKEY;
	}
	
	memcpy(responsor_pubkey, &agreement_data->pk, sizeof(SM2PublicKey));
	memcpy(responsor_temp_pubkey, &agreement_data->tmppk, sizeof(SM2PublicKey));
//	printfs("f_sm2_agreement_generate_data_key agreement_key is: \r\n");
//	printfb(agreement_key, BIT_TO_BYTE(key_bits));
	rtval = writer_sessionkey_mcufpga(BIT_TO_BYTE(key_bits), agreement_key, key_index);
	sd_free(agreement_data);
	return rtval;
}


int32_t fpga_sm2_agreement_generate_key(uint8_t *response_id, uint32_t response_id_len, 
										SM2PublicKey *response_pubkey, SM2PublicKey *response_temp_pubkey, 
										void *agreement_handle, uint32_t *key_index)
{
//if(HSMD1)
	return mcu_sm2_agreement_generate_key(response_id,response_id_len,response_pubkey,response_temp_pubkey,agreement_handle,key_index);

	//查看FPGA是否支持 HSM2 SM2 算法 
	if((ArgFlag&0x01) == 0){
		return mcu_sm2_agreement_generate_key(response_id,response_id_len,response_pubkey,response_temp_pubkey,agreement_handle,key_index);
	}
	int32_t rtval;
	uint8_t agreement_key[64];
	AgreementData *agreement_data = (AgreementData *)agreement_handle;
		
	rtval = sm2_agreement_genkey(response_id, response_id_len, response_pubkey, response_temp_pubkey, agreement_handle, agreement_key);
	if (rtval)
	{
		print(PRINT_FPGA,"f_sm2_ag_gen_key sm2_ag_genkey err %d\r\n", rtval);
		sd_free(agreement_handle);
		return ERR_CIPN_SM2ARGENKEY;
	}
//	printfs("f_sm2ag_gen_key ag_key is: \r\n");
//	printfb(ag_key, BIT_TO_BYTE(ag_data->key_bits));
	rtval = writer_sessionkey_mcufpga(BIT_TO_BYTE(agreement_data->key_bits), agreement_key, key_index);
	sd_free(agreement_handle);
	return rtval;
}

int32_t fpga_ssx1510_sign_external(SM2PrivateKey *pri_key, uint8_t *hash, uint8_t *sign_r, uint8_t *sign_s)
{
	FPGAHeader fpga_header;
	int32_t rtval;
	uint8_t *alg_hdr;
	uint8_t *data_ptr;
	uint8_t random[SM2_BYTE_LEN];
	uint8_t test_random[SM2_BYTE_LEN] = 
{
	0x25, 0x00, 0xe6, 0x08, 0xd8, 0x14, 0x9b, 0xf0, 0x25, 0x73, 0xce, 0x39, 0xd2, 0xc5, 0x6b, 0x23,
	0x13, 0x90, 0x0d, 0xfe, 0xa7, 0xd8, 0x14, 0x9b, 0xb3, 0xbb, 0x25, 0x73, 0x39, 0x54, 0xe0, 0x49
};
	rtval = get_hrng(random, SM2_BYTE_LEN);
	if (rtval)
	{
		print(PRINT_FPGA,"f_sm2_sign_ext ghrng err\r\n");
		return ERR_CIPN_RANDOM;
	}
	
	memcpy(random, test_random, SM2_BYTE_LEN);
	
	memset(&fpga_header, 0, sizeof(FPGAHeader));
	fpga_header.mark = FPGA_HEAD_MARK;
	fpga_header.src = FPGA_DATA_ARM;
	fpga_header.dst = FPGA_DATA_SM2_SSX;
	fpga_header.channel = FPGA_CHANNEL_DEF;
	fpga_header.pkglen = FPGA_DATAHEAD_LEN + FPGA_MCUHEAD_LEN + 2 * SM2_BYTE_LEN + SM3_HASH_LEN;
	fpga_header.retpkglen = FPGA_DATAHEAD_LEN + 2 * SM2_BYTE_LEN;
	fpga_header.sm2_cmd = CMD_SM2_SIGN;
	fpga_header.keytype = KEY_TYPE_INPACK;
	fpga_header.keyindex = 0;
	
	if(fpga_write_start()==REG_REST) return ERR_COMM_OUTTIME;
	alg_hdr = set_fpga_header((uint8_t *)FPGA_DATA_WRITE_ADDR, &fpga_header);
	data_ptr = alg_header(alg_hdr, 0, fpga_header.pkglen - FPGA_DATAHEAD_LEN, ENCRYPT_MODE, SM4_ECB_MODE, FPGA_DISABLE, 0, FPGA_DISABLE, 0);
	memcpy(data_ptr, random + SM2_BYTE_LEN / 2, SM2_BYTE_LEN / 2);
	data_ptr += SM2_BYTE_LEN / 2;
	memcpy(data_ptr, random, SM2_BYTE_LEN / 2);
	data_ptr += SM2_BYTE_LEN / 2;
	memcpy(data_ptr, pri_key->K + SM2_BYTE_LEN / 2, SM2_BYTE_LEN / 2);
	data_ptr += SM2_BYTE_LEN / 2;
	memcpy(data_ptr, pri_key->K, SM2_BYTE_LEN / 2);
	data_ptr += SM2_BYTE_LEN / 2;	
	memcpy(data_ptr, hash + SM2_BYTE_LEN / 2, SM2_BYTE_LEN / 2);
	data_ptr += SM2_BYTE_LEN / 2;
	memcpy(data_ptr, hash, SM2_BYTE_LEN / 2);
	fpga_write_finish(fpga_header.pkglen);
	
//	print(PRINT_FPGA,"fpga_ssx1510_sign_external send data is: \r\n");
//	print_byte((uint8_t *)FPGA_DATA_WRITE_ADDR, fpga_header.pkglen);
		
//	fpga_buff_read_start();
//	rtval = fpga_recv_buff_process(FPGA_BUFF_ID);
//	if (rtval)
//	{
//		print(PRINT_FPGA,"fpga_recv_buff_process error!!!\r\n");
//		return -1;
//	}
	uint8_t *mcu_recv_buff = fpga_read_start_ex();
	if( mcu_recv_buff == NULL){
		print(PRINT_FPGA,"fpga no data %x!\r\n",fpga_header.dst);
		return ERR_COMM_OUTTIME;
	}	
	get_fpga_header(&fpga_header, (uint8_t *)mcu_recv_buff);
#ifndef TEST
	if ((fpga_header.channel & 0xE0) != 0x20 && (fpga_header.channel & 0xE0) != 0x00)
	{
		return -2;
	}
#endif
	data_ptr = (uint8_t *)(mcu_recv_buff + FPGA_DATAHEAD_LEN);
	
//	memcpy(sign_r, data_ptr, SM2_BYTE_LEN);
//	data_ptr += SM2_BYTE_LEN;
//	memcpy(sign_s, data_ptr, SM2_BYTE_LEN);
//	data_ptr += SM2_BYTE_LEN;
	
	memcpy(sign_r + SM2_BYTE_LEN / 2, data_ptr, SM2_BYTE_LEN / 2);
	data_ptr += SM2_BYTE_LEN / 2;
	memcpy(sign_r, data_ptr, SM2_BYTE_LEN / 2);
	data_ptr += SM2_BYTE_LEN / 2;
	memcpy(sign_s + SM2_BYTE_LEN / 2, data_ptr, SM2_BYTE_LEN / 2);
	data_ptr += SM2_BYTE_LEN / 2;
	memcpy(sign_s, data_ptr, SM2_BYTE_LEN / 2);
	data_ptr += SM2_BYTE_LEN / 2;
	
//	print(PRINT_FPGA,"fpga_ssx1510_sign_external sign_r is: \r\n");
//	print_byte(sign_r, SM2_BYTE_LEN);
//	print(PRINT_FPGA,"fpga_ssx1510_sign_external sign_s is: \r\n");
//	print_byte(sign_s, SM2_BYTE_LEN);
	
	return 0;
}

int32_t fpga_ssx1510_verify_external(SM2PublicKey *pub_key, uint8_t *sign_r, uint8_t *sign_s, uint8_t *hash)
{
//	int32_t rtval;
	FPGAHeader fpga_header;
	uint8_t *alg_hdr;
	uint8_t *data_ptr;
	
	memset(&fpga_header, 0, sizeof(FPGAHeader));
	fpga_header.mark = FPGA_HEAD_MARK;
	fpga_header.src = FPGA_DATA_ARM;
	fpga_header.dst = FPGA_DATA_SM2_SSX;
	fpga_header.channel = FPGA_CHANNEL_DEF;
	fpga_header.pkglen = FPGA_DATAHEAD_LEN + FPGA_MCUHEAD_LEN + 2 * SM2_BYTE_LEN + SM3_HASH_LEN + 2 * SM2_BYTE_LEN;
	fpga_header.retpkglen = FPGA_DATAHEAD_LEN;
	fpga_header.sm2_cmd = CMD_SM2_VERIFY;
	fpga_header.keytype = KEY_TYPE_INPACK;
	fpga_header.keyindex = 0;
	
	if(fpga_write_start()==REG_REST) return ERR_COMM_OUTTIME;
	alg_hdr = set_fpga_header((uint8_t *)FPGA_DATA_WRITE_ADDR, &fpga_header);
	data_ptr = alg_header(alg_hdr, 0, fpga_header.pkglen - FPGA_DATAHEAD_LEN, ENCRYPT_MODE, SM4_ECB_MODE, FPGA_DISABLE, 0, FPGA_DISABLE, 0);
	memcpy(data_ptr, pub_key->x + SM2_BYTE_LEN / 2, SM2_BYTE_LEN / 2);
	data_ptr += SM2_BYTE_LEN / 2;
	memcpy(data_ptr, pub_key->x, SM2_BYTE_LEN / 2);
	data_ptr += SM2_BYTE_LEN / 2;
	memcpy(data_ptr, pub_key->y + SM2_BYTE_LEN / 2, SM2_BYTE_LEN / 2);
	data_ptr += SM2_BYTE_LEN / 2;
	memcpy(data_ptr, pub_key->y, SM2_BYTE_LEN / 2);
	data_ptr += SM2_BYTE_LEN / 2;
	memcpy(data_ptr, sign_r + SM2_BYTE_LEN / 2, SM2_BYTE_LEN / 2);
	data_ptr += SM2_BYTE_LEN / 2;
	memcpy(data_ptr, sign_r, SM2_BYTE_LEN / 2);
	data_ptr += SM2_BYTE_LEN / 2;
	memcpy(data_ptr, sign_s + SM2_BYTE_LEN / 2, SM2_BYTE_LEN / 2);
	data_ptr += SM2_BYTE_LEN / 2;
	memcpy(data_ptr, sign_s, SM2_BYTE_LEN / 2);
	data_ptr += SM2_BYTE_LEN / 2;
	memcpy(data_ptr, hash + SM2_BYTE_LEN / 2, SM2_BYTE_LEN / 2);
	data_ptr += SM2_BYTE_LEN / 2;
	memcpy(data_ptr, hash, SM2_BYTE_LEN / 2);
	data_ptr += SM2_BYTE_LEN / 2;
	fpga_write_finish(fpga_header.pkglen);
	
//	print_byte((uint8_t *)FPGA_DATA_WRITE_ADDR, fpga_header.pkglen);
		
//	fpga_buff_read_start();
//	rtval = fpga_recv_buff_process(FPGA_BUFF_ID);
//	if (rtval)
//	{
//		print(PRINT_FPGA,"fpga_recv_buff_process error!!!\r\n");
//		return -1;
//	}
	uint8_t *mcu_recv_buff = fpga_read_start_ex();
	if( mcu_recv_buff == NULL){
		print(PRINT_FPGA,"fpga no data %x!\r\n",fpga_header.dst);
		return ERR_COMM_OUTTIME;
	}	
	get_fpga_header(&fpga_header, (uint8_t *)mcu_recv_buff);
#ifndef TEST
	if ((fpga_header.channel & 0xE0) != 0x20 && (fpga_header.channel & 0xE0) != 0x00)
	{
		return -2;
	}
#endif
	return 0;
}

int32_t fpga_ssx1510_gen_keypair(SM2PrivateKey *pri_key, SM2PublicKey *pub_key)
{
	int32_t rtval;
	FPGAHeader fpga_header;
	uint8_t *alg_hdr;
	uint8_t *data_ptr;
	uint8_t random[SM2_BYTE_LEN];
	uint8_t sm2_base_x[] =
{
	0x32, 0xC4, 0xAE, 0x2C, 0x1F, 0x19, 0x81, 0x19, 0x5F, 0x99, 0x04, 0x46, 0x6A, 0x39, 0xC9, 0x94, 0x8F, 0xE3, 0x0B, 0xBF, 0xF2, 0x66, 0x0B, 0xE1, 0x71, 0x5A, 0x45, 0x89, 0x33, 0x4C, 0x74, 0xC7
};
uint8_t sm2_base_y[] =
{
	0xBC, 0x37, 0x36, 0xA2, 0xF4, 0xF6, 0x77, 0x9C, 0x59, 0xBD, 0xCE, 0xE3, 0x6B, 0x69, 0x21, 0x53, 0xD0, 0xA9, 0x87, 0x7C, 0xC6, 0x2A, 0x47, 0x40, 0x02, 0xDF, 0x32, 0xE5, 0x21, 0x39, 0xF0, 0xA0
};
	rtval = get_hrng(random, SM2_BYTE_LEN);
	if (rtval)
	{
		print(PRINT_FPGA,"f_sm2_enc ghrng err\r\n");
		return ERR_CIPN_RANDOM;
	}
	
	memset(&fpga_header, 0, sizeof(FPGAHeader));
	fpga_header.mark = FPGA_HEAD_MARK;
	fpga_header.src = FPGA_DATA_ARM;
	fpga_header.dst = FPGA_DATA_SM2_SSX;
	fpga_header.channel = FPGA_CHANNEL_DEF;
	fpga_header.pkglen = FPGA_DATAHEAD_LEN + FPGA_MCUHEAD_LEN + 3 * SM2_BYTE_LEN;
	fpga_header.retpkglen = FPGA_DATAHEAD_LEN + 2 * SM2_BYTE_LEN;
	fpga_header.sm2_cmd = CMD_SM2_PTMUL;
	fpga_header.keytype = KEY_TYPE_INPACK;
	fpga_header.keyindex = 0;

	if(fpga_write_start()==REG_REST) return ERR_COMM_OUTTIME;
	alg_hdr = set_fpga_header((uint8_t *)FPGA_DATA_WRITE_ADDR, &fpga_header);
	data_ptr = alg_header(alg_hdr, 0, fpga_header.pkglen - FPGA_DATAHEAD_LEN, ENCRYPT_MODE, SM4_ECB_MODE, FPGA_DISABLE, 0, FPGA_DISABLE, 0);
	memcpy(data_ptr, sm2_base_x + SM2_BYTE_LEN / 2, SM2_BYTE_LEN / 2);
	data_ptr += SM2_BYTE_LEN / 2;
	memcpy(data_ptr, sm2_base_x, SM2_BYTE_LEN / 2);
	data_ptr += SM2_BYTE_LEN / 2;
	memcpy(data_ptr, sm2_base_y + SM2_BYTE_LEN / 2, SM2_BYTE_LEN / 2);
	data_ptr += SM2_BYTE_LEN / 2;
	memcpy(data_ptr, sm2_base_y, SM2_BYTE_LEN / 2);
	data_ptr += SM2_BYTE_LEN / 2;
	memcpy(data_ptr, random + SM2_BYTE_LEN / 2, SM2_BYTE_LEN / 2);
	data_ptr += SM2_BYTE_LEN / 2;
	memcpy(data_ptr, random, SM2_BYTE_LEN / 2);
	data_ptr += SM2_BYTE_LEN / 2;
	fpga_write_finish(fpga_header.pkglen);

//	fpga_buff_read_start();
//	rtval = fpga_recv_buff_process(FPGA_BUFF_ID);
//	if (rtval)
//	{
//		print(PRINT_FPGA,"fpga_recv_buff_process error!!!\r\n");
//		return -2;
//	}
	uint8_t *mcu_recv_buff = fpga_read_start_ex();
	if( mcu_recv_buff == NULL){
		print(PRINT_FPGA,"fpga no data %x!\r\n",fpga_header.dst);
		return ERR_COMM_OUTTIME;
	}	

	get_fpga_header(&fpga_header, (uint8_t *)mcu_recv_buff);
	if ((fpga_header.channel & 0x40) != 0x00)
	{
		return -3;
	}
	data_ptr = (uint8_t *)(mcu_recv_buff + FPGA_DATAHEAD_LEN);
	memcpy(pub_key->x + SM2_BYTE_LEN / 2, data_ptr, SM2_BYTE_LEN / 2);
	data_ptr += SM2_BYTE_LEN / 2;
	memcpy(pub_key->x, data_ptr, SM2_BYTE_LEN / 2);
	data_ptr += SM2_BYTE_LEN / 2;
	memcpy(pub_key->y + SM2_BYTE_LEN / 2, data_ptr, SM2_BYTE_LEN / 2);
	data_ptr += SM2_BYTE_LEN / 2;
	memcpy(pub_key->y, data_ptr, SM2_BYTE_LEN / 2);
	data_ptr += SM2_BYTE_LEN / 2;
	memcpy(pri_key, random, SM2_BYTE_LEN);
	
	return 0;
}
int32_t fpga_sm2_1510_getkey(uint16_t key_index, SM2PrivateKey *pri_key, SM2PublicKey *pub_key)
{
	FPGAHeader fpga_header;
	uint8_t *alg_hdr;
	uint8_t *data_ptr;
	uint8_t tt;
	memset(&fpga_header, 0, sizeof(FPGAHeader));
	fpga_header.mark = FPGA_HEAD_MARK;
	fpga_header.src = FPGA_DATA_ARM;
	fpga_header.dst = FPGA_DATA_SM2_SSX;
	fpga_header.channel = FPGA_CHANNEL_DEF;
	fpga_header.pkglen = FPGA_DATAHEAD_LEN;
	fpga_header.retpkglen = FPGA_DATAHEAD_LEN + 3 * SM2_BYTE_LEN;
	fpga_header.sm2_cmd = CMD_SM2_GETKEY;
	fpga_header.keytype = KEY_TYPE_LOOKUP;
	fpga_header.keyindex = key_index;
	
	if(fpga_write_start()==REG_REST) return ERR_COMM_OUTTIME;
	alg_hdr = set_fpga_header((uint8_t *)FPGA_DATA_WRITE_ADDR, &fpga_header);
	tt=*(uint8_t *)(FPGA_DATA_WRITE_ADDR+2);
	fpga_write_finish(fpga_header.pkglen);
	
	data_ptr=fpga_read_start_ex();
	if( data_ptr == NULL){
		print(PRINT_FPGA,"fpga no data %x!\r\n",fpga_header.dst);
		return ERR_COMM_OUTTIME;
	}
	get_fpga_header(&fpga_header, data_ptr);
#ifndef TEST
	if ((fpga_header.channel & 0xE0) != 0x20 && (fpga_header.channel & 0xE0) != 0xa0
			&& (fpga_header.channel & 0xE0) != 0x00)
	{
		print(PRINT_FPGA,"f_sm2_gkey rec err 0x%x\r\n", fpga_header.channel);
		fpga_read_finish();
		return -1;
	}
#endif
	data_ptr = (uint8_t *)(data_ptr + FPGA_DATAHEAD_LEN);
	memcpy(pri_key, data_ptr, sizeof(SM2PrivateKey));
	data_ptr += sizeof(SM2PrivateKey);
	memcpy(pub_key, data_ptr, sizeof(SM2PublicKey));
	data_ptr += sizeof(SM2PublicKey);
	fpga_read_finish();
	
	return 0;
}
