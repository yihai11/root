#include "fpga.h"
#include "fpga_sm4.h"
#include "sm4.h"
#include "FreeRTOS.h"
#include "type_code.h"
static uint8_t SM4_test_key[16]={
0x73,0x80,0x16,0x6F,0x49,0x14,0xB2,0xB9, \
0x17,0x24,0x42,0xD7,0xDA,0x8A,0x06,0x00
};

static uint8_t SM4_test_data[16]={
0x11 ,0x22 ,0x33 ,0x44 ,0x55 ,0x66 ,0x77 ,0x88 , \
0x99 , 0x00 ,0x11 ,0x22 ,0x33 ,0x44 ,0x55 ,0x66
};

static uint8_t SM4_test_enc[16]={
0x6E,0x96,0xAA,0xAD,0xFD,0x10,0x88,0xBA, \
0x86,0xD3,0x05,0xF6,0x29,0x07,0xF2,0x74
};

//static uint8_t test_sm4_iv[16]={0};
static uint8_t SM4_test_buff[16]={0};
int32_t FPGA_SM4_test(void)
{
	FPGA_SYM_Encrypt(FPGA_DATA_SM4,SM4_ECB_MODE,SM4_test_key,NULL, SM4_test_buff,16,SM4_test_data);
	if(memcmp(SM4_test_buff,SM4_test_enc,16))
		return ERR_CIPN_DECDATA;
	else
		return 0;

}

// 调用FPGA执行SM4加密
// 输入数据需满足16字节整数倍
int32_t FPGA_SYM_Encrypt(uint8_t SYM_type,uint8_t SM4_MODE,uint8_t *key,uint8_t *IV,uint8_t *data, uint32_t len, uint8_t *enc)
{
	FPGAHeader header; 
	uint8_t *ptr = NULL;
	uint32_t alg_header_len;
	uint32_t iv_enable;
	uint32_t iv_len;
	
	
	if ((SM4_MODE == FPGA_CBC_MODE) && (IV == NULL))
	{
		return -1;
	}
	if (len % 16 != 0)
	{
		return -2;
	}
	
	memset(&header, 0, sizeof(FPGAHeader));
	header.src = FPGA_DATA_ARM;
	header.dst = SYM_type;
	if (SM4_MODE == FPGA_ECB_MODE)
	{
		header.pkglen = len + FPGA_DATAHEAD_LEN + FPGA_ALGHEAD_LEN + SM4_KEY_LEN;
	}
	else if (SM4_MODE == FPGA_CBC_MODE)
	{
		header.pkglen = len + FPGA_DATAHEAD_LEN + FPGA_ALGHEAD_LEN + SM4_IV_LEN + SM4_KEY_LEN;
	}
	header.retpkglen = len + FPGA_DATAHEAD_LEN;
	header.keytype = KEY_TYPE_INPACK;
	header.keyindex = 0;
	header.channel = FPGA_CHANNEL_DEF;
	
	if(fpga_write_start()==REG_REST) return -3;
	ptr = set_fpga_header((uint8_t *)FPGA_DATA_WRITE_ADDR, &header);
	if(SM4_MODE == FPGA_CBC_MODE)
	{
		alg_header_len = len + FPGA_ALGHEAD_LEN + SM4_KEY_LEN + SM4_IV_LEN;
		iv_enable = FPGA_ENABLE;
		iv_len = SM4_IV_LEN;
	}
	else
	{
		alg_header_len = len + FPGA_ALGHEAD_LEN + SM4_KEY_LEN;
		iv_enable = FPGA_DISABLE;
		iv_len = 0;
		
	}
	ptr = alg_header(ptr, 0, alg_header_len, SM4_MODE, ENCRYPT_MODE, FPGA_ENABLE, SM4_KEY_LEN, iv_enable, iv_len);
	memcpy(ptr, key, SM4_KEY_LEN);
	ptr += SM4_KEY_LEN;
	if (iv_enable == FPGA_ENABLE)
	{
		memcpy(ptr, IV, SM4_IV_LEN);
		ptr += SM4_IV_LEN;
	}
	memcpy(ptr, data, len);
	ptr += len;
	fpga_write_finish(header.pkglen);
	
	ptr = fpga_read_start_ex();
	if( ptr == NULL){ 
		return ERR_COMM_OUTTIME;
	}
	//ptr = (uint8_t *)FPGA_DATA_READ_ADDR;
	memcpy(enc, ptr + FPGA_DATAHEAD_LEN, len);		//忽略了数据头
	fpga_read_finish();
	
	return 0;
}

// 调用FPGA执行SM4解密
// 输入数据已满足整数倍及小于FPGA可处理长度
int32_t FPGA_SYM_Decrypt(uint8_t SYM_type, uint8_t SM4_MODE, uint8_t *key, uint8_t *IV ,uint8_t *enc, uint32_t len, uint8_t *data)
{
	FPGAHeader header; 
	uint8_t *ptr = NULL;
	uint32_t alg_header_len;
	uint32_t iv_enable;
	uint32_t iv_len;
	
	if ((SM4_MODE == FPGA_CBC_MODE) && (IV == NULL))
	{
		return -1;
	}
	if (len % 16 != 0)
	{
		return -2;
	}
	
	memset(&header, 0, sizeof(FPGAHeader));
	header.src = FPGA_DATA_ARM;
	header.dst = SYM_type;
	if (SM4_MODE == FPGA_ECB_MODE)
	{
		header.pkglen = len + FPGA_DATAHEAD_LEN + FPGA_ALGHEAD_LEN + SM4_KEY_LEN;
	}
	else if (SM4_MODE == FPGA_CBC_MODE)
	{
		header.pkglen = len + FPGA_DATAHEAD_LEN + FPGA_ALGHEAD_LEN + SM4_IV_LEN + SM4_KEY_LEN;
	}
	header.retpkglen = len + FPGA_DATAHEAD_LEN;
	header.keytype = KEY_TYPE_INPACK;
	header.keyindex = 0;
	header.channel = FPGA_CHANNEL_DEF;
	
	if(fpga_write_start()==REG_REST) return -3;
	ptr = set_fpga_header((uint8_t *)FPGA_DATA_WRITE_ADDR, &header);
	if(SM4_MODE == FPGA_CBC_MODE)
	{
		alg_header_len = len + FPGA_ALGHEAD_LEN + SM4_KEY_LEN + SM4_IV_LEN;
		iv_enable = FPGA_ENABLE;
		iv_len = SM4_IV_LEN;
	}
	else
	{
		alg_header_len = len + FPGA_ALGHEAD_LEN + SM4_KEY_LEN;
		iv_enable = FPGA_DISABLE;
		iv_len = 0;
	}
	ptr = alg_header(ptr, 0, alg_header_len, SM4_MODE, DECRYPT_MODE, FPGA_ENABLE, SM4_KEY_LEN, iv_enable, iv_len);
	memcpy(ptr, key, SM4_KEY_LEN);
	ptr += SM4_KEY_LEN;
	if (iv_enable == FPGA_ENABLE)
	{
		memcpy(ptr, IV, SM4_IV_LEN);
		ptr += SM4_IV_LEN;
	}
	memcpy(ptr, enc, len);
	ptr += len;
	fpga_write_finish(header.pkglen);

	//fpga_read_start();
	ptr = fpga_read_start_ex();
	if( ptr == NULL){ 
		return ERR_COMM_OUTTIME;
	}
	memcpy(data, ptr + FPGA_DATAHEAD_LEN, len);		//忽略了数据头
	fpga_read_finish();
	
	return 0;
}
void SM4_Encrypt(unsigned char *key, unsigned char *enc,unsigned char *data, int len)
{
	//FPGA_SM1_4Encrypt(FPGA_DATA_SM4,key, enc,SM4_ECB_MODE,0,data,len);
	FPGA_SYM_Encrypt(FPGA_DATA_SM4,SM4_ECB_MODE,key, 0,data,len,enc);

}
void SM4_Decrypt(unsigned char *key, unsigned char *data,unsigned char *enc, int enclen)
{
	//FPGA_SM1_4Decrypt(FPGA_DATA_SM4,key, data,SM4_ECB_MODE,0,enc,enclen);
	FPGA_SYM_Decrypt(FPGA_DATA_SM4,SM4_ECB_MODE,key,0,enc,enclen,data);

}

