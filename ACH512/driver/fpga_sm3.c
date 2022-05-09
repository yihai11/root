#include "fpga.h"
#include "fpga_sm3.h"
#include "type_code.h"

unsigned char SM3_KEY[32]={
	0x73,0x80,0x16,0x6f,0x49,0x14,0xb2,0xb9, \
  0x17,0x24,0x42,0xd7,0xda,0x8a,0x06,0x00, \
  0xa9,0x6f,0x30,0xbc,0x16,0x31,0x38,0xaa, \
	0xe3,0x8d,0xee,0x4d,0xb0,0xfb,0x0e,0x4e
};
static uint8_t SM3_test_data[140]={0x12,0x34,0x56,0x78};
static const uint8_t SM3_test_len=4;
static uint8_t SM3_test_enc[32]={
0x36,0x33,0x26,0x83,0xf1,0xbe,0x7b,0x42, \
0x10,0x54,0x14,0x32,0x3e,0xaa,0x5d,0xe2, \
0x9c,0xba,0x8c,0x3a,0xb6,0x9d,0x0b,0x55, \
0xf6,0x4b,0x4d,0x75,0x2f,0xa1,0x5f,0xC6
};
//if(task_node->totalpacknum == task_node->curpacknum)//最后一包
// {
//  pkg_len += hash_req->uiDataLength - MAX_PAYLOAD_LEN *(  task_node->curpacknum  - 1);
//  fill_padding_buffer(padding_buf, hash_req->uiDataLength, &padding_size);//填充
//  pkg_len += padding_size;
// }
 
static int fill_padding_buffer(unsigned char *padding_buf, unsigned int input_size, unsigned int *padding_size)
{
 unsigned int left_size;
 unsigned int fill_padding_size; 
 left_size = input_size % SM3_BLOCK_SIZE;
 if (SM3_BLOCK_SIZE - 8 <= left_size)
 {
  *padding_size = SM3_BLOCK_SIZE * 2 - left_size;
 }
 else
 {
  *padding_size = SM3_BLOCK_SIZE - left_size;
 }

 memset(padding_buf, 0, *padding_size);
 padding_buf[0] = 0x80;
 fill_padding_size = input_size * 8;
 memcpy(padding_buf + *padding_size - 4, &fill_padding_size, sizeof(unsigned int));

 return 0;
}

unsigned char  FPGA_SM3_test(void)
{
	uint8_t buff[128];
//	uint8_t  i=0;
	uint8_t enc_data[32]={0};
	uint32_t code_size=0;
	fill_padding_buffer(buff,SM3_test_len, &code_size);
	memcpy(SM3_test_data+4,buff,code_size);
	FPGA_SM3Encrypt( (uint8_t *)SM3_test_data, enc_data,code_size+SM3_test_len,\
										SM3_HASH,SM3_KEY);
	if(memcmp(enc_data,SM3_test_enc,SM3_CIPHERTEXT_LEN)){
		print(PRINT_FPGA,"SM3 F test err\r\n");
		return 0xff;
	}
	else
		return 0;
}

/******************************************************
*	FPGA_SM3Encrypt
*	input	: *data 		明文
*					*enc			密文
*					len				明文长度
*					SM3_MODE	hash/hmac
*					*key  		密钥指针(仅hmac模式)
*******************************************************/

void FPGA_SM3Encrypt( unsigned char *test_data, unsigned char *enc,int len,\
											unsigned char SM3_MODE,unsigned char *key)
{
	FPGAHeader header; 
	unsigned char *ptr = NULL;
	//memset(&header, 0, sizeof(FPGAHeader));
	header.src = FPGA_DATA_ARM;
	header.dst = FPGA_DATA_SM3;
	if(SM3_MODE == SM3_HMAC)
	{
		header.pkglen = len +SM3_KEY_LEN+FPGA_DATAHEAD_LEN +FPGA_ALGHEAD_LEN;
	}
	else
	{
		header.pkglen = len +FPGA_DATAHEAD_LEN +FPGA_ALGHEAD_LEN;
	}
	header.retpkglen = 32 + FPGA_ALGHEAD_LEN+FPGA_DATAHEAD_LEN;
	header.keytype = KEY_TYPE_INPACK;
	header.keyindex = 0;	
	header.channel = FPGA_CHANNEL_DEF;

	if(fpga_write_start()==REG_REST) return;
	ptr = set_fpga_header((unsigned char *)FPGA_DATA_WRITE_ADDR, &header);
	if(SM3_MODE == SM3_HMAC){
		ptr = alg_header(ptr, 0, SM3_KEY_LEN+len +FPGA_ALGHEAD_LEN , SM3_MODE, ENCRYPT_MODE,\
										FPGA_ENABLE, SM3_KEY_LEN, FPGA_DISABLE, 0);
		memcpy(ptr, key, SM3_KEY_LEN);
		ptr+=SM3_KEY_LEN;
	}
	else{
		ptr = alg_header(ptr, 0, len+FPGA_ALGHEAD_LEN , SM3_MODE, ENCRYPT_MODE,\
										FPGA_DISABLE, 0, FPGA_DISABLE, 0);
	}
	
	memcpy((unsigned char *)FPGA_DATA_WRITE_ADDR+FPGA_ALGHEAD_LEN+FPGA_DATAHEAD_LEN,\
											test_data,len);
	fpga_write_finish(len+FPGA_ALGHEAD_LEN+FPGA_DATAHEAD_LEN);
	//fpga_read_start();
	ptr = fpga_read_start_ex();
	if( ptr == NULL){ 
		return;
	}
	memcpy(enc, ptr +FPGA_DATAHEAD_LEN, SM3_CIPHERTEXT_LEN);		//忽略了数据头
	fpga_read_finish();
}
unsigned char  get_random_data(uint8_t *random_data,uint16_t data_len)
{
	FPGAHeader header; 
//	uint8_t i=0;
	unsigned char *ptr = NULL;
	header.src = FPGA_DATA_ARM;
	header.dst = FPGA_DATA_RANDOM;
	
	header.pkglen = FPGA_DATAHEAD_LEN ;
	header.retpkglen = FPGA_DATAHEAD_LEN + data_len;
	header.keytype = KEY_TYPE_INPACK;
	header.keyindex = 0;
	header.channel = FPGA_CHANNEL_DEF;

	if(fpga_write_start()==REG_REST) return 4;
	set_fpga_header((unsigned char *)FPGA_DATA_WRITE_ADDR, &header);
	fpga_write_finish(FPGA_DATAHEAD_LEN);
	
	//fpga_read_start();
	ptr = fpga_read_start_ex();//(unsigned char *)FPGA_DATA_READ_ADDR;
	if( ptr == NULL){ 
		return 5;
	}
	memcpy(random_data, ptr + FPGA_DATAHEAD_LEN, data_len);		//忽略了数据头
	fpga_read_finish();
	
	return 0;
}

void fpga_random_test(void)
{
	uint16_t data_len=32;
	
	uint8_t random_data[32]={0};
	get_random_data(random_data, data_len);
#ifdef DEBUG
	uint8_t i=0;
	print(PRINT_FPGA,"the r is\r\n");
	for(;i<data_len;i++)
		print(PRINT_FPGA,"%x",random_data[i]);
	#endif
}

