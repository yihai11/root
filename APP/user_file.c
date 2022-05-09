#include "user_file.h"
#include "spiflash_addr.h"
#include "gd25q256b.h"
#include "fpga.h"
#include "FreeRTOS.h"
#include "spiflash.h"

unsigned char  DATA_FILE_KEY[16]={
0x73,0x80,0x16,0x6f,0x49,0x14,0xb2,0xb9, \
0x17,0x24,0x42,0xd7,0xda,0x8a,0x06,0x00
};

/*******************************************************
*
* user.c
* 遗留问题:
*	1.优化一下读写文件输入的读写值与可读值之间的逻辑问题
*	2.完成加解密函数
*
********************************************************/
#define GETFILELENTH(buff,addr)			flash_page_read_X1(buff,addr,8)
#pragma pack(1)

FILE_HEAD_STR	FILE_AREA_CONFIG;
#pragma pack()

/*********************user.c file*****************
*1.对用户文件区的操作:增加文件，删除文件
*2.对用户的管理：删除，增加操作员
***************************************************/
#pragma pack(1)
typedef struct {
	uint16_t index;
	uint16_t length;			//max is 3840B
	uint16_t user;
//	uint8_t *data;
}USERFILE_STR;
#pragma pack()

void set_file_config(uint16_t config_file_size,uint16_t config_file_quantity)
{
	FILE_HEAD_STR file_head={0};
	file_head.file_size = config_file_size;
	file_head.file_quantity = config_file_quantity;
	file_head.file_in_use_quantity = 0;
	file_head.file_config_state=1;
	flash_page_program_auto((uint8_t *)&file_head,USER_FILE_START_ADDR,sizeof(FILE_HEAD_STR));
}
	

FILE_HEAD_STR read_file_config(void)
{
	FILE_HEAD_STR	file_head={0};
	uint8_t head_buff[6];
	flash_page_read_X1(	(uint8_t *)&file_head,USER_FILE_START_ADDR,sizeof(FILE_HEAD_STR));
	return file_head;
}
/***********************************************************
*file_encrypt
*input: *message 要加密的数据指针
*				*encrymess 加密后的数据指针
*
************************************************************/
void file_encrypt(uint8_t * message,uint8_t *encrymess,uint8_t *key,uint32_t data_len)
{
	memcpy(encrymess,message,data_len);
}
/***********************************************************
*file_decrypt
*input: *message 要解密的数据指针
*				*encrymess 解密后的数据指针
*
************************************************************/
void file_decrypt(uint8_t *decrymess,uint8_t *encrymess,uint32_t data_len)
{
	memcpy(decrymess,encrymess,data_len);
}
/************************************************
*scan_file_name
*input: filename:所查找的文件名
*				file_name_length:所查找的文件长度
*output: 0:未在文件名表中查找到所查文件名
*				others: 对应文件名所在文件名列表中的索引号
*note	:	文件名占128Bytes 不管文件区如何配置，文件名按128Bytes顺序排列
*************************************************/
uint16_t scan_file_name(uint8_t *filename,uint8_t file_name_length){

	FILE_HEAD_STR	file_head = {0};
	uint8_t namebuff[128];
	uint32_t file_offset=1;
	uint16_t file_cnt=0;
	file_head=read_file_config();
	for(;file_offset<file_head.file_quantity+1;){
		flash_page_read_X1(namebuff,USER_FILE_NAME_START_ADDR+(file_offset-1)*128,128);
		if(*namebuff != 0xFF)			//存在一个文件名
			if(!memcmp(namebuff,filename,file_name_length))
					return file_offset;
		file_offset++;
	}
	return 0;			
}
uint32_t enum_file(uint16_t fileindex,uint8_t * filename,uint8_t *namelen)
{
	uint8_t namebuff[128];
	char *endpoint=NULL;
	flash_page_read_X1(namebuff,USER_FILE_NAME_START_ADDR+(fileindex-1)*128,128);
	endpoint=strchr((char*)namebuff,'\0');
	*namelen =(uint8_t *)endpoint-namebuff+1;
	memcpy(filename,namebuff,*namelen);
}
uint32_t write_new_file_name(uint8_t *filename,uint16_t length)
{
	FILE_HEAD_STR	file_head = {0};
	uint8_t namebuff[128];
	uint32_t offset=1;
	uint16_t file_cnt=0;
	file_head=read_file_config();
	for(;(offset-1)<file_head.file_quantity;){
		flash_page_read_X1(namebuff,USER_FILE_NAME_START_ADDR+(offset-1)*128,1);
		if(*namebuff != 0xFF)
			offset++;
		else{
			flash_page_program_auto(filename, USER_FILE_NAME_START_ADDR+ \
														 (offset-1)*128,length);
			return offset;
		}
	}
	return FILE_FULL;	
}

uint32_t read_file_encrpted_len(uint16_t fileindex)
{
	uint8_t file_len[4]={0};
	flash_page_read_X1(file_len,USER_FILE_LEN_START_ADDR+(fileindex-1)*4,4);
	return	*(uint32_t *)file_len;
}

uint32_t	write_file_encrypted_len(uint16_t fileindex,uint32_t file_encry_len)
{
	uint8_t file_len[256]={0},i=0;
	uint8_t offset=0;
	uint32_t addr=0,sec_addr=0;
	addr=USER_FILE_LEN_START_ADDR+(fileindex-1)*4;
	offset=addr%256; 
	addr=addr/256*256;
	flash_page_read_X1(file_len,addr,256);
	*(uint32_t *)(file_len+offset)=file_encry_len;
	//memcpy(file_len+offset,)
	flash_erase_sector(addr);
	flash_page_program(file_len, addr, 256);
	
	return OK;
}
uint8_t create_user_file(uint8_t *filename,uint32_t filesize,uint16_t length)
{
	uint8_t *userfile;
	uint32_t file_offset=0;
	//uint16_t file_offset_cnt=0;
	uint32_t addr=0;
	if(scan_file_name(filename,length))
		return 1;		//已经存在该文件
	else{
		file_offset=write_new_file_name(filename,length);
		return 0;
	}
}
uint32_t read_file_len(uint16_t index)
{
		return read_file_encrpted_len(index);
}
uint8_t read_file_encrypted(uint16_t index,uint32_t offset,uint8_t *filebuff,uint32_t len)
{
	FILE_HEAD_STR	file_head = {0};
	uint32_t fileaddr=0;
	uint32_t read_i=0;
	
	file_head=read_file_config();
//	encry_data_len=read_file_encrpted_len(index);
//	if(~encry_data_len ==0)		//空文件
//		return 0;
	fileaddr=USER_FILE_START_ADDR+file_head.file_size*USER_FILE_MIN_SIZE*(index-1);
	fileaddr+=offset;
	for(;(len-read_i) > 512;read_i+=512)
		flash_page_read_X1(filebuff+read_i,fileaddr+read_i,512);
	if((len-read_i) >0 )
			flash_page_read_X1(filebuff+read_i,fileaddr+read_i,len-read_i);
	return 0;
}

/*************************write_file_encrypted******************
* input:	dataindex:文件索引
*					write_length:需要写入的数据长度
*					data_encypted:要写入的加密数据指针
*	output: NULL
***************************************************************/
void	write_file_encrypted(uint16_t dataindex,uint32_t write_length,uint8_t *data_encrypt)
{
	FILE_HEAD_STR	file_head = {0};
	uint32_t	fileaddr=0;
	uint32_t data_point=0;
	file_head=read_file_config();
	fileaddr=USER_FILE_START_ADDR+file_head.file_size*USER_FILE_MIN_SIZE*(dataindex-1);
	
	for(;(write_length - data_point)>256;data_point+=256)
		flash_page_program_auto(data_encrypt+data_point,fileaddr+data_point,256);
	if((write_length- data_point)>0)
		flash_page_program_auto(data_encrypt+data_point, fileaddr+data_point,write_length- data_point);
}

uint8_t read_user_file(uint16_t fileindex,uint32_t usr_offset, uint8_t off_remain,\
											 uint8_t *filebuff,uint16_t read_size)
{
	uint32_t read_i=0;
	uint8_t *encrybuff;
		
	encrybuff=pvPortMalloc(read_size+off_remain);
	read_file_encrypted(fileindex,usr_offset, encrybuff,read_size);
	file_decrypt(filebuff,encrybuff+off_remain,read_size-off_remain);
	
	vPortFree(encrybuff);
	return OK;
}
	
uint8_t write_user_file(uint16_t dataindex,uint16_t offset ,uint32_t write_len,uint8_t *data_decrypt)
{
	uint16_t data_p=0;
	uint16_t data_sec=0;
	uint32_t fileaddr=0;
	uint8_t remain=0;
	FILE_HEAD_STR	file_head = {0};
	file_head=read_file_config();
	
	uint8_t 	temp_encrydata[256];
	uint8_t		temp_decrydata[256];
	remain=offset%255;
	data_sec = offset/256;
	fileaddr=USER_FILE_START_ADDR+file_head.file_size*USER_FILE_MIN_SIZE*(dataindex-1);
	
	//
	read_file_encrypted(dataindex,data_sec,temp_encrydata,256);	//读出首扇区数据
	file_decrypt(temp_decrydata,temp_encrydata,256);							//解密
	data_p= write_len > (256-remain)?(256-remain):write_len;
	memcpy(temp_decrydata+remain,data_decrypt,data_p);			
	file_encrypt(temp_decrydata,temp_encrydata,DATA_FILE_KEY,256);
	flash_page_program_auto(temp_encrydata,fileaddr,256);
	
	//写入flash
	for(;(write_len-data_p) > 256; data_p+=256){
		file_encrypt(data_decrypt+data_p,temp_encrydata,DATA_FILE_KEY,256);
		flash_page_program_auto(temp_encrydata,fileaddr,256);
	}
	
	if((write_len-data_p) > 0){
		read_file_encrypted(dataindex,offset+data_p,temp_encrydata,256);	//读出末扇区数据
		file_decrypt(temp_decrydata,temp_encrydata,256);							//解密
		//data_p= write_len > (256-remain)?(256-remain):write_len;
		memcmp(temp_decrydata,data_decrypt+data_p,write_len-data_p);			
		file_encrypt(temp_decrydata,temp_encrydata,DATA_FILE_KEY,256);
		flash_page_program_auto(temp_encrydata,fileaddr,256);
	}
	return OK;
}
/*
uint8_t read_user_file(uint8_t *filename,uint8_t name_length,uint32_t usr_offset, \
											 uint8_t *filebuff,uint16_t read_size,uint16_t *read_actual_size)
{
	uint8_t fileindex=0;
	uint32_t encry_data_len=0;
	uint32_t read_i=0;
	uint8_t *encrybuff,*decry_buff;

	fileindex=scan_file_name(filename,name_length);
	if(!fileindex){
		return NO_FILE_NAME;
		
	encrybuff=pvPortMalloc(read_size+usr_offset);
	decry_buff=pvPortMalloc(read_size+usr_offset);	
	encry_data_len=read_file_encrypted(fileindex, encrybuff);
		
	if(encry_data_len == 0)
		return EMPTY;
	
	file_decrypt(decry_buff,encrybuff);
	

	
	memcpy(filebuff,decry_buff+usr_offset,*read_actual_size);
	vPortFree(encrybuff);
	vPortFree(decry_buff);
	return OK;
}
*/

/******************write_user_file***********************
* input :
* output:
* notes:	写加密数据流程：读出flash 中加密数据，解密后在相应
					偏移地址加入新数据，再加密存储
********************************************************/
/*
uint8_t write_user_file(uint8_t *filename,uint8_t namelength,uint32_t data_offset,uint32_t data_length,\
												uint8_t *encry_data,uint8_t *decrybuff,uint8_t *filebuff,uint8_t *key)
{
	uint16_t fileindex=0;
	uint32_t file_len=0;
		
//	if(write_length>file_head.file_size)
//		return LENGTH_OVER_THRESHOLD;
	fileindex=scan_file_name(filename,namelength);
	if(!fileindex)
		return NO_FILE_NAME;
	file_len=read_file_encrypted(fileindex,encry_data);
	if( file_len== EMPTY){	//写入新文件  新文件不允许偏移
		file_encrypt(filebuff,encry_data, key);//数据加密
		write_file_encrypted(fileindex,data_length,encry_data);
	}
	else{
		file_decrypt(encry_data,decrybuff);
		memcpy(decrybuff+data_offset,filebuff,data_length);
		file_encrypt(decrybuff,encry_data, key);//数据加密
		file_len=(file_len-data_offset-data_length) ? file_len : (data_offset+data_length);
		write_file_encrypted(fileindex,file_len,encry_data);
		write_file_encrypted_len(fileindex,file_len);
	}
	return OK;
}*/

//uint8_t
uint8_t delete_user_file(uint8_t *filename,uint32_t name_length)
{
	FILE_HEAD_STR	file_head ={0};
	uint8_t file_offset;
	uint32_t addr=0,block_cnt=0;
	file_offset=scan_file_name(filename,name_length);
	if(!file_offset)
		return NO_FILE_NAME;   
	if(file_offset%2)
		addr=USER_FILE_NAME_START_ADDR+file_offset*128;
	else
		addr=USER_FILE_NAME_START_ADDR+(file_offset-2)*128;
	
	uint8_t *databuff=pvPortMalloc(128);
	
	flash_page_read_X1(databuff,addr,128);		//读出与要擦除文件名同一页的文件名
	
	flash_erase_sector(USER_FILE_NAME_START_ADDR+(file_offset-1)/2*256);
	
	flash_page_program_auto(databuff, addr,128);
	
	write_file_encrypted_len(file_offset,0);		//清 文件长度
	
	file_head=read_file_config();
	addr=USER_FILE_START_ADDR+(file_offset-1)*file_head.file_size*USER_FILE_MIN_SIZE;
	//attention :此处是将删除文件所在区的所有扇区内容擦除，需要优化为只擦除有内容的block
	for(block_cnt=0;block_cnt<(file_head.file_size/USER_FILE_MIN_SIZE);block_cnt++)
		flash_erase_block(addr+block_cnt*USER_FILE_MIN_SIZE);
	vPortFree(databuff);
	return OK;
}
