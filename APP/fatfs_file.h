#ifndef __FATFS_FILE_H__
#define	__FATFS_FILE_H__
#include "spiflash_addr.h"
#include <stdint.h>
#include "FreeRTOS.h"
#include "common.h"
#define REAL_SIZE_LEN		(sizeof(uint32_t))
typedef enum {
	FR_EX_OVERSIZE = 21,	//offset illegal when write file 	
	
} FRESULT_EXTEND;

void FS_config(void);
	
int write_usr_key( char *pin, uint8_t pinlen,uint8_t * cipher,uint8_t cipher_len);
	
int file_encrypt(uint8_t * message,uint8_t *encrymess,uint32_t data_len);

int file_decrypt(uint8_t *decrymess,uint8_t *encrymess,uint32_t data_len);

void set_file_name(char *file_name_complete,char *file_name,uint16_t name_length);

uint16_t CheckPara(char *filename,uint8_t name_length,uint32_t file_offset,uint32_t *oper_size);
uint16_t create_fs_file(char *filename, uint16_t name_length, uint32_t filesize);

uint8_t read_fs_file(char *filename,uint8_t name_length,uint32_t file_offset, \
											 uint8_t *filebuff,uint32_t read_len,uint32_t *br);

uint8_t write_fs_file(char *filename,uint8_t name_length,uint32_t file_offset,\
																		 uint32_t write_len,uint8_t *filebuff);

uint8_t clear_fs_file(void);

uint16_t clear_filedir_file(char* filedirchar);
	
uint16_t delete_fs_file(char *filename,uint16_t name_length);

uint8_t clear_fs(void);

uint16_t read_file(char *filename,uint8_t name_length,uint32_t file_offset, \
																 uint8_t *filebuff,uint32_t *read_size);

uint16_t write_file(char *filename,uint8_t name_length,uint32_t file_offset, \
																 uint8_t *filebuff,uint32_t write_size);

uint16_t enum_usr_file(uint16_t file_num_start,uint16_t file_count,uint8_t *enum_file,uint8_t *outdata);


void SM4_padding(uint8_t *data,uint8_t datalen);

uint8_t SM4_depadding(uint8_t *data);
#endif
