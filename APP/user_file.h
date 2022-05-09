#ifndef		__USER_FILE_H__
#define		__USER_FILE_H__
#include  "stdint.h"
#include  "error_code.h"
typedef struct{
	uint16_t	file_size;			//4KµÄÕû±¶Êý
	uint16_t	file_quantity;
	uint16_t	file_in_use_quantity;
	uint16_t  file_config_state;
}FILE_HEAD_STR;

FILE_HEAD_STR read_file_config(void);
void set_file_config(uint16_t config_file_quantity,uint16_t config_file_size);

void	write_file_encrypted(uint16_t dataindex,uint32_t write_length,uint8_t *data_encrypt);
void spiflash_read_test(uint32_t sector_addr, uint32_t addr);
void test_spiflash(void);

uint32_t enum_file(uint16_t fileindex,uint8_t * filename,uint8_t *namelen);

uint32_t read_file_len(uint16_t index);

uint16_t scan_file_name(uint8_t *filename,uint8_t file_name_length);
	
uint8_t read_file_encrypted(uint16_t index,uint32_t offset,uint8_t *filebuff,uint32_t len);

uint8_t create_user_file(uint8_t *filename,uint32_t filesize,uint16_t length);

uint8_t read_user_file(uint16_t fileindex,uint32_t usr_offset, uint8_t off_remain,\
											 uint8_t *filebuff,uint16_t read_size);

uint8_t write_user_file(uint16_t dataindex,uint16_t offset ,uint32_t write_length,uint8_t *data_decrypt);

uint8_t delete_user_file(uint8_t *filename,uint32_t name_length);

#endif
