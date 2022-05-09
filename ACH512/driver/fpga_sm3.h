#ifndef __FPGA_SM3_H__
#define	__FPGA_SM3_H__


#define	SM3_KEY_LEN		0x32
#define	SM3_HASH			0x00
#define	SM3_HMAC			0x10

#define BIT_TO_BYTE(bits)		(((bits) +7) /8)
#define SM3_HASH_LEN			BIT_TO_BYTE(256)

#define	SM3_CIPHERTEXT_LEN		32
#define	SM3_BLOCK_SIZE				64

unsigned char  FPGA_SM3_test(void);
void fpga_random_test(void);
unsigned char  get_random_data(unsigned char *random_data, \
															 unsigned short data_len);
void FPGA_SM3Encrypt( unsigned char *data, unsigned char *enc,int len,\
											unsigned char SM3_MODE,unsigned char *key);
												
#endif
