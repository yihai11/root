#ifndef  __FPGA_SM4_H__
#define  __FPGA_SM4_H__
#include <stdint.h>

#define SM4_FPGA_BLOCK_SIZE		(4*1024 -FPGA_DATAHEAD_LEN -FPGA_ALGHEAD_LEN)
#define SM4_KEY_LEN				16
#define	SM4_IV_LEN				16
#define SM4_BLOCK_LEN			16
#define SM4_PADDING_LEN(l)		(SM4_BLOCK_LEN-((l)%SM4_BLOCK_LEN))
#define SM4_ENCDATA_LEN(l)		((l)+SM4_PADDING_LEN(l))

int32_t FPGA_SM4_test(void);

int32_t FPGA_SYM_Encrypt(uint8_t SYM_type, uint8_t SM4_MODE, uint8_t *key, uint8_t *IV, uint8_t *data, uint32_t len, uint8_t *enc);
int32_t FPGA_SYM_Decrypt(uint8_t SYM_type, uint8_t SM4_MODE, uint8_t *key, uint8_t *IV ,uint8_t *enc, uint32_t len, uint8_t *data);


void SM4_Encrypt(unsigned char *key,unsigned char *enc,unsigned char *data, int len);
void SM4_Decrypt(unsigned char *key, unsigned char *data,unsigned char *enc, int enclen);


#endif
