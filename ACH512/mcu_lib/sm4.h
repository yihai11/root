/******************************************************************************
* File Name:			scb2.h
* Author:				AisinoChip
* Data First Issued:	2010-03-05
* Description:			Header fo scb2.c
******************************************************************************/

#ifndef __SM4__H_
#define __SM4__H_

#include "common.h"
#include "hrng.h"

#define SM4_ENCRYPTION    1
#define SM4_DECRYPTION    0

#define SM4_ECB_MODE      0
#define SM4_CBC_MODE      1 

#define SM4_SWAP_ENABLE   1
#define SM4_SWAP_DISABLE  0

#define SM4_NORMAL_MODE   0x12345678
#define SM4_SECURITY_MODE 0

#define SM4_FAIL          0x0
#define SM4_PASS          0xa59ada68

/****************************************************************************** 
Name:        sm4_set_key
Function:    set sm4 key for encryption and decryption
Input:
             keyin    --    pointer to buffer of key           	
             swap_en  --    SM4_SWAP_ENABLE, SM4_SWAP_DISABLE               
Return:      None
*******************************************************************************/
void sm4_set_key(UINT32 *keyin, UINT8 swap_en);
void sm4_set_key_u8(UINT8 *keyin, UINT8 swap_en);
/******************************************************************************

Name:        sm4_crypt
Function:    Function for des encryption and decryption
Input:
             indata            --   pointer to buffer of input
             outdata           --   pointer to buffer of result
             block_len         --   block(128bit) length for des cryption
             operation         --   SM4_ENCRYPTION,SM4_DECRYPTION
             mode              --   SM4_ECB_MODE, SM4_CBC_MODE,
             iv                --   initial vector for CBC mode
             security_mode     --   SM4_NORMAL_MODE, SM4_SECURITY_MDOE
Return:      None

*******************************************************************************/
UINT32 sm4_crypt(
    UINT32 *indata,
    UINT32 *outdata,
    UINT32 block_len,
    UINT8  operation,
    UINT8  mode,
    UINT32 *iv,
    UINT32 security_mode
);


UINT32 sm4_crypt_u8(
    UINT8 *indata,
    UINT8 *outdata,
    UINT32 block_len,
    UINT8  operation,
    UINT8  mode,
    UINT8 *iv,
    UINT32 security_mode
);

/******************************************************************************
Name:       sm4_crypt_ofb 
Function:   Function for SM4 encryption and decryption with OFB mode
Input:
            indata         --  pointer to buffer of input
            outdata        --  pointer to buffer of result
            block_len      --  block(128bit) length for sm1 cryption
            ofb_iv         --  pointer to initial vector, length is 4 words
            ofb_iv_next    --  pointer to next iv,so it can be chained to caluate sm4_crypt_ofb from large array of data,
                               length is 4 words
Return:		SM4_FAIL(0x00) or SM4_PASS(0x5aaada6e)
*******************************************************************************/
UINT32 sm4_crypt_ofb(
    UINT32 *indata,
	UINT32 *outdata,
	UINT32 block_len,
	UINT32 *ofb_iv,
	UINT32 *ofb_iv_next
);


/******************************************************************************
Name:       sm4_crypt_cfb 
Function:   Function for SM4 encryption and decryption with CFB mode
Input:
            indata         --  pointer to buffer of input
            outdata        --  pointer to buffer of result
            block_len      --  block(128bit) length for sm1 cryption
			operation      --   SM4_ENCRYPTION,SM4_DECRYPTION
            cfb_iv         --  pointer to initial vector, length is 4 words
            cfb_iv_next    --  pointer to next iv,so it can be chained to caluate sm4_crypt_cfb from large array of data,
                               length is 4 words
Return:		SM4_FAIL(0x00) or SM4_PASS(0x5aaada6e)
*******************************************************************************/

UINT32 sm4_crypt_cfb(
    UINT32 *indata,
	UINT32 *outdata,
	UINT32 block_len,
	UINT8  operation,
	UINT32 *cfb_iv,
	UINT32 *cfb_iv_next
);


#endif
/******************************************************************************
 * end of file
*******************************************************************************/
