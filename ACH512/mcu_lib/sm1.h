/***********************************************************************
 * Copyright (c)  2008 - 2016, Shanghai AisinoChip Co.,Ltd .
 * All rights reserved.
 * Filename    : sm1.h
 * Description : sm1 driver header file
 * Author(s)   : Eric  
 * version     : V1.0
 * Modify date : 2016-03-24
 ***********************************************************************/
#ifndef __SM1_H__
#define __SM1_H__

#include "common.h"
#include "hrng.h"


#define SM1_ENCRYPTION          1
#define SM1_DECRYPTION          0

#define SM1_INTERPRAR           0
#define SM1_EXTERPRAR           1 

#define SM1_ECB_MODE            0
#define SM1_CBC_MODE            1 

#define SM1_SWAP_ENABLE         1
#define SM1_SWAP_DISABLE        0

#define SM1_NORMAL_MODE         0x12345678
#define SM1_SECURITY_MODE       0

#define SM1_FAIL                0x0
#define SM1_PASS                0x5aaada6e


/******************************************************************************
Name:       sm1_set_key
Function:   input sm1 key for encryption and decryption
Input:
            keyin    --    pointer to buffer of key                
			sk       --    SM1_INTERPRAR, SM1_EXTERPRAR
			swap_en  --    SM1_SWAP_ENABLE, SM1_SWAP_DISABLE
					 
Return:		None
*******************************************************************************/
void sm1_set_key(UINT32 *keyin, UINT8 sk,  UINT8 swap_en);
void sm1_set_key_u8(UINT8 *keyin, UINT8 sk,  UINT8 swap_en);


/******************************************************************************
Name:       sm1_crypt 
Function:   Function for SM1 encryption and decryption with ECB or CBC mode
Input:
            indata         --  pointer to buffer of input
            outdata        --  pointer to buffer of result
            block_len      --  block(128bit) length for sm1 cryption
            operation      --  SM1_ENCRYPTION,SM1_DECRYPTION
            mode           --  SM1_ECB_MODE, SM1_CBC_MODE,
            iv             --  pointer to initial vector for CBC mode
            security_mode  --   SM1_NORMAL_MODE, SM1_SECURITY_MODE
Return:		SM1_FAIL(0x00) or SM1_PASS(0x5aaada6e)
*******************************************************************************/
UINT32 sm1_crypt(
    UINT32 *indata,
    UINT32 *outdata,
    UINT32 block_len,
    UINT8  operation,
    UINT8  mode,
    UINT32 *iv,
    UINT32 security_mode
);

UINT32 sm1_crypt_u8(
    UINT8 *indata,
    UINT8 *outdata,
    UINT32 block_len,
    UINT8  operation,
    UINT8  mode,
    UINT8 *iv,
    UINT32 security_mode
);

/******************************************************************************
Name:       sm1_crypt_ofb 
Function:   Function for SM1 encryption and decryption with OFB mode
Input:
            indata         --  pointer to buffer of input
            outdata        --  pointer to buffer of result
            block_len      --  block(128bit) length for sm1 cryption
            ofb_iv         --  pointer to initial vector
            ofb_iv_next    --  pointer to next iv,so it can be chained to caluate sm1_crypt_ofb from large array of data
Return:		SM1_FAIL(0x00) or SM1_PASS(0x5aaada6e)
*******************************************************************************/

UINT32 sm1_crypt_ofb(
    UINT32 *indata,
 	UINT32 *outdata,
	UINT32 block_len,
	UINT32 *ofb_iv,
	UINT32 *ofb_iv_next
);

/******************************************************************************
Name:       sm1_crypt_cfb 
Function:   Function for SM1 encryption and decryption with CFB mode
Input:
            indata         --  pointer to buffer of input
            outdata        --  pointer to buffer of result
            block_len      --  block(128bit) length for sm1 cryption
			operation      --  SM1_ENCRYPTION,SM1_DECRYPTION
            cfb_iv         --  pointer to initial vector
            cfb_iv_next    --  pointer to next iv,so it can be chained to caluate sm1_crypt_cfb from large array of data
Return:		SM1_FAIL(0x00) or SM1_PASS(0x5aaada6e)
*******************************************************************************/


UINT32 sm1_crypt_cfb(
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
