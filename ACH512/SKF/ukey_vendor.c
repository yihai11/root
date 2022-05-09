#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "common.h"
#define DEV_NAME "SL811_USB_KEY"
#define PRINT_USBVEN 2
static void usbEnumSucessCallBack (void)
{
}

static void usbDevDisConCallBack (void)
{
}

unsigned long UKeySCListDevs(char *pszDrives, unsigned long *pulDrivesLen, unsigned long *pulDriveNum)
{
    strcpy(pszDrives, DEV_NAME);
    *(pszDrives + strlen(DEV_NAME)) = 0x00;

    *pulDrivesLen = strlen(DEV_NAME) + 1;
    *pulDriveNum = 1;

    return 0;
}

unsigned long UKeySCConnectDev(char *pszDrive, int *pfd)
{
	*pfd = 1;
    return 0;
}

unsigned long UKeySCDisconnectDev(int fd)
{
    return 0;
}

unsigned long UKeySCBeginTransaction(int fd)
{
    return 0;
}

unsigned long UKeySCEndTransaction(int fd)
{
    return 0;
}

unsigned long UKeySCResetCard(int fd, unsigned char *pbAtr, unsigned long *pulAtrLen)
{
    return 0;
}

#if 1
int32_t UKey_APDU_Send(uint8_t *apdu_cmd, uint32_t apdu_len);
int32_t UKey_APDU_Recv(uint8_t *recv_buff, uint32_t recv_len);
extern void * UKeyMalloc(uint32_t size);
void UKeyFree(void *memory);
unsigned long UKeySCTransmit(int fd, unsigned char *pbCommand, unsigned long ulCommandLen, unsigned long ulTimeOutMode, unsigned char *pbOutData, unsigned long *pulOutDataLen, unsigned long *pulCosState)
{
	int32_t rtval;
	uint32_t cmd_pad_len;
	uint32_t recv_len;
	uint32_t send_len;
	uint8_t *temp_recv_buff;
	uint32_t temp_recv_len;
	
	cmd_pad_len = 4 - ulCommandLen % 4;
	memset(pbCommand + ulCommandLen, cmd_pad_len, cmd_pad_len);
//	print(PRINT_USBVEN,"ulCmdLen %ld\r\n",ulCommandLen);
//	print(PRINT_USBVEN,"cmd_pad_len %d\r\n",cmd_pad_len);
//	if(0x18==pbCommand[1]){
//	print(PRINT_USBVEN,"vercmd \r\n");
//	printf_buff_byte(pbCommand,ulCommandLen + cmd_pad_len);
//	}
	rtval = UKey_APDU_Send(pbCommand, ulCommandLen + cmd_pad_len);
	if (rtval)
	{
		print(PRINT_USBVEN,"UKeySCTransmit err %d\r\n", rtval);
		return 1;
	}
	
	if (ulCommandLen == 4)
	{
		recv_len = 0;
	}
	else if (ulCommandLen == 7)
	{
		recv_len = pbCommand[5] * 256 + pbCommand[6];
	}
	else if (ulCommandLen > 7)
	{
		send_len = pbCommand[5] * 256 + pbCommand[6];
		if (ulCommandLen - 7 == send_len)
		{
			recv_len = 0;
		}
		else
		{
			recv_len = pbCommand[ulCommandLen - 2] * 256 + pbCommand[ulCommandLen - 1];
		}
	}
	else
	{
		print(PRINT_USBVEN,"UKeySCTransmit ulCmdLen err %ld!!!\r\n", ulCommandLen);
		return 2;
	}
	
	//temp_recv_len = (recv_len + 6 + 4) / 4 * 4;
	//temp_recv_len = (recv_len + 6) + 4 - (recv_len + 6) % 4;
	temp_recv_len = 1024;
	temp_recv_buff = UKeyMalloc(temp_recv_len);
	if (temp_recv_buff == NULL)
	{
		print(PRINT_USBVEN,"UKeySCTransmit UKeyMalloc error!!!\r\n");
		return 3;
	}
				
	rtval = UKey_APDU_Recv(temp_recv_buff, temp_recv_len);
	if (rtval)
	{
		print(PRINT_USBVEN,"UKey_APDU_Recv err %d\r\n", rtval);
		UKeyFree(temp_recv_buff);
		return 4;
	}
	temp_recv_len = 256 * temp_recv_buff[2] + temp_recv_buff[3];
	temp_recv_len = temp_recv_len - temp_recv_buff[temp_recv_len + 3] - 2;
//	print(PRINT_USBVEN,"recv_len %d\r\n",temp_recv_len);
	memcpy(pbOutData, temp_recv_buff + 4, temp_recv_len);
//	printf_buff_byte(pbOutData,temp_recv_len);
	*pulOutDataLen = temp_recv_len;
	*pulCosState =  256 * temp_recv_buff[temp_recv_len + 4] + temp_recv_buff[temp_recv_len + 5];
//	if(0x18==pbCommand[1])
//	print(PRINT_USBVEN,"State %lx\r\n",*pulCosState);
	UKeyFree(temp_recv_buff);

	return 0;
}

unsigned long UKeySCTransmitEx(int fd, unsigned char *pbCommand, unsigned long ulCommandLen, unsigned long ulTimeOutMode, unsigned long *pbOutData, unsigned long *pulOutDataLen)
{	
	int32_t rtval;
	uint32_t cmd_pad_len;
	uint32_t recv_len;
	uint32_t send_len;
	uint8_t *temp_recv_buff;
	uint32_t temp_recv_len;

	cmd_pad_len = 4 - ulCommandLen % 4;
	memset(pbCommand + ulCommandLen, cmd_pad_len, cmd_pad_len);
	
	rtval = UKey_APDU_Send(pbCommand, ulCommandLen + cmd_pad_len);
	if (rtval)
	{
		print(PRINT_USBVEN,"UKeySCTransmit err %d!!!\r\n", rtval);
		return 1;
	}
	
	if (ulCommandLen == 4)
	{
		recv_len = 0;
	}
	else if (ulCommandLen == 7)
	{
		recv_len = pbCommand[5] * 256 + pbCommand[6];
	}
	else if (ulCommandLen > 7)
	{
		send_len = pbCommand[5] * 256 + pbCommand[6];
		if (ulCommandLen - 7 == send_len)
		{
			recv_len = 0;
		}
		else
		{
			recv_len = pbCommand[ulCommandLen - 2] * 256 + pbCommand[ulCommandLen - 1];
		}
	}
	else
	{
		print(PRINT_USBVEN,"UKeySCTransmit ulCmdLen err %ld!!!\r\n", ulCommandLen);
		return 2;
	}
	
	//temp_recv_len = (recv_len + 6 + 4) / 4 * 4;
	//temp_recv_len = (recv_len + 6) + 4 - (recv_len + 6) % 4;
	temp_recv_len = 1024;
	temp_recv_buff = UKeyMalloc(temp_recv_len);
	if (temp_recv_buff == NULL)
	{
		print(PRINT_USBVEN,"UKeySCTransmit UKeyMalloc err\r\n");
		return 3;
	}
			
	rtval = UKey_APDU_Recv(temp_recv_buff, temp_recv_len);
	if (rtval)
	{
		print(PRINT_USBVEN,"UKey_APDU_Recv err %d\r\n", rtval);
		UKeyFree(temp_recv_buff);
		return 4;
	}
	temp_recv_len = 256 * temp_recv_buff[2] + temp_recv_buff[3];
	temp_recv_len = temp_recv_len - temp_recv_buff[temp_recv_len + 3] - 2;
	memcpy(pbOutData, temp_recv_buff + 4, temp_recv_len);
	*pulOutDataLen = temp_recv_len;
	UKeyFree(temp_recv_buff);
	
	return 0;
}

#endif
