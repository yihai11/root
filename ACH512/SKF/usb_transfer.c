#include <stdio.h>
#include <string.h>
#include "SL811_usb.h"
#include "common.h"
extern uint8_t data_toggle;

int32_t UKey_APDU_Send(uint8_t *apdu_cmd, uint32_t apdu_len)
{
	int32_t rtval;
	Bulk_CBW cbw;

	cbw.CBWSignature = UMS_CBW_SIG;
	cbw.CBWTag = USB_SHUDUN_TAG;
	cbw.CBWDataLength = apdu_len;
	cbw.CBWFlags = CBW_OUT_FLAG;
	cbw.CBWLUNNum = DEF_LUN_NUM;
	cbw.CBWCBLength = 0x02;
	memset(cbw.CBWCB, 0, 16);
	cbw.CBWCB[0] = 0xFF;
	cbw.CBWCB[1] = 0x02;
	
	rtval = usb_bulk_command(&cbw, apdu_cmd, apdu_len);
	if (rtval)
	{
		print(PRINT_811USB,"UKey_APDU_S  usb_blk_com err\r\n");
		return -1;
	}

	return 0;
}

int32_t UKey_APDU_Recv(uint8_t *recv_buff, uint32_t recv_len)
{
	int32_t rtval;
	int32_t recv_total;
	Bulk_CBW cbw;
	
	cbw.CBWSignature = UMS_CBW_SIG;
	cbw.CBWTag = USB_SHUDUN_TAG;
	cbw.CBWDataLength = recv_len;
	cbw.CBWFlags = CBW_IN_FLAG;
	cbw.CBWLUNNum = DEF_LUN_NUM;
	cbw.CBWCBLength = 0x02;
	memset(cbw.CBWCB, 0, 16);
	cbw.CBWCB[0] = 0xFF;
	cbw.CBWCB[1] = 0x03;
	
	rtval = usb_bulk_command(&cbw, recv_buff, recv_len);
	if (rtval)
	{
		print(PRINT_811USB,"UKey_APDU_R usb_blk_com error!!!\r\n");
		return -1;
	}
	
	recv_total = recv_buff[2] * 256 +  recv_buff[3];
	if (recv_total > recv_len)
	{
		print(PRINT_811USB,"no space\r\n");
		return -1;
	}

	return 0;
}

