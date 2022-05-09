#include <stdint.h>
#include "gpio.h"
#include "SL811_usb.h"

USBDev		g_usb_dev;

//void printf_byte(uint8_t *buff, uint32_t len)
//{
//	int i;
//	
//	for (i = 0; i < len; i++)
//	{
//		print(PRINT_811USB,"0x%02x ", buff[i]);
//		if ((i + 1) % 32 == 0)
//		{
//			print(PRINT_811USB,"\r\n");
//		}
//	}
//	print(PRINT_811USB,"\r\n");
//}

/*SL811HS芯片初始化，寄存器读写函数*/
void sl811_pin_config(void)
{
	gpio_config(HOST_A0, 1);
	gpio_config(HOST_RST, 1);
	gpio_clr(HOST_RST);
	delay_ms(10);
	gpio_set(HOST_RST);
}

void sl811_os_init(void)
{
	sl811_reg_write(USB_CONTROL01_REG, 0x08); 
	sl811_reg_write(USB_CONTROL01_REG, 0x00);     
 	sl811_reg_write(USB_INTSTATUS_REG, INT_CLEAR);
}
void sl811_soc_init(void)
{
	sl811_pin_config();
	sl811_reg_write(USB_CONTROL02_REG, 0xae);
	sl811_reg_write(USB_CONTROL02_REG, 0xae);
	sl811_reg_write(USB_CONTROL01_REG, 0x08); //0x08
	delay_ms(10);
	sl811_reg_write(USB_CONTROL01_REG, 0x00);     
	sl811_reg_write(USB_INTENABLE_REG, 0x61);
	sl811_reg_write(USB_INTSTATUS_REG, INT_CLEAR);
	delay_ms(200);
	
	memset(&g_usb_dev, 0, sizeof(USBDev));
}

__inline void sl811_reg_write(uint8_t reg_addr, uint8_t reg_value)
{
	gpio_clr(HOST_A0);
	delay_us(2);
	USB_HOST_INDEX_ADDR = reg_addr;
	delay_us(2);
	gpio_set(HOST_A0);
	delay_us(2);
	USB_HOST_DATA_ADDR = reg_value;
	delay_us(2);
}

__inline void sl811_reg_write_continue(uint8_t reg_value)
{
	gpio_set(HOST_A0);
	delay_us(2);
	USB_HOST_DATA_ADDR = reg_value;
	delay_us(2);
}

__inline void sl811_reg_write_buff(uint8_t reg_addr, uint8_t *buff, uint8_t size)
{
	gpio_clr(HOST_A0);
	delay_us(2);
	USB_HOST_INDEX_ADDR = reg_addr;
	delay_us(2);
	gpio_set(HOST_A0);
	delay_us(2);
	while (size--)
	{
		USB_HOST_DATA_ADDR = *buff++;
	}
	delay_us(2);
}

__inline uint8_t sl811_reg_read(uint8_t reg_addr)
{
	uint8_t	data = 0;

	gpio_clr(HOST_A0);
	delay_us(2);
	USB_HOST_INDEX_ADDR = reg_addr;
	delay_us(2);
	gpio_set(HOST_A0);
	delay_us(2);
	data = USB_HOST_DATA_ADDR;
	delay_us(2);

	return data;
}

__inline uint8_t sl811_reg_read_continue(void)
{
	uint8_t data = 0;

	gpio_set(HOST_A0);
	delay_us(1);
	data = (uint8_t)USB_HOST_DATA_ADDR;
	delay_us(1);

	return data;
}

__inline void sl811_reg_read_buff(uint8_t reg_addr, uint8_t *buff, uint8_t size)
{
	gpio_clr(HOST_A0);
	delay_us(2);
	USB_HOST_INDEX_ADDR = reg_addr;
	delay_us(1);
	gpio_set(HOST_A0);
	delay_us(2);
	while (size--)
	{
		*buff++ = USB_HOST_DATA_ADDR;
	}
	delay_us(1);	
}

/*usb功能相关参数*/

uint8_t get_ctrl_endpoint()
{
	return g_usb_dev.ctrlEP_addr;
}

int32_t get_bulkin_endpoint(int8_t *ep_addr, int16_t *ep_payload)
{
	int i;
	pInterface usb_if;
	
	if (g_usb_dev.inface_num == 0 || g_usb_dev.ums_index == INVALID_IF_ADDR)
	{
		return -1;
	}
	usb_if = &g_usb_dev.usb_interfaces[g_usb_dev.ums_index];
	
	for (i = 0; i < usb_if->bEndpointNum; i++)
	{
		if (usb_if->bEndpointAttr[i] == EP_BULK_TYPE && (usb_if->bEndpointAddr[i] & 0x80) != 0)
		{
			*ep_addr = usb_if->bEndpointAddr[i];
			*ep_payload = usb_if->wEndpointPayload[i];
			return 0;
		}
	}
	
	return -2;
}

int32_t get_bulkout_endpoint(int8_t *ep_addr, int16_t *ep_payload)
{
	int i;
	pInterface usb_if;
	
	if (g_usb_dev.inface_num == 0 || g_usb_dev.ums_index == INVALID_IF_ADDR)
	{
		return -1;
	}
	usb_if = &g_usb_dev.usb_interfaces[g_usb_dev.ums_index];
	
	for (i = 0; i < usb_if->bEndpointNum; i++)
	{
		if (usb_if->bEndpointAttr[i] == EP_BULK_TYPE && (usb_if->bEndpointAddr[i] & 0x80) == 0)
		{
			*ep_addr = usb_if->bEndpointAddr[i];
			*ep_payload = usb_if->wEndpointPayload[i];
			return 0;
		}
	}
	return -2;
}

int32_t usb_transfer_data(uint8_t usb_addr, uint8_t endpoint, uint8_t pid, uint8_t iso, uint16_t payload, uint16_t data_len, uint8_t *data)
{
	uint8_t host_ctl;
	uint8_t xfer_len;
	uint8_t int_status;
	uint8_t pkg_status;
	uint16_t retry_time;
	uint16_t time_out;
	uint8_t *tmp_ptr;
	uint8_t ep_index;
	uint8_t left_size;
	uint8_t real_recv;
	uint8_t ctrl_toggle = 0;
	uint8_t *data_toggle;
		
	//初始化
	tmp_ptr = data;
	ep_index = endpoint & 0x0F;
	
	if (ep_index == 0)
	{
		data_toggle = &ctrl_toggle;
	}
	else
	{
		if (g_usb_dev.inface_num == 0 || g_usb_dev.ums_index == INVALID_IF_ADDR)
		{
			return -1;
		}
		
		data_toggle = &g_usb_dev.usb_interfaces[g_usb_dev.ums_index].bDataToggle[ep_index];
	}
#if(0)
	print(PRINT_811USB,"****  ");
	print(PRINT_811USB,"addr %d  ",usb_addr);
	print(PRINT_811USB,"ep %d  ",endpoint);
	print(PRINT_811USB,"pid %d  ",pid);
	print(PRINT_811USB,"iso %d  ",iso);
	print(PRINT_811USB,"pd %d  ",payload);
	print(PRINT_811USB,"len %d\r\n",data_len);
	xfer_len = data_len > payload ? payload : data_len;
	if(data_len && (pid==PID_OUT))
			printf_buff_byte(data,xfer_len);
	//print(PRINT_811USB,"\r\n");
#endif
	do
	{
		xfer_len = data_len > payload ? payload : data_len;
		if (pid == PID_IN)
		{
			host_ctl = DATA0_READ;
		}
		else if (pid == PID_OUT) 
		{
			if (data_len)
			{
				sl811_reg_write_buff(USBA_START_ADDR, tmp_ptr, xfer_len);
			}
			
			if (*data_toggle == 0)
			{
				host_ctl = DATA0_WRITE;
			}
			else
			{
				host_ctl = DATA1_WRITE;
			}
			*data_toggle ^= 1;

			if (endpoint == 0)
			{
				host_ctl ^= TOGGLE_BIT;
			}
		}
		else if (pid == PID_SETUP)
		{
			if (data_len)
			{
				sl811_reg_write_buff(USBA_START_ADDR, tmp_ptr, xfer_len);
			}
			host_ctl = DATA0_WRITE;
		}
		else
		{
			print(PRINT_811USB,"usb_tdata err pid 0x%x!\r\n", pid);
			return -1;
		}

		if (iso)
		{
			host_ctl |= ISO_BIT;
		}
		
#if 0
		print(PRINT_811USB,"reg 0x%x: value 0x%x\r\n", USB_PIDENPT_REG(USBA_INDEX), ((ep_index & 0x0F) | pid));
		print(PRINT_811USB,"reg 0x%x: value 0x%x\r\n", USB_DEVADDR_REG(USBA_INDEX), usb_addr);
		print(PRINT_811USB,"reg 0x%x: value 0x%x\r\n", USB_HOSTADD_REG(USBA_INDEX), USBA_START_ADDR);
		print(PRINT_811USB,"reg 0x%x: value 0x%x\r\n", USB_XFERLEN_REG(USBA_INDEX), xfer_len);
		print(PRINT_811USB,"reg 0x%x: value 0x%x\r\n", USB_INTSTATUS_REG, INT_CLEAR);
		print(PRINT_811USB,"reg 0x%x: value 0x%x\r\n", USB_HOSTCTL_REG(USBA_INDEX), host_ctl);	
		print(PRINT_811USB,"-------\r\n");
#endif

		sl811_reg_write(USB_PIDENPT_REG(USBA_INDEX), ((ep_index & 0x0F) | pid));		/* PID + EP address */
		sl811_reg_write(USB_DEVADDR_REG(USBA_INDEX), usb_addr);			        		/* USB address */
		sl811_reg_write(USB_HOSTADD_REG(USBA_INDEX), USBA_START_ADDR);					/* buffer address, start with "data0" */
		sl811_reg_write(USB_XFERLEN_REG(USBA_INDEX), xfer_len);			        		/* data transfer length */
		sl811_reg_write(USB_INTSTATUS_REG, INT_CLEAR); 		        					/* clear interrupt status */
		sl811_reg_write(USB_HOSTCTL_REG(USBA_INDEX), host_ctl);							/* Enable ARM and USB transfer start here */

		retry_time = 0;
		while (1)
		{
			time_out = 0;
			while (1)
			{
				int_status = sl811_reg_read(USB_INTSTATUS_REG);
				//if ((int_status & INSERT_REMOVE) || (int_status & USB_DETECT))
				if (int_status & USB_DETECT)
				{
					print(PRINT_811USB,"USB is rm\r\n");
					return -2;
				}

				if (int_status & USB_A_DONE)
				{
					break;
				}

				if (time_out++ > 3000)
				{
					print(PRINT_811USB,"USB s/r timeout");
					return -3;
				}
			}
			delay_ms(10);
			sl811_reg_write(USB_INTSTATUS_REG, INT_CLEAR);
			pkg_status = sl811_reg_read(USB_XSTATUS_REG(USBA_INDEX));
			if (pkg_status & PKG_ACK)
			{
				if (pid == PID_IN)
				{
					left_size = sl811_reg_read(USB_CONTRER_REG(USBA_INDEX));
					real_recv = xfer_len - left_size;
					sl811_reg_read_buff(USBA_START_ADDR, tmp_ptr, real_recv);
					if (real_recv < payload)
					{
						data_len = xfer_len;
					}
#if(0)
						if(data_len && (pid==PID_IN))                  //!!!!
							printf_buff_byte(tmp_ptr,real_recv);
#endif
				}
				break;
			}

			if (pkg_status & PKG_NAK)
			{
//				if (ep_index == 0)
//				{
//					sl811_reg_write(USB_INTSTATUS_REG, INT_CLEAR);
//					sl811_reg_write(USB_HOSTCTL_REG(USBA_INDEX), host_ctl);
//					pkg_status = 0;
//				}
//				else
//				{
//					print(PRINT_811USB,"USB send/recv data PKG_NAK for endpoint(%d)\r\n", ep_index);
//					return -4;
//				}
				delay_ms(100);
				sl811_reg_write(USB_INTSTATUS_REG, INT_CLEAR);
				sl811_reg_write(USB_HOSTCTL_REG(USBA_INDEX), host_ctl);
				print(PRINT_811USB,"USB s/r data PKG_NAK ep(%d)\r\n", ep_index);
			}

			//print(PRINT_811USB,"pkg_status is 0x%x\r\n", pkg_status);
			if ((pkg_status & PKG_STALL) || (pkg_status & PKG_TIMEOUT) || (pkg_status & PKG_ERROR))
			{
				print(PRINT_811USB,"USB s/r pkg err(STALL,TIME,ERR)\r\n");
				return -5;
			}

			if (retry_time++ > 20)
			{
				print(PRINT_811USB,"USB s/r re_time 10:%x\r\n",pkg_status);
				return -6;
			}
		}

		tmp_ptr += xfer_len;
		data_len -= xfer_len;
		
		delay_ms(1);
	} while (data_len > 0);

	return 0;
}

int32_t ctrl_transfer_data(uint16_t payload, SetupPKG *setup_req, uint8_t *data)
{
#if 1
	int32_t rtval;
	uint8_t pid;
	uint8_t next_pid;
	uint8_t ep_addr;
	
#if 0
	print(PRINT_811USB,"ctrl_transfer_data payload is 0x%x\r\n", payload);
	print(PRINT_811USB,"ctrl_transfer_data setup_req->RequestType is 0x%x\r\n", setup_req->RequestType);
	print(PRINT_811USB,"ctrl_transfer_data setup_req->Request is 0x%x\r\n", setup_req->Request);
	print(PRINT_811USB,"ctrl_transfer_data setup_req->Value is 0x%x\r\n", setup_req->Value);
	print(PRINT_811USB,"ctrl_transfer_data setup_req->Index is 0x%x\r\n", setup_req->Index);
	print(PRINT_811USB,"ctrl_transfer_data setup_req->Length is 0x%x\r\n", setup_req->Length);
#endif
	
	ep_addr = get_ctrl_endpoint();
	rtval = usb_transfer_data(g_usb_dev.USB_Addr, ep_addr, PID_SETUP, 0, payload, sizeof(SetupPKG), (uint8_t *)setup_req);
	if (rtval)
	{
		print(PRINT_811USB,"ctrl_tdata SETUP t err %d\r\n", rtval);
		return -1;
	}

	if (setup_req->Length)
	{
		if (setup_req->RequestType & 0x80)
		{
			pid = PID_IN;
			next_pid = PID_OUT;
		}
		else
		{
			pid = PID_OUT;
			next_pid = PID_IN;
		}
		rtval = usb_transfer_data(g_usb_dev.USB_Addr, ep_addr, pid, 0, payload, setup_req->Length, data);
		if (rtval)
		{
			print(PRINT_811USB,"ctrl_tdata in/out t err %d\r\n", rtval);
			return -2;
		}
	}
	else
	{
		next_pid = PID_IN;
	}
	
	rtval = usb_transfer_data(g_usb_dev.USB_Addr, ep_addr, next_pid, 0, payload, 0, NULL);
	if (rtval)
	{
		print(PRINT_811USB,"ctrl_tdata pkg0 t err %d\r\n", rtval);
		return -3;
	}
#endif
	return 0;
}

int32_t usb_set_address(uint16_t usb_addr)
{
	int32_t rtval;
	SetupPKG setup_req;
	
	if (g_usb_dev.is_attached == 0)
	{
		return -1;
	}

	setup_req.RequestType = REQ_OUT_TYPE;
	setup_req.Request = SET_ADDRESS;
	setup_req.Value = usb_addr;
	setup_req.Index = 0;
	setup_req.Length = 0;

	rtval = ctrl_transfer_data(g_usb_dev.ctrlEP_payload, &setup_req, NULL);
	if (rtval)
	{
		print(PRINT_811USB,"set_usb_add ctrl_tdata err %d\r\n", rtval);
		return -1;
	}
	
	g_usb_dev.USB_Addr = usb_addr;

	return 0;
}

int32_t usb_set_config(uint16_t config_index)
{
	int32_t rtval;
	SetupPKG setup_req;

	setup_req.RequestType = REQ_OUT_TYPE;
	setup_req.Request = SET_CONFIG;
	setup_req.Value = config_index;
	setup_req.Index = 0;
	setup_req.Length = 0;

	rtval = ctrl_transfer_data(g_usb_dev.ctrlEP_payload, &setup_req, NULL);
	if (rtval)
	{
		print(PRINT_811USB,"usb_get_config ctrl_tdata err %d\r\n", rtval);
		return -1;
	}

	return 0;
}

int32_t usb_get_desc(uint8_t desc_type, uint8_t desc_index, uint16_t desc_len, uint8_t *desc_buff)
{
	int32_t rtval;
	uint16_t payload;
	SetupPKG setup_req;
	
	if (g_usb_dev.is_attached == 0)
	{
		return -1;
	}

	setup_req.RequestType = REQ_IN_TYPE;
	setup_req.Request = GET_DESCRIPTOR;
	setup_req.Value = desc_type << 8 | desc_index;
	setup_req.Index = 0;
	setup_req.Length = desc_len;
	
	if (g_usb_dev.ctrlEP_payload == 0)
	{
		payload = 8;
	}
	else
	{
		payload = g_usb_dev.ctrlEP_payload;
	}

	rtval = ctrl_transfer_data(payload, &setup_req, desc_buff);
	if (rtval)
	{
		print(PRINT_811USB,"usb_get_desc ctrl_tdata err %d\r\n", rtval);
		return -2;
	}

	return 0;
}

int32_t parse_interface_endpoint(uint8_t *desc_buff, uint8_t buff_len)
{
	int8_t i;
	uint8_t desc_len;
	uint8_t desc_type;
	uint8_t interface_num = 0;
	uint8_t *temp_ptr;
	EPDesc *pEP_desc;
	IFDesc *pIF_desc;
	pInterface pinface;
	
	temp_ptr = desc_buff + sizeof(CfgDesc);
	do
	{
		desc_len = *temp_ptr;
		desc_type = *(temp_ptr + 1);
		if (desc_type == ITFACE_DESC)
		{
			interface_num++;
			if (interface_num >= 2)
			{
				print(PRINT_811USB,"par_IF_EP IF>1\r\n");
				return -1;
			}
			
			pIF_desc = (IFDesc *)temp_ptr;
			g_usb_dev.usb_interfaces[interface_num - 1].bInterfaceClass = pIF_desc->bInterfaceClass;
			g_usb_dev.usb_interfaces[interface_num - 1].bInterfaceSubClass = pIF_desc->bInterfaceSubClass;
			g_usb_dev.usb_interfaces[interface_num - 1].bInterfaceProtocol = pIF_desc->bInterfaceProtocol;
			g_usb_dev.inface_num++;
		}
		else if (desc_type == ENDPNT_DESC)
		{
			if (interface_num == 0)
			{
				print(PRINT_811USB,"found a EP desc, err\r\n");  //before interface desc found a endpoint desc,
				return -2;
			}
			
			pEP_desc = (EPDesc *)temp_ptr;
			pinface = &g_usb_dev.usb_interfaces[interface_num - 1];
			pinface->bEndpointAttr[pinface->bEndpointNum] = pEP_desc->bAttr;
			pinface->bEndpointAddr[pinface->bEndpointNum] = pEP_desc->bEPAdd;
			pinface->wEndpointPayload[pinface->bEndpointNum] = pEP_desc->wPayLoad;
			pinface->wEndpointInterval[pinface->bEndpointNum] = pEP_desc->bInterval;
			pinface->bEndpointNum++;
		}
		temp_ptr += desc_len;
	} while (temp_ptr - desc_buff < buff_len);
	
	if (interface_num == 0)
	{
		print(PRINT_811USB,"no IFace desc err\r\n");
		return -3;
	}
	
	g_usb_dev.ums_index = INVALID_IF_ADDR;
	for (i = 0; i < g_usb_dev.inface_num; i++)
	{
		if (g_usb_dev.usb_interfaces[i].bInterfaceClass == 0x08 && 
			g_usb_dev.usb_interfaces[i].bInterfaceSubClass == 0x06 &&
			g_usb_dev.usb_interfaces[i].bInterfaceProtocol == 0x50)
		{
			g_usb_dev.ums_index = i;
		}
	}
	
	if (g_usb_dev.ums_index == INVALID_IF_ADDR)
	{
		print(PRINT_811USB,"usb not MSC\r\n");   //the usb device is not a usb mass storage device, not supported!
		return -4;
	}
	
	return  0;
}

void usb_detect_init()
{
	sl811_reg_write(USB_CONTROL02_REG, 0xae);
	sl811_reg_write(USB_SOFLOWCNT_REG, 0xe0);
	sl811_reg_write(USB_CONTROL01_REG, 0x05);
	
	sl811_reg_write(USB_PIDENPT_REG(USBA_INDEX), 0x50);   		/* Setup SOF Token, EP0 */
	sl811_reg_write(USB_DEVADDR_REG(USBA_INDEX), 0x00);			/* reset to zero count */
	sl811_reg_write(USB_HOSTCTL_REG(USBA_INDEX), 0x01);   		/* start generate SOF or EOP */
	delay_ms(25);					        					/* Hub required approx. 24.1m */
	sl811_reg_write(USB_INTSTATUS_REG, INT_CLEAR);				/* Clear Interrupt status */
}

void usb_reset_dev()
{
	uint8_t reg_value;
	
	reg_value = sl811_reg_read(USB_CONTROL01_REG);
	sl811_reg_write(USB_CONTROL01_REG, reg_value | 0x08);
	delay_ms(10);
	sl811_reg_write(USB_CONTROL01_REG, reg_value);
}

void usb_clean_info()
{
	sl811_reg_write(USB_INTSTATUS_REG, INT_CLEAR);
	memset(&g_usb_dev, 0, sizeof(USBDev));
}

int32_t usb_bulk_command(pBulk_CBW cbw, uint8_t *cmd_data, int32_t data_len)
{
	uint16_t times = 0;
	int32_t rtval;
	pInterface pIF;
	int8_t bulk_in_addr;
	int8_t bulk_out_addr;
	int16_t bulk_in_payload;
	int16_t bulk_out_payload;
	Bulk_CSW csw;
	
	if (g_usb_dev.is_enumed == 0)
	{
		print(PRINT_811USB,"usb not enum\r\n");    //usb device not enumed
		return -1;
	}
	if (g_usb_dev.inface_num == 0 || g_usb_dev.ums_index == INVALID_IF_ADDR)
	{
		print(PRINT_811USB,"no MSC\r\n");    //no usb mass strorage device found
		return -2;
	}
	
	pIF = &g_usb_dev.usb_interfaces[g_usb_dev.ums_index];
	rtval = get_bulkin_endpoint(&bulk_in_addr, &bulk_in_payload);
	if (rtval)
	{
		print(PRINT_811USB,"get_bulk_EP err %d\r\n", rtval);
		return -3;
	}
	rtval = get_bulkout_endpoint(&bulk_out_addr, &bulk_out_payload);
	if (rtval)
	{
		print(PRINT_811USB,"get_bulk_EP err %d\r\n", rtval);
		return -4;
	}
	
	rtval = usb_transfer_data(g_usb_dev.USB_Addr, bulk_out_addr, PID_OUT, 0, bulk_out_payload, sizeof(Bulk_CBW), (uint8_t *)cbw);
	if (rtval)
	{
		print(PRINT_811USB,"usb_tdata Bulk_CBW err %d\r\n", rtval);
		return -5;
	}
	
	if (cbw->CBWDataLength)
	{
		if (cbw->CBWFlags & CBW_IN_FLAG)
		{
			rtval = usb_transfer_data(g_usb_dev.USB_Addr, bulk_in_addr, PID_IN, 0, bulk_in_payload, data_len, cmd_data);
		}
		else
		{
			rtval = usb_transfer_data(g_usb_dev.USB_Addr, bulk_out_addr, PID_OUT, 0, bulk_out_payload, data_len, cmd_data);
		}
		if (rtval)
		{
			print(PRINT_811USB,"usb_bulk_cmd usb_tdata cmd_data err %d\r\n", rtval);
			return -6;
		}
	}
	delay_ms(10);
	//print(PRINT_811USB,"USB_Addr is %d, bulk_in_addr is %d, bulk_in_payload is %d\r\n", g_usb_dev.USB_Addr, bulk_in_addr, bulk_in_payload);
	do 
	{
		rtval = usb_transfer_data(g_usb_dev.USB_Addr, bulk_in_addr, PID_IN, 0, bulk_in_payload, sizeof(Bulk_CSW), (uint8_t *)&csw);
		
		times++;
		delay_ms(10);
	}
	while (rtval == -6 && times < 1000);
	if (rtval)
	{
		print(PRINT_811USB,"usb_bulk_cmd usb_tdata Bulk_CSW err %d\r\n", rtval);
		return -7;
	}
//	print(PRINT_811USB,"times is %d\r\n",times);
	if (csw.CSWSignature != UMS_CSW_SIG || csw.CSWStatus != 0x00)
	{
		print(PRINT_811USB,"usb_bulk_cmd check CSW err\r\n");
		return -8;	
	}
	
	return 0;
}

int32_t usb_check_ready()
{
	int32_t rtval;
	pInterface pIF;
	Bulk_CBW cbw_req;
	
	pIF = &g_usb_dev.usb_interfaces[g_usb_dev.ums_index];
	cbw_req.CBWSignature = UMS_CBW_SIG;
	cbw_req.CBWTag = USB_SHUDUN_TAG;
	cbw_req.CBWDataLength = 0;
	cbw_req.CBWFlags = CBW_OUT_FLAG;
	cbw_req.CBWLUNNum = (pIF->bCurrentLUNnum &0x0F);
	cbw_req.CBWCBLength = 0x06;
	memset(cbw_req.CBWCB, 0, 0x10);
	cbw_req.CBWCB[0] = 0x00;
	
	rtval = usb_bulk_command(&cbw_req, NULL, 0);
	if (rtval)
	{
		print(PRINT_811USB,"usb_CK_ready usb_bulk_cmd err %d\r\n", rtval);
		return -1;
	}
	
	return 0;
}

int32_t usb_ums_init()
{
	int32_t rtval;
	SetupPKG setup_req;
	uint8_t max_lun_num;
	
	if (g_usb_dev.is_enumed == 0)
	{
		print(PRINT_811USB,"usb not enum\r\n");
		return -1;
	}
	
	if (g_usb_dev.inface_num == 0 || g_usb_dev.ums_index == INVALID_IF_ADDR)
	{
		print(PRINT_811USB,"no usb MSC\r\n");
		return -2;
	}
	
	//reset mass storage device
//	setup_req.RequestType = REQ_UMS_RESET;
//	setup_req.Request = CMD_UMS_RESET;
//	setup_req.Value = 0;
//	setup_req.Index = g_usb_dev.ums_index;
//	setup_req.Length = 0;	
//	rtval = ctrl_transfer_data(g_usb_dev.ctrlEP_payload, &setup_req, NULL);
//	if (rtval)
//	{
//		print(PRINT_811USB,"ctrl_transfer_data REQ_UMS_RESET error!!\r\n");
//		return -3;		
//	}
	
	//get max LUN num
	setup_req.RequestType = REQ_UMS_GETLUN;
	setup_req.Request = CMD_UMS_GETLUN;
	setup_req.Value = 0;
	setup_req.Index = g_usb_dev.ums_index;
	setup_req.Length = 1;
	rtval = ctrl_transfer_data(g_usb_dev.ctrlEP_payload, &setup_req, &max_lun_num);
	if (rtval)
	{
		print(PRINT_811USB,"ctrl_tdata UMS_GETLUN err\r\n");
		return -4;		
	}
	if (max_lun_num >= 1)
	{
		print(PRINT_811USB,"more LUN\r\n");     //more than one LUN, not supported
		return -5;
	}
	g_usb_dev.usb_interfaces[g_usb_dev.ums_index].bCurrentLUNnum = max_lun_num;
	
	//check device is ready or not
	rtval = usb_check_ready();
	if (rtval)
	{
		print(PRINT_811USB,"usb_CK_RD err\r\n");
		return -6;
	}
	
	return 0;
}

int32_t usb_is_detach()
{
	if ( (sl811_reg_read(USB_INTSTATUS_REG) & INSERT_REMOVE) || (sl811_reg_read(USB_INTSTATUS_REG) & USB_DETECT) )
	{										
		sl811_reg_write(USB_INTSTATUS_REG, INT_CLEAR);
		return 1;									
	}
	return 0;
}
