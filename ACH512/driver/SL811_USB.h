#ifndef SL811_USB_H
#define SL811_USB_H

#include <stdint.h>
#include <SL811.h>

#define USB_HOST_INDEX_ADDR    	(*(volatile uint8_t* )MIM_MEM_ADDR(EMEM3))
#define USB_HOST_DATA_ADDR     	(*(volatile uint8_t* )(MIM_MEM_ADDR(EMEM3) + 1))

//SL811 GPIO Pin
#define	HOST_A0					31
#define	HOST_RST				34

//SL811 Registor
#define USBA_INDEX				0x00
#define USBB_INDEX				0x01

#define USB_HOSTCTL_REG(index)	(0x00 + index * 0x08)
#define USB_HOSTADD_REG(index)	(0x01 + index * 0x08)
#define USB_XFERLEN_REG(index)	(0x02 + index * 0x08)
//for read
#define USB_XSTATUS_REG(index)	(0x03 + index * 0x08)
#define USB_CONTRER_REG(index)	(0x04 + index * 0x08)
//for write
#define USB_PIDENPT_REG(index)	(0x03 + index * 0x08)
#define USB_DEVADDR_REG(index)	(0x04 + index * 0x08)

#define USB_CONTROL01_REG		0x05
#define USB_INTENABLE_REG		0x06
#define USB_INTSTATUS_REG		0x0D
//for read
#define USB_HWVERSION_REG		0x0E
#define USB_SOFDIVCNT_REG		0x0F
//for write
#define USB_SOFLOWCNT_REG		0x0E
#define USB_CONTROL02_REG		0x0F

#define USBA_START_ADDR			0x10
#define USBA_MAX_LEN			0x40

//Interrupt Status Mask
#define USB_A_DONE				0x01
#define USB_B_DONE				0x02
#define SOF_TIMER				0x10
#define INSERT_REMOVE			0x20
#define USB_DETECT				0x40
#define USB_DPLUS				0x80
#define INT_CLEAR				0xFF

//usb request type defintion
#define GET_STATUS      		0x00																  
#define CLEAR_FEATURE   		0x01
#define SET_FEATURE     		0x03
#define SET_ADDRESS     		0x05
#define GET_DESCRIPTOR  		0x06
#define SET_DESCRIPTOR  		0x07
#define GET_CONFIG      		0x08
#define SET_CONFIG      		0x09
#define GET_INTERFACE   		0x0a
#define SET_INTERFACE   		0x0b
#define SYNCH_FRAME     		0x0c

//descriptor type
#define DEVICE_DESC				0x01
#define CONFIG_DESC				0x02
#define STRING_DESC				0x03
#define ITFACE_DESC				0x04
#define ENDPNT_DESC				0x05

//endpoint type
#define EP_CRTL_TYPE			0x00
#define EP_ISOC_TYPE			0x01
#define EP_BULK_TYPE			0x02
#define EP_INTR_TYPE			0x03

//sl811 pid defintion
#define PID_SETUP   			0xD0 
#define PID_IN      			0x90
#define PID_OUT     			0x10

//Endpoint Status Mask defintion
#define PKG_ACK					0x01
#define PKG_ERROR				0x02
#define PKG_TIMEOUT				0x04
#define PKG_SEQUENCE			0x08
#define PKG_SETUP				0x10
#define PKG_OVERFLOW			0x20
#define PKG_NAK					0x40
#define PKG_STALL				0x80

//send & recv CMD
#define DATA0_WRITE				0x27
#define DATA1_WRITE				0x67
#define DATA0_READ				0x23
#define ISO_BIT     			0x10
#define TOGGLE_BIT				0x40

//usb standard request type
#define REQ_OUT_TYPE			0x00
#define REQ_IN_TYPE				0x80

#define INVALID_IF_ADDR			0xFF
#define INVALID_EP_ADDR			0xFF

#define MAX_INTFACE				0x02
#define MAX_ENDPONT				0x04

#define DEF_USB_ADDR			0x01
#define DEF_CFG_NUM				0x01
#define DEF_LUN_NUM				0x00


#define REQ_UMS_RESET			0x21
#define REQ_UMS_GETLUN			0xA1
#define CMD_UMS_RESET			0xFF
#define CMD_UMS_GETLUN			0xFE

#define UMS_CBW_SIG				0x43425355
#define UMS_CSW_SIG				0x53425355
#define USB_SHUDUN_TAG			0xAA5500FF
#define CBW_IN_FLAG				0x80
#define CBW_OUT_FLAG			0x00

/* USB specific request */
typedef __packed struct
{
    uint8_t RequestType;
    uint8_t Request;
    uint16_t Value;
    uint16_t Index;
    uint16_t Length;
} SetupPKG/*, *pSetupPKG*/;

/* Standard Device Descriptor */
typedef __packed struct
{   
    uint8_t bLength;
    uint8_t bDescriptorType;
    uint16_t bcdUSB;
    uint8_t bDeviceClass;
    uint8_t bDeviceSubClass;
    uint8_t bDeviceProtocol;
    uint8_t bMaxPacketSize0;
    uint16_t idVendor;
    uint16_t idProduct;
    uint16_t bcdDevice;
    uint8_t iManufacturer;
    uint8_t iProduct;
    uint8_t iSerialNumber;
    uint8_t bNumConfigurations;
} DevDesc/*, *pDevDesc*/;

typedef __packed struct
{
	uint8_t bLength;
	uint8_t bDescriptorType;
	uint8_t bInterfaceNumber;
	uint8_t bAlternateSetting;
	uint8_t bNumEndpoints;
	uint8_t bInterfaceClass;
	uint8_t bInterfaceSubClass;
	uint8_t bInterfaceProtocol;
	uint8_t iInterface;
} IFDesc;

/* Standard Configuration Descriptor */
typedef __packed struct
{	
    uint8_t bLength;                 /* Size of descriptor in byte */
	uint8_t bType;					 /* Configuration */
	uint16_t wLength;                /* Total length */
	uint8_t bNumIntf;				 /* Number of interface */
	uint8_t bCV;             		 /* bConfigurationValue */
	uint8_t bIndex;          		 /* iConfiguration */
	uint8_t bAttr;                   /* Configuration Characteristic */
	uint8_t bMaxPower;				 /* Power config */
} CfgDesc/*, *pCfgDesc*/;

/* Standard EndPoint Descriptor */
typedef __packed struct
{	
    uint8_t bLength;
	uint8_t bType;
	uint8_t bEPAdd;
	uint8_t bAttr;
	uint16_t wPayLoad;               /* low-speed this must be 0x08 */
	uint8_t bInterval;
} EPDesc/*, *pEPDesc*/;

/* Standard String Descriptor */
typedef __packed struct
{	
    uint8_t bLength;
	uint8_t bType;
	uint16_t wLang;
} StrDesc/*, *pStrDesc*/;

/* Standard CBW struct */
typedef __packed struct
{
	uint32_t CBWSignature;
	uint32_t CBWTag;
	uint32_t CBWDataLength;
	uint8_t CBWFlags;
	uint8_t	CBWLUNNum;
	uint8_t CBWCBLength;
	uint8_t CBWCB[16];
} Bulk_CBW, *pBulk_CBW;

/* Standard CSW struct */
typedef __packed struct
{
	uint32_t CSWSignature;
	uint32_t CSWTag;
	uint32_t CSWDataResidue;
	uint8_t CSWStatus;
} Bulk_CSW, *pBulk_CSW;

typedef struct
{
	uint8_t bInterfaceClass;
	uint8_t bInterfaceSubClass;
	uint8_t bInterfaceProtocol;
	uint8_t bEndpointNum;
	uint8_t bEndpointAddr[MAX_ENDPONT];
	uint8_t bEndpointAttr[MAX_ENDPONT];
	uint16_t wEndpointPayload[MAX_ENDPONT];
	uint16_t wEndpointInterval[MAX_ENDPONT];
	uint8_t bDataToggle[MAX_ENDPONT];
	uint8_t bCurrentLUNnum;
} Interface, *pInterface;

typedef struct
{
	//flags
	uint8_t	is_attached;
	uint8_t is_enumed;
	uint8_t	USB_Addr;
	
  uint8_t ctrlEP_addr;
  uint8_t ctrlEP_payload;
//	uint8_t ctrlEP_datatoggle;
	
	uint8_t inface_num;
	uint8_t ums_index;
	Interface usb_interfaces[MAX_INTFACE];
} USBDev, *pUSBDev;


//function definetion
void sl811_os_init(void);
void sl811_soc_init(void);
void sl811_reg_write(uint8_t reg_addr, uint8_t reg_value);
void sl811_reg_write_continue(uint8_t reg_value);
void sl811_reg_write_buff(uint8_t reg_addr, uint8_t *buff, uint8_t size);
uint8_t sl811_reg_read(uint8_t reg_addr);
uint8_t sl811_reg_read_continue(void);
void sl811_reg_read_buff(uint8_t reg_addr, uint8_t *buff, uint8_t size);
int32_t usb_transfer_data(uint8_t usb_addr, uint8_t endpoint, uint8_t pid, uint8_t iso, uint16_t payload, uint16_t data_len, uint8_t *data);
int32_t ctrl_transfer_data(uint16_t payload, SetupPKG *setup_req, uint8_t *data);
int32_t usb_set_address(uint16_t usb_addr);
int32_t usb_set_config(uint16_t config_index);
int32_t usb_get_desc(uint8_t desc_type, uint8_t desc_index, uint16_t desc_len, uint8_t *desc_buff);
int32_t parse_interface_endpoint(uint8_t *desc_buff, uint8_t buff_len);
int32_t usb_ums_init(void);
int32_t usb_check_ready(void);
int32_t usb_bulk_command(pBulk_CBW cbw, uint8_t *cmd_data, int32_t data_len);
void usb_detect_init(void);
void usb_reset_dev(void);
int32_t usb_is_detach(void);

//void printf_byte(uint8_t *buff, uint32_t len);

#endif
