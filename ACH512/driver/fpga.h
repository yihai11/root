#ifndef _FPGA_H_
#define	_FPGA_H_

#include "gpio.h"
#include "hsm2_init.h"
#include "config.h"
#ifndef CHECK
#define PRINT_FPGA 2
#else
#define PRINT_FPGA 0
#endif
#define		REG_FREE				1
#define		REG_BUSY				0
#define		REG_REST				3
//��һ����
#define	FPGA_WRITE_DATA_SIZE		(FPGA_WRITE_REG_SIZE-FPGA_DATAHEAD_LEN-FPGA_MCUHEAD_LEN)
#define PAGE_NUM(l)							(l + FPGA_WRITE_DATA_SIZE - 1)/FPGA_WRITE_DATA_SIZE

/*****------FPGA�Ĵ�����ַ����------*****/ //FPGA_CLEAR_R_STATE_ADDR//0x60800006
#define FPGA_BASE_ADDR  					 MIM_MEM_ADDR(EMEM1)
#define FPGA_VERL_MASTER_ADDR			(FPGA_BASE_ADDR+0x00)			//���汾�Ĵ���
#define FPGA_VERL_SLAVER_ADDR			(FPGA_BASE_ADDR+0x02)			//�ΰ汾�Ĵ���
#define FPGA_VERL_CORRECT_ADDR		(FPGA_BASE_ADDR+0x04)			//�����汾�Ĵ���
#define	FPGA_VERH_REG_ADDR				(FPGA_BASE_ADDR+0x06)     //�汾�Ĵ������� ��
#define FPGA_VERL_REG_ADDR				(FPGA_BASE_ADDR+0x08)			//�汾�Ĵ�������
#define FPGA_CHECK_REG_ADDR				(FPGA_BASE_ADDR+0x0A)			//���ԼĴ�����ȡ��
#define FPGA_ARG_REG_ADDR					(FPGA_BASE_ADDR+0x0C)     //Ӳ���汾�Ĵ������㷨����
#define FPGA_RESET_SM2_ADDR				(FPGA_BASE_ADDR+0x0E)			//��λSM2�Ĵ���
#define FPGA_CARD_TYPE_ADDR				(FPGA_BASE_ADDR+0x10)

#define FPGA_HS				0x00			//HS:  000 000  00 ���ܿ�PEM611
#define FPGA_SM1			0x02			//     000 001  01 ǩ����PEM601
#define FPGA_SM2			0x01			//     000 010  02 ���ܿ�PEM611 SM1
																//     000 011  03 ǩ����PEM601 SM1
#define FPGA_HP				0x08			//HP:  001 000  08 ����λ+1ΪоƬ����

#define FPGA_TS				0x10			//TS:  010 000  10 S10A
#define FPGA_S10A			0x00			//     010 001  11 S10G
#define FPGA_S10G			0x01

//#if HSMD1
#define FPGA_HSMD1_STATUS_ADDR			(FPGA_BASE_ADDR+0x12)		//bit0~bit3:1��HSMD1_n LOCKED
																														//          0��HSMD1_n NOT LOCKED
																														//bit4~bit7:1��HSMD1_n UNRESET
																														//          0��HSMD1_n RESET
#define FPGA_HSMD1_SELECT_ADDR			(FPGA_BASE_ADDR+0x14)		//bit0~bit3:1��HSMD1_nѡ�н������ã�
																														//          0��HSMD1_nδѡ�н������ã�
//#else

#define FPGA_SM3SM4_STATUS_ADDR			(FPGA_BASE_ADDR+0x12)

//#endif

#define	FPGA_FRAMING_CMD_ADDR			(FPGA_BASE_ADDR+0x20)			//֡����Ĵ���
#define	FPGA_FRAMING_LEN_ADDR			(FPGA_BASE_ADDR+0x22)			//֡���ȼĴ���
#define	FPGA_FRAMING_STATE_ADDR		(FPGA_BASE_ADDR+0x24)			//֡״̬�Ĵ���
#define	FPGA_CLEAR_S_STATE_ADDR		(FPGA_BASE_ADDR+0x26)			//֡״̬����Ĵ���
#define	FPGA_FRAME_REC_STATE_ADDR	(FPGA_BASE_ADDR+0x28)   //֡״���ճ��Ĵ��� ������MUC�����Ƿ�Ϊ�ձ�־
#define FPGA_DRIVER_LEVEL_ADDR		(FPGA_BASE_ADDR+0x2A)   //14 ����/MCU->FPGA����ˮλ
#define FPGA_MCU_LEVEL_ADDR				(FPGA_BASE_ADDR+0x2C)   //16 FPGA->muc ˮλ
#define FPGA_MCU_DRIVER_WRITE			(FPGA_BASE_ADDR+0x2E)   //MCU��FPGAͨѶ�Ĵ���ֻд
#define FPGA_MCU_DRIVER_READ			(FPGA_BASE_ADDR+0x30)   //MCU��FPGAͨѶ�Ĵ���ֻ��
#define FPGA_LED_CONTR_ADDR				(FPGA_BASE_ADDR+0x32)   //FPGA��LED����15bit:1->����0->��˸ 9-0bit����˸T=��V+1��*2
#define FPGA_RESET_MCU_ADDR				(FPGA_BASE_ADDR+0x34)   //FPGA��λMCUͨѶ�Ĵ��� 1����λ 0���⸴λ
#define FPGA_INT_CLEAR_ADDR				(FPGA_BASE_ADDR+0x36)   //FPGA�ж��¼�����Ĵ��� 1 ������ж� 0����Ϊ0 �ŻῪʼ�´��ϱ�

#define FPGA_DATA_WRITE_ADDR			(FPGA_BASE_ADDR+0x1000)
#define	FPGA_DATA_READ_ADDR				(FPGA_BASE_ADDR+0x2000) //ת���������ݵ�ַ
#define	FPGA_DATA_READ_ADDR_EX		(FPGA_BASE_ADDR+0x2002) //����FPGA���ݵ�ַ

#define FPGA_WRITE_REG_SIZE			0x1000
#define	FPGA_READ_REG_SIZE			0x1000

/*****------ͨѶ֡����------*****/

#define	FPGA_HEAD_MARK				0xD6FA

#define FPGA_DATA_HOST_DMA0		0x00
#define FPGA_DATA_HOST_DMA1		0x01
#define	FPGA_DATA_SM3					0x02
#define FPGA_DATA_SM4					0x03
#define FPGA_DATA_ARM					0x04


#define FPGA_DATA_SM2_HS			0x05
#define FPGA_DATA_SM2_HP			0x0A
#define FPGA_DATA_SM4_1				0x0f
#define HSM2_NUM ((HSMD1)? 4 : 1)
#define FPGA_DATA_SM2_HSM2 ((HSMD1)? FPGA_DATA_SM2_HP : FPGA_DATA_SM2_HS)

#define FPGA_DATA_SM2_SSX			0x06
#define FPGA_DATA_SM1 				0x07
#define FPGA_DATA_RANDOM			0x08
#define FPGA_DATA_DRIVER			0x80


#define FPGA_CHANNEL_DEF			0x01
#define FPGA_KEY_PKG					0x01
#define	FPGA_SET_KEY					0x02		//Э����Կ�洢
#define FPGA_CLEAR_KEY				0x03

#define FPGA_BLOCK_LEN				16
#define FPGA_DATAHEAD_LEN			16
#define FPGA_MCUHEAD_LEN			16
#define FPGA_ALGHEAD_LEN			16
#define FPGA_HSMD1_LEN				16
#define FPGA_DATA_LEN(len)	((len + FPGA_BLOCK_LEN - 1) / FPGA_BLOCK_LEN * FPGA_BLOCK_LEN)

#define FPGA_ENABLE					0x01
#define FPGA_DISABLE				0x00

#define FPGA_ECB_MODE				0x00
#define FPGA_CBC_MODE				0x10

#define	PACK_SINGLE					0x00
#define	PACK_HEAD						0x04
#define	PACK_MID						0x08
#define	PACK_END						0x0D

#define ENCRYPT_MODE				0x00
#define DECRYPT_MODE				0x01

//FPGA Header SM2 CMD
#define CMD_SM2_ENCRYPT				0x00
#define CMD_SM2_DECRYPT				0x01
#define CMD_SM2_SIGN					0x02
#define CMD_SM2_VERIFY				0x03
#define CMD_SM2_SETKEY				0x04
#define CMD_SM2_GETKEY				0x05
#define CMD_SM2_DELKEY				0x06
#define CMD_SM2_GENKEY				0x07
#define CMD_SM2_EXCHGKEY			0x09

#define CMD_SM2_INIT0					0x0A
#define CMD_SM2_INIT1					0x0B
#define CMD_SM2_INIT2					0x0C
#define CMD_SM2_PTMUL					0x0D
#define CMD_SM2_MD1WR					0x0E
#define CMD_SM2_MD1RD					0x0F



#define KEY_TYPE_LOOKUP				0x0
#define KEY_TYPE_INPACK				0x1
#define KEY_TYPE_SETKEY				0x2
#define KEY_TYPE_DELKEY				0x3


#define	FPGA_REG(x)						(*(volatile uint16_t *) (x))

//#define SET_FPGA_READ_FINISH			FPGA_REG(FPGA_FRAME_REC_STATE_ADDR)=0;

#pragma pack(1)
typedef struct {
	unsigned char  src;
	unsigned char  dst;
	unsigned short mark;
	unsigned short pkglen;
	unsigned short retpkglen;
	unsigned short keyindex : 14;
	unsigned char  keytype : 2;
	unsigned char  sm2_cmd;
	unsigned char  channel;
	unsigned int   reserved;
} FPGAHeader;

typedef struct {
	unsigned short check;    // У��ͷ 0xF5A0
	unsigned short length;   // ������
	unsigned short total;    // ������
	unsigned short count;    // ��ǰ������
	unsigned short cmd;		   // ����
	unsigned short arg1; 	   // ����1
	unsigned short arg2; 	   // ����2
	unsigned short result; 	 // ������ 0==�ɹ�
} MCUHeader;
#pragma pack()

struct Str_PACKAGE {
	FPGAHeader fpga_package;
	MCUHeader  arm_package;
	uint16_t cipher_data[16];
	uint16_t IV_data[16];
	uint16_t data[2048];				//�ܰ���4096bytes
};

typedef struct {
	unsigned int length;      // У��ͷ 0xF5A0
	unsigned int addr;        // ������
	unsigned int reserve;     // ����
	unsigned int reserve1;    // ����
} HSMD1CMD;

void fpga_init(void);
uint32_t fpga_get_ver(void);
uint8_t fpga_check_reg(void);
uint8_t fpga_receive_data(void);

uint8_t * fpga_read_start_ex(void);
uint8_t * fpga_read_start(void);
void fpga_read_finish(void);

unsigned char fpga_write_start(void);
void fpga_write_finish(uint32_t length);


uint8_t fpga_wait_allow_write(void);
uint8_t fpga_send_data(uint8_t *databuff,uint16_t length);
void fpga_read_finish(void);
void fpga_write_busy(void);

void get_fpga_header(FPGAHeader *header, unsigned char *buff);
unsigned char *set_fpga_header(unsigned char *buff, FPGAHeader *header);
unsigned char *get_mcu_header(unsigned char *buff, MCUHeader *header);
unsigned char *set_mcu_header(unsigned char *buff, MCUHeader *header);

unsigned char *alg_header(unsigned char *alg_header, unsigned int pkg_index,\
													unsigned int pkg_len, unsigned int alg_mod, \
													unsigned int crypto_mod, unsigned int key_en,\
													unsigned int key_len, unsigned int iv_en, unsigned int iv_len);
														
//fpga program function
uint8_t fpga_pro_start(void);
void fpga_pro_write_byte(uint8_t buff_byte);
void fpga_pro_write(uint8_t * pro_buff,uint16_t length);
uint8_t fpga_wait_done(uint8_t timeout);
void fpga_init_ready(void);
int32_t fpga_set_symkey(uint8_t dst_id, uint16_t key_index, uint8_t *key_buff, uint16_t key_len);
uint8_t fpga_handshake(void);
void fpga_int_clear(void);
void fpga_reset_mcu(void);

#endif
