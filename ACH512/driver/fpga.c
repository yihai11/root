#include "fpga.h"
#include "sram.h"
#include "type_code.h"
#include "FreeRTOS.h"
#include "task.h"

extern uint8_t ArgFlag;	
/*********************************************************************************************************
** �������ƣ�chgBELE_32/16
** ����������32/16λ�������ݴ�С��ת��
*********************************************************************************************************/
unsigned int chgBELE_32(unsigned int i)
{
	unsigned int ret = (i) & 0xFF; ret = ret << 8;
	ret |= (i >> 8) & 0xFF; ret = ret << 8;
	ret |= (i >> 16) & 0xFF; ret = ret << 8;
	ret |= (i >> 24) & 0xFF;
	return ret;
}

unsigned short chgBELE_16(unsigned short i)
{
	unsigned short ret = (i) & 0xFF;
	ret = (unsigned short)(ret << 8);
	ret |= (i >> 8) & 0xFF; 
	return ret;
}

uint32_t fpga_get_ver(void)
{
	uint32_t ver_fpga=0;
	ver_fpga=((uint32_t)FPGA_REG(FPGA_VERH_REG_ADDR)<<16)+FPGA_REG(FPGA_VERL_REG_ADDR);
	return ver_fpga;
}

uint8_t fpga_check_reg(void)
{
	uint16_t check_data=0xA55A;
	FPGA_REG(FPGA_CHECK_REG_ADDR)=check_data;
	check_data=~check_data;
	if(check_data != FPGA_REG(FPGA_CHECK_REG_ADDR))
		return 1;
	else
		return 0;
}

uint8_t fpga_handshake(void)
{
	uint8_t error=0;
	if(fpga_get_ver() == 0)
		error=1;
	if(fpga_check_reg())
		error=2;
	return error;
}

void fpga_init_ready(void){
	
	uint8_t wait;
	do
	{
		wait = fpga_handshake();
	} while (wait != 0);
	

	
}
uint8_t fpga_receive_data_ex(void)//ͨ��2 ����FPGA����
{
		if((FPGA_REG(FPGA_FRAME_REC_STATE_ADDR)&0x02)== 0)
			return 1;
		else
			return 0;
}
uint8_t fpga_receive_data(void) //ͨ��1 ����FPGAת��MCU
{
		if((FPGA_REG(FPGA_FRAME_REC_STATE_ADDR)&0x01)== 0)
			return 1;
		else
			return 0;
}
uint8_t  fpga_wait_allow_write(void)
{
	return FPGA_REG(FPGA_FRAMING_STATE_ADDR);
//	if(FPGA_REG(FPGA_FRAMING_STATE_ADDR) == REG_FREE)
//		return REG_FREE;
//	else
//		return REG_BUSY;
}

void fpga_write_busy(void)
{
	FPGA_REG(FPGA_CLEAR_S_STATE_ADDR) = 1;
	FPGA_REG(FPGA_CLEAR_S_STATE_ADDR) = 0;
}

void fpga_write_finish(uint32_t length)
{
	if(FPGA_RESET==FPGA_FLAG) return;
	FPGA_REG(FPGA_FRAMING_LEN_ADDR)=length;
	FPGA_REG(FPGA_FRAMING_CMD_ADDR)=1;
	FPGA_REG(FPGA_FRAMING_CMD_ADDR)=0;
}

void fpga_read_finish(void)
{
//	FPGA_REG(FPGA_CLEAR_R_STATE_ADDR)=1;
//	FPGA_REG(FPGA_CLEAR_R_STATE_ADDR)=0;
}
void fpga_int_clear(void)
{
	FPGA_REG(FPGA_INT_CLEAR_ADDR)=0x01;
	//print(PRINT_FPGA,"get fpga int signal %x.\r\n",FPGA_REG(FPGA_INT_CLEAR_ADDR));
	FPGA_REG(FPGA_INT_CLEAR_ADDR)=0x00;
	//print(PRINT_FPGA,"get fpga int clear %x.\r\n",FPGA_REG(FPGA_INT_CLEAR_ADDR));
}
void fpga_reset_mcu(void)
{
	FPGA_REG(FPGA_RESET_MCU_ADDR)=0x01;
	print(PRINT_FPGA,"F_RE_MCU %x.\r\n",FPGA_REG(FPGA_RESET_MCU_ADDR));
	FPGA_REG(FPGA_RESET_MCU_ADDR)=0x00;
	print(PRINT_FPGA,"F_RE_MCU %x.\r\n",FPGA_REG(FPGA_RESET_MCU_ADDR));

}
uint8_t * fpga_read_start(void)
{
	while(!fpga_receive_data());
	return 0;
}
uint8_t * fpga_read_start_ex11(void)
{
	while(!fpga_receive_data());
	return (uint8_t *)FPGA_DATA_READ_ADDR;
}

uint8_t FPGAdt[4100]={0};
uint8_t * fpga_read_start_ex(void)
{
	uint16_t *pdt = (uint16_t *)FPGAdt;
	FPGAHeader * FH = (FPGAHeader *)FPGAdt;
	int32_t tmpL=0;
	uint32_t t_cont1 = 0;
	uint32_t t_cont0 = xTaskGetTickCount();
	memset(FPGAdt,0,4096);
	while(!fpga_receive_data_ex()){ //�ȴ�������
		t_cont1 = xTaskGetTickCount();
		if((t_cont1 - t_cont0) > 2000){//2�������ݣ���ʱ����NULL��
			return NULL;
		}
	}
	while(fpga_receive_data_ex()){
		//��ȡ����
		*pdt = *(uint16_t *)FPGA_DATA_READ_ADDR_EX;  pdt++;
		if(FH->dst != FPGA_DATA_ARM){
			tmpL = 0;
			pdt = (uint16_t *)FPGAdt;
			continue;
		}
		//�����
		tmpL+=2;
		if(tmpL > 4096){
			tmpL = 4096;
			pdt = (uint16_t *)(FPGAdt+4097);
		}
		//���գ��˳��������ݡ�	
		if(!fpga_receive_data_ex()){
			return FPGAdt;
		}
	}
}


unsigned char fpga_write_start(void)
{
	if(fpga_wait_allow_write() == REG_REST) return REG_REST;
	while(fpga_wait_allow_write() != REG_FREE);
	fpga_write_busy();
	return REG_FREE;
}

void get_fpga_header(FPGAHeader *header, unsigned char *buff)
{
	memcpy(header, buff, sizeof(FPGAHeader));
}


unsigned char *set_fpga_header(unsigned char *buff, FPGAHeader *header)
{
	header->mark = 0xD6FA;
	memcpy(buff, header, sizeof(FPGAHeader));
	return buff + FPGA_DATAHEAD_LEN;
}

unsigned char *get_mcu_header(unsigned char *buff, MCUHeader *header)
{
	memcpy(header, buff, sizeof(MCUHeader));
	return (buff + FPGA_MCUHEAD_LEN);
}

unsigned char *set_mcu_header(unsigned char *buff, MCUHeader *header)
{
	memcpy(buff, header, sizeof(MCUHeader));
	return (buff + FPGA_MCUHEAD_LEN);
}
/**********************************************************************
*
*input: alg_mod: ѡ��ECB ���� CBC
*				crypto_mode: �ӽ��ܱ�ʶ
***********************************************************************/
unsigned char *alg_header(unsigned char *alg_header, unsigned int pkg_index,\
													unsigned int pkg_len, unsigned int alg_mod, \
													unsigned int crypto_mod, unsigned int key_en,\
													unsigned int key_len, unsigned int iv_en, unsigned int iv_len)
{
	unsigned short short_value;
	unsigned char *ptr = (unsigned char *)&short_value;
	unsigned short *short_ptr = (unsigned short *)alg_header;
	ptr[0] = 0xAA;
	ptr[1] = 0x55;
	*short_ptr++ = short_value;
	*short_ptr++ = chgBELE_16((unsigned short)pkg_index);
	*short_ptr++ = chgBELE_16((unsigned short)pkg_len);
    ptr[0] = 0;
    ptr[0] |= alg_mod;
    ptr[0] |= crypto_mod;	//�����ʶ�ڴ˲���
    ptr[1] = 0;
    ptr[1] |= (key_en << 7);
    ptr[1] |= key_len;
	*short_ptr++ = short_value;
    ptr[0] = 0;
    ptr[0] |= (iv_en << 7);
    ptr[0] |= iv_len;
    ptr[1] = 0;							//������-����
	*short_ptr++ = short_value;
	return (alg_header + FPGA_ALGHEAD_LEN);
}

int32_t fpga_set_symkey(uint8_t dst_id, uint16_t key_index, uint8_t *key_buff, uint16_t key_len)
{
	FPGAHeader fpga_header;
	uint8_t *data_ptr;
	
	if (dst_id != FPGA_DATA_SM3 && dst_id != FPGA_DATA_SM4 && dst_id != FPGA_DATA_SM1 && dst_id != FPGA_DATA_SM4_1)
	{
		print(PRINT_FPGA,"fpga_set_symkey dst 0x%x\r\n", dst_id);
		return -1;
	}
	if (key_len != 16 && key_len != 32)
	{
		print(PRINT_FPGA,"fpga_set_symkey key_len %d\r\n", key_len);
		return -2;
	}
	//�鿴SM3�㷨  
	if((ArgFlag&0x08) == 0 && dst_id == FPGA_DATA_SM3){
		return 0; //δʹ�� ����
	}
	//�鿴SM1�㷨
	if((ArgFlag&0x04) == 0 && dst_id == FPGA_DATA_SM1){
		return 0; //δʹ�� ����
	}
	//�鿴SM4�㷨
	if((ArgFlag&0x10) == 0 && dst_id == FPGA_DATA_SM4){
		return 0; //δʹ�� ����
	}
		//�鿴SM4������>16
//if(!HSMD1)
//	if((ArgFlag&0x20) == 0 && dst_id == FPGA_DATA_SM4_1){
//		return 0; //δʹ�� ����
//	}
	memset(&fpga_header, 0, sizeof(FPGAHeader));
	fpga_header.mark = FPGA_HEAD_MARK;
	fpga_header.src = FPGA_DATA_ARM;
	fpga_header.dst = dst_id;
	fpga_header.channel = FPGA_CHANNEL_DEF;
	fpga_header.pkglen = FPGA_DATAHEAD_LEN + key_len;
	fpga_header.retpkglen = 0;
	fpga_header.sm2_cmd = CMD_SM2_SETKEY;   //SM1 PORT  �����ò�ͬ�Ĳ�������
	fpga_header.keytype = KEY_TYPE_SETKEY;  //SM4 PORT  �����ò�ͬ�Ĳ�������
	fpga_header.keyindex = key_index;
	
	if(fpga_write_start()==REG_REST) return ERR_COMM_OUTTIME;
	data_ptr = set_fpga_header((uint8_t *)FPGA_DATA_WRITE_ADDR, &fpga_header);
	memcpy(data_ptr, key_buff, key_len);
	data_ptr += key_len;
	fpga_write_finish(fpga_header.pkglen);
	return 0;
}

#if 0
//-----FPGA �̼���д����GPIO-----//
#define	FPGA_INITB			63
#define	FPGA_SCK			61
#define	FPGA_DAT			36
#define	FPGA_PRO			35
#define	FPGA_DONE			59

static const uint8_t GPIO_INPUT = 0;
static const uint8_t GPIO_OUTPUT = 1;

void fpga_init(void)
{
	gpio_config(FPGA_PRO, GPIO_OUTPUT);
	gpio_config(FPGA_INITB,GPIO_INPUT);
	gpio_config(FPGA_SCK, GPIO_OUTPUT);
	gpio_config(FPGA_DAT, GPIO_OUTPUT);
	gpio_config(FPGA_PRO, GPIO_OUTPUT);
	gpio_config(FPGA_DONE, GPIO_INPUT);
}

/************fpga program function****************
*MCU ͨ��download���нӿ�ΪFPGA���س���
*************************************************/
uint8_t fpga_pro_start(void)
{
	uint8_t error=0;
	uint32_t errorcount=0;
	gpio_clr(FPGA_PRO);
	
	while(gpio_state(FPGA_INITB)){	//�ȴ�initb������
		printfS("�ȴ�INITB������\r\r\n");
		errorcount++;
		if(errorcount>500000){
			error=1;
			printfS("INITB�źŵȴ����ͳ�ʱ��INITB����״̬Ϊ%d\r\n" \
			,REG_GPIO_IDATA(GPIOB)>>(FPGA_INITB-32)&0x01);
			return error;
		}
	}
	errorcount=0;
	printfS("INITB������\r\n");
	delay_ms(1);
	gpio_set(FPGA_PRO);
	while(!gpio_state(FPGA_INITB)){	//�ȴ�initb������
		printfS("�ȴ�INITB������\r\n");
		errorcount++;
		if(errorcount>500000){
			error=2;
			printfS("INITB�źŵȴ����߳�ʱ��INITB����״̬Ϊ%d\r\n" \
			,REG_GPIO_IDATA(GPIOB)>>(FPGA_INITB-32)&0x01);
			return error;
		}
	}
	printfS("INITB������\r\n");
	return error;
}

void fpga_pro_write_byte(uint8_t buff_byte)
{
	uint8_t byte_num=0;
	for(;byte_num<8;byte_num++){
		if(buff_byte&0x80)
			gpio_set(FPGA_DAT);
		else
			gpio_clr(FPGA_DAT);
		gpio_set(FPGA_SCK);
		buff_byte<<=1;
		gpio_clr(FPGA_SCK);
	}
}

void fpga_pro_write(uint8_t * pro_buff,uint16_t length)
{
	uint32_t buff_point=0;
	uint8_t error=0;
	uint32_t errorcount=0;
	for(;buff_point<length;buff_point++)
		fpga_pro_write_byte(*pro_buff++);
	/*while(!gpio_state(FPGA_DONE))	{
		errorcount++;
		if(errorcount>10000){
			error=1;
		}	
	}*/
}

uint8_t fpga_wait_done(uint8_t timeout)
{
	printfS("�ȴ�done �ź�\r\n");
	uint8_t error=0;
	uint32_t errorcount=0;
	while(!gpio_state(FPGA_DONE)){
		errorcount++;
		delay_ms(1);
		if(errorcount>(1000*timeout)){
			error=1;
			break;
		}
	}
	return error;
}
#endif
