#include "user_manage.h"
#include "stdint.h"
#include "fpga_sm3.h"
#include "shamir.h"
#include "FreeRTOS.h"
#include "type_code.h"
#include "string.h"
#include "mcu_algorithm.h"
#include "ukey_oper.h"
#include "fatfs_file.h"
#include "cipher.h"
#include "pwm.h"
#include "SL811.h"
#include "SL811disk.h"
#include "at24cxx.h"
#define UKEYCHECH			500
#define WAITUKEY_TIME		40			//20s֮����UKey�����������¼
#define OUT_READ_USR(res){\
		if(0==res || ERR_UKEY_VOID==res || ERR_UKEY_CONNECT==res || ERR_UKEY_LOCK==res || ERR_UKEY_FILE==res) break;\
		else if(res >= (SAR_PIN_INCORRECT & 0xff) && res <= (SAR_PIN_LEN_RANGE & 0xff)){res = ERR_UKEY_PIN; break;}\
		else if(res == (SAR_FILE_NOT_EXIST & 0xff) || res == (SAR_APPLICATION_NOT_EXISTS & 0xff) || res == (SAR_TIMEOUTERR & 0xff)){res=ERR_UKEY_NOFREE; break;}\
		else res = ERR_UKEY_APP;\
	}    //
#define PRINT_MANA 2
extern xSemaphoreHandle	USBMutexSemaphore;	
extern uint8_t UkeyState;
extern unsigned char null_array[MAINKEY_LEN];		//������
FlashData eFlash;
extern unsigned char main_key[MAINKEY_LEN];			//����Կ
extern unsigned char main_key_mcu[MAINKEY_LEN];	//����Կ����-MCU
//extern unsigned char main_key_ukey[MAINKEY_LEN];	//����Կ����-ukey
extern MCUSelfCheck DevSelfCheck;
extern unsigned char back_key[MAINKEY_LEN];			//������Կ
//extern unsigned char back_key_part[3][MAINKEY_LEN];
USRLOG usr;

uint8_t *main_key_ukey = NULL;
uint8_t *main_key_ukeyTSET = NULL;
//uint8_t admin_num = 0;
extern SM2KeyPair mgtkeypair;  		//�豸������Կ��
extern char pin0_temp[17];
extern uint8_t UkeyStateflag;
//���ݹ���Ա
//uint8_t backkey_part_point[3]={0};
//uint8_t back_key_part[3][48]={0};
uint8_t recover_mainkey[MAINKEY_LEN];//R2
uint8_t recover_backkey_part[2][SHAMIR_PART_LEN(MAINKEY_LEN)];			//������Կ����
uint8_t recover_backkey[MAINKEY_LEN];								//������Կ
uint8_t	recover_usr_index[DEF_ADMIN_TOTAL_NUM]={0};	//���ݹ���Ա��¼��־
uint8_t recover_login_num = 0;
uint8_t recover_iv[MAINKEY_LEN] = {0};
uint16_t recover_key_index = 0;
uint16_t recover_pag_count = 0;

int DevStatusIs(unsigned int  DEV_S){
	if(eFlash.DEV_STATE == DEV_S){
		return 1;  //�豸״̬����
	}else{
		return 1;  // 1:��Ȩ�޿��� 0:��Ȩ�޿���
	}
}
int DevStatusNo(unsigned int  DEV_S){
	if(eFlash.DEV_STATE != DEV_S){
		return 0;  //�豸״̬���� 0
	}else{
		return 0;  // 
	}
}

void Ukey_enum(void)
{
	uint8_t count = 0;
	sl811_os_init();
	//delay_ms(10);
	if(!Slave_Detach()){
			//print(PRINT_COM,"Ukey exist\r\n");
			if(UkeyStateflag){
				while(count < 3){ //ö�ٲ��ɹ�������3��
					if(sl811_disk_init()) count++;
					else break;
				}
			}
	}
//	DevSelfCheck.des |= 0x02;
//	at24cxx_write_bytes(UKEY_DATA_ADDR,(uint8_t*)&DevSelfCheck.des, 4);
}
int add_admin(char *PIN, int PINlen, int ukeyindex)
{
	int ret = 0,retry = 0;
	int i = 0;	
//	uint8_t time_out=0;
	static uint8_t **back_key_part = NULL;
	DeviceStateStr	devstatus;
	devstatus = Get_DevState();//��װ̬�������������Ա
	if(devstatus!= InitialStatus)
		return ERR_DVES_INIT;
	if(memcmp(eFlash.AUTHKEY[ukeyindex],null_array,MAINKEY_LEN)){
		return ERR_MANG_RE_ADD;		//���û����ڣ��޷�������
	}
	if(eFlash.ADMINNUM>=3){
		return ERR_MANG_ADMNUM;    //��������Ա����
	}
	if(!memcmp(main_key_mcu,null_array,MAINKEY_LEN))	//δ��ʼ������Կ
	{
		main_key_ukey = pvPortMalloc(MAINKEY_LEN);	//����Կ����-ukey
 		back_key_part = pvPortMalloc(sizeof(*back_key_part) * DEF_ADMIN_TOTAL_NUM);			//������Կ
		if((main_key_ukey == NULL) || (back_key_part == NULL))
			return 1;
		for (i=0; i<DEF_ADMIN_TOTAL_NUM; i++) {
			back_key_part[i] = pvPortMalloc(SHAMIR_PART_LEN(MAINKEY_LEN));
			memset(back_key_part[i], 0, SHAMIR_PART_LEN(MAINKEY_LEN));
		}
		
		eFlash.ADMINNUM = 0;
		//��������Կ����
		if(get_random_MCU(main_key_mcu,MAINKEY_LEN))
			return ERR_CIPN_RANDOM;
		if(get_random_MCU(main_key_ukey,MAINKEY_LEN))
			return ERR_CIPN_RANDOM;
		
		//�ϳ�����Կ
		for (i=0; i<MAINKEY_LEN; i++) {
			main_key[i] = main_key_mcu[i] ^ main_key_ukey[i];
		}
		//���ɱ�����Կ�������
		if(get_random_MCU(back_key,MAINKEY_LEN))
			return ERR_CIPN_RANDOM;
		shamir_split(back_key, MAINKEY_LEN, DEF_ADMIN_TOTAL_NUM, \
								 DEF_ADMIN_ACCESS_NUM,back_key_part);
	}
	if(get_random_MCU(eFlash.AUTHKEY[ukeyindex],MAINKEY_LEN))
		return ERR_CIPN_RANDOM;		//���������֤��Կ
	
	//��ȡUSBʹ��Ȩ��
	xSemaphoreTake(USBMutexSemaphore,portMAX_DELAY);
	
	if(!UkeyState){
		xSemaphoreGive(USBMutexSemaphore);
		memset(eFlash.AUTHKEY[ukeyindex],0,MAINKEY_LEN);
		return ERR_UKEY_CONNECT;
	}
	do{
		ret = CreateAdminUkey(ukeyindex, PIN, PINlen, main_key_ukey, eFlash.AUTHKEY[ukeyindex],\
												 &(mgtkeypair.pk), back_key_part[ukeyindex],DEF_ADMIN_TOTAL_NUM,DEF_ADMIN_ACCESS_NUM);
		Ukey_ReadFinish();
		if(0 == ret || ERR_UKEY_CONNECT == ret)break;
		if(ERR_UKEY_NOFREE == ret && 0 == retry)break;
		Ukey_enum();
		DeleteApplication();
		delay_ms(10);
	}while(retry++ <10);
	//�ͷ�USBʹ��Ȩ��
	xSemaphoreGive(USBMutexSemaphore);
	if(ret){
		memset(eFlash.AUTHKEY[ukeyindex],0,MAINKEY_LEN);
		return ret;
	}
	++eFlash.ADMINNUM;
	print(PRINT_MANA,"AD_OP_N is %x %x\r\n",eFlash.ADMINNUM,eFlash.OPERNUM);
	if(eFlash.ADMINNUM >= DEF_ADMIN_TOTAL_NUM){		//����Ա���ɽ���
		memcpy(eFlash.MAINKEY_MCU,main_key_mcu,MAINKEY_LEN);	//
		memset(main_key,0,MAINKEY_LEN);
		//write_usr_key(pin0_temp,pin0_temp[16],(uint8_t *)&mgtkeypair,sizeof(SM2KeyPair));
		vPortFree(main_key_ukey);
		main_key_ukey = NULL;
		Update_DevState(ReadyStatus);
		//�������ݵ�eflash 
		WriteFlashData();
	}
	return 0;
}

int add_operator(char *PIN, int PINlen, int ukeyindex)
{
	int ret = 0;
		uint8_t retry=0;
//	uint8_t time_out=0,retry=0;
//	BaseType_t er=pdFALSE;
	DeviceStateStr	devstatus;
	uint8_t mainkey_usr[SM4_KEY_LEN]={0};
	devstatus=Get_DevState();
	if(devstatus!= ManagementStatus){
			return ERR_DVES_OPER;			
	}
	if(memcmp(eFlash.AUTHKEY[ukeyindex],null_array,MAINKEY_LEN)){
		return ERR_MANG_RE_ADD;		//���û����ڣ��޷�������
	}
	if(get_random_MCU(eFlash.AUTHKEY[ukeyindex],MAINKEY_LEN)){		//���������֤��Կ
		memset(eFlash.AUTHKEY[ukeyindex],0,MAINKEY_LEN);
		return ERR_CIPN_RANDOM;
	}
	//��ȡUSBʹ��Ȩ��
	xSemaphoreTake(USBMutexSemaphore,portMAX_DELAY);
	
	if(!UkeyState){
		memset(eFlash.AUTHKEY[ukeyindex],0,MAINKEY_LEN);
		xSemaphoreGive(USBMutexSemaphore);
		return ERR_UKEY_CONNECT;
	}
	//��ԭ����Կ����2
	data_xor(main_key,eFlash.MAINKEY_MCU,mainkey_usr,SM4_KEY_LEN);
	do{
		ret = CreateOperUkey(ukeyindex, PIN, PINlen,mainkey_usr,eFlash.AUTHKEY[ukeyindex]);
		Ukey_ReadFinish();
		if(0 == ret || ERR_UKEY_CONNECT == ret)break;
		if(ERR_UKEY_NOFREE == ret && 0 == retry)break;
		Ukey_enum();
		DeleteApplication();
		delay_ms(10);
	}while(retry++ <10);
	
	//Ukey_ReadFinish();
	//�ͷ�USBʹ��Ȩ��
	xSemaphoreGive(USBMutexSemaphore);
	if (0 != ret) {
		memset(eFlash.AUTHKEY[ukeyindex],0,MAINKEY_LEN);
		return ret;
	}
	eFlash.OPERNUM++;
	print(PRINT_MANA,"AD_OP_N is %d %d\r\n",eFlash.ADMINNUM,eFlash.OPERNUM);
	eFlash.DEV_STATE = ReadyStatus;
	//����eflash���� ��Ӳ���Ա��Ϣ
	WriteFlashData();
	eFlash.DEV_STATE = ManagementStatus;
	return 0;
}

//��ݼ�������
int UserAuthProcess(uint8_t* key_auth,uint8_t UserIndex){
	uint8_t Random[16] = {0};
	uint8_t AuthCode[16] = {0};
//	uint8_t time_out=0;
	if(MCU_Auth_GenRandom( Random,16)){
		return -1;
	}
	
	xSemaphoreTake(USBMutexSemaphore,portMAX_DELAY);
	//ERR_UKEY_CONNECT
	if(!UkeyState){
		xSemaphoreGive(USBMutexSemaphore);
		return ERR_UKEY_CONNECT;
	}
	if(MCU_Auth_GenAuthCode(Random,16,key_auth,AuthCode)){
		xSemaphoreGive(USBMutexSemaphore);
		return -1;
	}
	//�ͷ�USBʹ��Ȩ��
	xSemaphoreGive(USBMutexSemaphore);

	if(MCU_Auth_UkeyAuth(AuthCode,16,UserIndex)){
		return -1;
	}
	return 0;
}

// �û���¼���������̬������̬������̬��ִ�У���״̬�½�֧�ֹ���Ա��¼�ָ�������Կ�����лָ�
//           ����̬�¹���Ա��¼�������̬
//           ����̬�µ�¼Ϊ��ͨ��¼
int UserLogin(uint16_t logusrtype, char *PIN, int PINlen)
{
	//int i;
	int	usr_error=0;
	uint8_t retry=0;
//	uint8_t time_out=0,retry=0;
//	BaseType_t er=pdFALSE;
	char pin_temp[16]={0};
	int shamir_secret_len=MAINKEY_LEN;
	int * secret_len=&shamir_secret_len;
	uint8_t usr_authkey[SM4_KEY_LEN]={0};
	uint8_t mainkey_usr[SM4_KEY_LEN]={0};
	static uint8_t **pback_key_part_login = NULL;
	static uint8_t backkey_usr_part[2][SHAMIR_PART_LEN(MAINKEY_LEN)]={0};
	
//	DeviceStateStr	devstatus;
//	devstatus = Get_DevState();
	memset(pin_temp,0,16);
	memcpy(pin_temp,PIN,PINlen);
	if(0==strlen(pin_temp)||0==PINlen) return ERR_MANG_PINLEN;
	//��ȡUSBʹ��Ȩ��
	xSemaphoreTake(USBMutexSemaphore,portMAX_DELAY);
	if(!UkeyState){
		xSemaphoreGive(USBMutexSemaphore);
		return ERR_UKEY_CONNECT;
	}
	do{
		usr_error=readUserData(&usr.index, pin_temp, PINlen, mainkey_usr, \
							usr_authkey, backkey_usr_part[usr.adm_login_num],NULL,NULL);		//�õ����ĵ�����
		//print(PRINT_MANA,"usr_error is %d\r\n",usr_error);
		OUT_READ_USR(usr_error);
		Ukey_enum();
		delay_ms(10);
	}while(retry++ <5);
	
	Ukey_ReadFinish();
	//�ͷ�USBʹ��Ȩ��
	xSemaphoreGive(USBMutexSemaphore);
	if(usr_error!=0)
		return usr_error;
	
	//�ָ�������Կ	
	data_xor(mainkey_usr,eFlash.MAINKEY_MCU,main_key,SM4_KEY_LEN);
	
	//����
#ifdef DG
	//memcpy(eFlash.AUTHKEY[9],main_key,SM4_KEY_LEN);
	//WriteFlashData();
#endif
	//����Ա��¼
	if(usr.index< DEF_ADMIN_TOTAL_NUM){
		if(logusrtype != 0){
			return ERR_UKEY_KIND;
		}
		if(memcmp((const char *)eFlash.AUTHKEY[usr.index],null_array,MAINKEY_LEN) == 0)
			return ERR_MANG_ERROR_USR;	//�޴˹���Ա
		//if(memcmp(usr_authkey,eFlash.AUTHKEY[usr.index], MAINKEY_LEN))
		if(UserAuthProcess(usr_authkey,usr.index))
			return ERR_MANG_AUTHUSR;			//�����֤��Կ��֤��ͨ��ASD 
		usr.usr_type = AdminLogging;
		if(usr.admin_index[usr.index] != 0)
	 	 return ERR_MANG_RELOGIN;
		usr.admin_index[usr.index]=1;
		if(++usr.adm_login_num >= DEF_ADMIN_ACCESS_NUM){
			//main_key_ukeyTSET = pvPortMalloc(MAINKEY_LEN);	
			//�ָ�������Կ
			usr.usr_type = Admin;
			//�ָ�������Կ
			pback_key_part_login = pvPortMalloc(sizeof(*pback_key_part_login) * DEF_ADMIN_TOTAL_NUM);
			pback_key_part_login[0] = backkey_usr_part[0];
			pback_key_part_login[1] = backkey_usr_part[1];
			shamir_combine(pback_key_part_login, DEF_ADMIN_ACCESS_NUM, back_key,secret_len);
			eFlash.DEV_STATE = ManagementStatus;
			*(unsigned short *)FPGA_MCU_DRIVER_WRITE = (0x0001<<(eFlash.DEV_STATE));
			loadusrkey();
			led_display(LED_1,HZ_2,LED_BL);//��¼�ɹ��̵ƿ���˸
			vPortFree(pback_key_part_login);
			pback_key_part_login = NULL;
		}
	}
	//����Ա��¼
	else{
		if(logusrtype != 1){
			return ERR_UKEY_KIND;
		}
		//if(usr_status.usr_type)
		if(memcmp(eFlash.AUTHKEY[usr.index],null_array,MAINKEY_LEN) == 0)
			return ERR_MANG_ERROR_USR	;	//�˲���Աδע��
		if(UserAuthProcess(usr_authkey,usr.index))
			return ERR_MANG_AUTHUSR;
		usr.usr_type = Operator;
		usr.adm_login_num = 0;
		eFlash.DEV_STATE =WorkStatus;
		*(unsigned short *)FPGA_MCU_DRIVER_WRITE = (0x0001<<(eFlash.DEV_STATE));
		loadusrkey();
		led_display(LED_1,HZ_05,LED_BL);//��¼�ɹ��̵�����˸
	}
	return 0;
}

//�û��ǳ�
int UserLogout(void)
{
//	int rtval;
	usr.usr_type=NoUser;
	usr.adm_login_num=0;
	usr.index=0;
	memset(&usr.admin_index,0,DEF_ADMIN_TOTAL_NUM);
	clear_userkey_logout();
	if(main_key_ukey){
		vPortFree(main_key_ukey);
		main_key_ukey = NULL;
	}
	led_display(LED_1,HZ_1,LED_ON);//�˳��ɹ��̵Ƴ���
	return 0;
}

/*ɾ������  0x102B
int ResetPWD(uint8_t usr_index,unsigned char * psw,uint8_t psw_len)
{
	//����Ukey������
}*/

int DelUsr(uint8_t usr_index)
{
	uint32_t temp = eFlash.DEV_STATE;
	DeviceStateStr	devstatus;
	devstatus=Get_DevState();
	
	if(devstatus!= ManagementStatus)	//����̬�������������Ա	
		return ERR_DVES_OPER ;
	
	if((usr_index < DEF_ADMIN_TOTAL_NUM))//&&(usr_index >= DEF_ADMIN_TOTAL_NUM))
		return ERR_MANG_DEL_ADMIN;
	if(usr_index >= DEF_OPERATOR_NUM_MAX)
		return ERR_MANG_ERROR_USR;
	
	if(memcmp((const char *)eFlash.AUTHKEY[usr_index],null_array,MAINKEY_LEN) == 0)
			return ERR_MANG_ERROR_USR;	//�޴��û�
	if((eFlash.OPERNUM) > 0){
		eFlash.OPERNUM--;
	}
	memset(eFlash.AUTHKEY[usr_index],0,MAINKEY_LEN);
	eFlash.DEV_STATE = ReadyStatus;
	WriteFlashData();
	eFlash.DEV_STATE = temp;
	return 0;
}
int ResetOperatorPWD(uint16_t new_pwd_len,uint16_t index,char * new_pwd)
{
	uint16_t ret = 0;
//	uint8_t time_out=0;
	//��ȡUSBʹ��Ȩ��
	xSemaphoreTake(USBMutexSemaphore,portMAX_DELAY);
	if(!UkeyState){
		xSemaphoreGive(USBMutexSemaphore);
		return ERR_UKEY_CONNECT;
	}
	//ʹ��UKEY����������Ukey���� ��Ҫ���ڹ���̬
	ret = ResetUserPin(index, new_pwd, new_pwd_len, &eFlash);
	Ukey_ReadFinish();
		//�ͷ�USBʹ��Ȩ��
	xSemaphoreGive(USBMutexSemaphore);
	return ret;
}

int ChangePWD(uint16_t old_len,char *pwd_old,uint16_t new_len,char *pwd_new)
{

	uint16_t ret = 0;
	char pin_tempold[16]={0};
	char pin_tempnew[16]={0};
//	uint8_t time_out=0;

	//��ȡUSBʹ��Ȩ��
	memset(pin_tempold,0,16);
	memcpy(pin_tempold,pwd_old,old_len);
	memset(pin_tempnew,0,16);
	memcpy(pin_tempnew,pwd_new,new_len);
	if(0==strlen(pin_tempold)||0==old_len||0==strlen(pin_tempnew)||0==new_len) return ERR_MANG_PINLEN;
	xSemaphoreTake(USBMutexSemaphore,portMAX_DELAY);
	if(!UkeyState){
		xSemaphoreGive(USBMutexSemaphore);
		return ERR_UKEY_CONNECT;
	}
	//Ukey���Ŀ���
	ret = ChangeUserPin(usr.index,old_len,pin_tempold,new_len,pin_tempnew,&eFlash);
	Ukey_ReadFinish();
		//�ͷ�USBʹ��Ȩ��
	xSemaphoreGive(USBMutexSemaphore);
	return ret;
}

int ChangePWDOper(uint16_t old_len,char *pwd_old,uint16_t new_len,char *pwd_new)
{
	uint16_t ret = 0;
	char pin_tempold[16]={0};
	char pin_tempnew[16]={0};
	//��ȡUSBʹ��Ȩ��
	memset(pin_tempold,0,16);
	memcpy(pin_tempold,pwd_old,old_len);
	memset(pin_tempnew,0,16);
	memcpy(pin_tempnew,pwd_new,new_len);
	if(0==strlen(pin_tempold)||0==old_len||0==strlen(pin_tempnew)||0==new_len) return ERR_MANG_PINLEN;
	
	xSemaphoreTake(USBMutexSemaphore,portMAX_DELAY);
	if(!UkeyState){
		xSemaphoreGive(USBMutexSemaphore);
		return ERR_UKEY_CONNECT;
	}
	//Ukey���Ŀ���
	ret = ChangeUserPin(usr.index,old_len,pin_tempold,new_len,pin_tempnew,&eFlash);
	Ukey_ReadFinish();
		//�ͷ�USBʹ��Ȩ��
	xSemaphoreGive(USBMutexSemaphore);
	return ret;
}

//ֱ�����Ukey
int CleanUkey(void){
 
 int usr_error=0;
// uint8_t time_out=0;
 //��ȡUSBʹ��Ȩ��
 xSemaphoreTake(USBMutexSemaphore,portMAX_DELAY);
 //ɾ��Ӧ��
 usr_error = DeleteApplication();
if(usr_error){
	xSemaphoreGive(USBMutexSemaphore);
	return usr_error;
}
//�ͷ�USBʹ��Ȩ��
 xSemaphoreGive(USBMutexSemaphore);
 return 0;
}


int CleanUkeyWithPin(uint16_t pinlen,char* pin){
 
 uint8_t usrindex=0,retry=0;
 int usr_error=0;
 char pin_temp[16]={0};
 uint8_t usr_authkey[SM4_KEY_LEN]={0};
 uint8_t mainkey_usr[SM4_KEY_LEN]={0};
 uint8_t backkey_usr_part[SHAMIR_PART_LEN(MAINKEY_LEN)]={0};
 
 //uint8_t time_out=0;
 //��ȡUSBʹ��Ȩ��
  memset(pin_temp,0,16);
  memcpy(pin_temp,pin,pinlen);
  if(0==strlen(pin_temp)||0==pinlen) return ERR_MANG_PINLEN;
 xSemaphoreTake(USBMutexSemaphore,portMAX_DELAY);
// while(!UkeyState)
// {
//  vTaskDelay(500);
//  time_out++;
//  if(time_out > WAITUKEY_TIME){
 //  time_out = 0;
//   xSemaphoreGive(USBMutexSemaphore);   
//  return ERR_UKEY_TIMEOUT;
//  }
// }
	if(!UkeyState){
		xSemaphoreGive(USBMutexSemaphore);
		return ERR_UKEY_CONNECT;
}

	do{
		usr_error=readUserData(&usrindex, pin_temp, pinlen, mainkey_usr, \
				usr_authkey, backkey_usr_part,NULL,NULL);  //�õ�����usr_authkey����
		OUT_READ_USR(usr_error);
		Ukey_enum();
		delay_ms(10);
	}while(retry++ <5);

 if(usr_error)
 {
	  xSemaphoreGive(USBMutexSemaphore);
		return usr_error;
 }
 if(usrindex > 9){
		xSemaphoreGive(USBMutexSemaphore);
		return ERR_MANG_AUTHUSR;
 }

 if(memcmp(usr_authkey,eFlash.AUTHKEY[usrindex], MAINKEY_LEN)){
	xSemaphoreGive(USBMutexSemaphore); 
  return ERR_MANG_AUTHUSR;   //�����֤��Կ��֤��ͨ��
 }
 //ɾ��Ӧ��
 usr_error = DeleteApplication();
if(usr_error){
	xSemaphoreGive(USBMutexSemaphore);
	return usr_error;
}
//�ͷ�USBʹ��Ȩ��
 xSemaphoreGive(USBMutexSemaphore);
 if(usrindex<DEF_ADMIN_TOTAL_NUM&&(eFlash.ADMINNUM)){
   --eFlash.ADMINNUM;
 }else{
  if(eFlash.OPERNUM > 0){
   eFlash.OPERNUM--;
  }
 }
 print(PRINT_MANA,"AD_OP_N is %d %d\r\n",eFlash.ADMINNUM,eFlash.OPERNUM);
 memset(eFlash.AUTHKEY[usrindex],0,MAINKEY_LEN);
 //��֤flash�д洢Ϊ����̬
 usr_error = eFlash.DEV_STATE;
 eFlash.DEV_STATE = ReadyStatus;
 //����eflash���� ��Ӳ���Ա��Ϣ
 WriteFlashData();
 eFlash.DEV_STATE = usr_error;
 return 0;
}

uint8_t *set_backup_data(uint8_t *sdt,uint8_t *data,uint8_t len)
{
	memcpy(sdt,data,len);
	return sdt + len;
}
uint8_t *get_backup_data(uint8_t *sdt,uint8_t * data, uint8_t len)
{
	memcpy(sdt,data,len);
	return data+len;
}

int BackUpAdminInfo(uint8_t *backupdata)
{
	uint16_t pagtail= 0XFF99;
	FlashData *pFD = (FlashData *)backupdata;
	memcpy(backupdata,(uint8_t *)&eFlash,sizeof(FlashData));
		//��ԭ����Կ����2
	data_xor(main_key,eFlash.MAINKEY_MCU,pFD->MAINKEY_MCU,SM4_KEY_LEN);//R2-�������ʶ
	//���ݣ�0XFFF0-Admin 0XFFF1-Opera 0XFFF2-�û���Կ 0XFFF3-KEK 0XFFF4-�û���Կ��KEK
	pFD->DATA_STATUS = 0XFFF0;    //����ͷ
	memcpy(backupdata+sizeof(FlashData)-2,(uint8_t *)&pagtail,2);	//����β
	return 0;
}
int BackUpOperaInfo(uint8_t *backupdata)
{
	uint16_t pagtail= 0XFF99;
	FlashData *pFD = (FlashData *)backupdata;
	memcpy(backupdata,(uint8_t *)&eFlash,sizeof(FlashData));
	//��ԭ����Կ����2
	data_xor(main_key,eFlash.MAINKEY_MCU,pFD->MAINKEY_MCU,SM4_KEY_LEN);
	//���ݣ�0XFFF0-Admin 0XFFF1-Opera 0XFFF2-�û���Կ 0XFFF3-KEK 0XFFF4-�û���Կ��KEK
	pFD->DATA_STATUS = 0XFFF1;    //����ͷ
	memcpy(backupdata+sizeof(FlashData)-2,(uint8_t *)&pagtail,2);	//����β
	return 0;
}
int RecoverAdminInfo(uint8_t *backupdata)
{
	uint16_t pagtail = 0XFF99;
	FlashData *pFD = (FlashData *)backupdata;
	if(recover_login_num < 2){
		return ERR_MANG_BACKAUTH;
	}
	if(pFD->DATA_STATUS != 0XFFF0 || memcmp(backupdata+sizeof(FlashData)-2,(uint8_t *)&pagtail,2)){
		return ERR_MANG_RECOVER_LEN;
	}
	memcpy(eFlash.AUTHKEY[0],pFD->AUTHKEY[0],MAINKEY_LEN*DEF_ADMIN_TOTAL_NUM);
	eFlash.ADMINNUM = pFD->ADMINNUM;
 print(PRINT_MANA,"AD_OP_N is %d %d\r\n",eFlash.ADMINNUM,eFlash.OPERNUM);
	if(get_random_MCU(eFlash.MAINKEY_MCU,MAINKEY_LEN))//��������Կ����R1
		return ERR_CIPN_RANDOM;
	eFlash.DEV_STATE = ReadyStatus;
	//����eflash���� ��Ӳ���Ա��Ϣ
	WriteFlashData();
	//�����豸״̬�Ĵ���
	*(unsigned short *)FPGA_MCU_DRIVER_WRITE = (0x0001<<(eFlash.DEV_STATE));
	return 0;
}
int RecoverOperaInfo(uint8_t *backupdata)
{
	uint16_t pagtail= 0XFF99;
	unsigned char tmpR2[MAINKEY_LEN];
	if((eFlash.OPERNUM) != 0){
		return ERR_DVES_INIT_BACKUP;
	}
	FlashData *pFD = (FlashData *)backupdata;
	if(pFD->DATA_STATUS != 0XFFF1 || memcmp(backupdata+sizeof(FlashData)-2,(uint8_t *)&pagtail,2)){
		return ERR_MANG_RECOVER_LEN;
	}
	data_xor(main_key,eFlash.MAINKEY_MCU,tmpR2,SM4_KEY_LEN);
	if(memcmp(tmpR2,pFD->MAINKEY_MCU,MAINKEY_LEN)){
		return ERR_MANG_BACKLOGIN;
	}
	memcpy(eFlash.AUTHKEY[DEF_ADMIN_TOTAL_NUM],pFD->AUTHKEY[DEF_ADMIN_TOTAL_NUM],
				 MAINKEY_LEN*(DEF_OPERATOR_NUM_MAX-DEF_ADMIN_TOTAL_NUM));
	eFlash.OPERNUM = pFD->OPERNUM;
 print(PRINT_MANA,"AD_OP_N is %d %d\r\n",eFlash.ADMINNUM,eFlash.OPERNUM);
	eFlash.DEV_STATE = ReadyStatus;
	//����eflash���� ��Ӳ���Ա��Ϣ
	WriteFlashData();
	eFlash.DEV_STATE = ManagementStatus;
	return 0;
}
int BackUpAdminLogin(uint16_t pinlen,uint8_t *pin)
{
	int	usr_error=0;
	int len=0;
	uint8_t usr_index=0,retry=0;
	uint8_t usr_authkey[SM4_KEY_LEN]={0};
	uint8_t recover_mainkey_R2[SM4_KEY_LEN]={0};
	static uint8_t **pback_key_part_login_ex=NULL;
	char pin_temp[32] = {0};
	len=MAINKEY_LEN;

	memset(pin_temp,0,16);
	memcpy(pin_temp,pin,pinlen);
	if(0==strlen(pin_temp)||0==pinlen) return ERR_MANG_PINLEN;
	if(recover_login_num >= 2){
		return ERR_MANG_RELOGIN;
	}
		xSemaphoreTake(USBMutexSemaphore,portMAX_DELAY);
	if(!UkeyState){
		xSemaphoreGive(USBMutexSemaphore);
		return ERR_UKEY_CONNECT;
	}
	do{
		usr_error=readUserData(&usr_index, pin_temp, pinlen,recover_mainkey_R2, \
							usr_authkey, recover_backkey_part[recover_login_num],NULL,NULL);		//�õ����ĵ�����
		OUT_READ_USR(usr_error);
		Ukey_enum();
		delay_ms(10);
	}while(retry++ <5);

	
	xSemaphoreGive(USBMutexSemaphore);
	if(usr_error){
		return usr_error;
	}
	if(usr_index >= DEF_ADMIN_TOTAL_NUM)
		return ERR_UKEY_KIND;		//�ǹ���ԱUkey
	if(recover_usr_index[usr_index] == 0){
		recover_usr_index[usr_index]=1;
	}else{
		return ERR_MANG_RELOGIN;		// ����ԱUkey�ظ���¼
	}
	if(recover_login_num == 0){   // ��¼�׸����ݹ���Ա
		memcpy(recover_mainkey,recover_mainkey_R2,MAINKEY_LEN);
	}else{//���׸����ݹ���Ա
		if(memcmp(recover_mainkey,recover_mainkey_R2,MAINKEY_LEN)){
			recover_usr_index[usr_index]=0;
			return ERR_MANG_BACKLOGIN; //���׸��ڲ�ͬ������
		}
	}
	recover_login_num++;
	if(recover_login_num >= DEF_ADMIN_ACCESS_NUM){
		pback_key_part_login_ex = pvPortMalloc(sizeof(*pback_key_part_login_ex) * DEF_ADMIN_TOTAL_NUM);
		pback_key_part_login_ex[0] = recover_backkey_part[0];
		pback_key_part_login_ex[1] = recover_backkey_part[1];
		shamir_combine(pback_key_part_login_ex,DEF_ADMIN_ACCESS_NUM,recover_backkey, &len);
		vPortFree(pback_key_part_login_ex);
		pback_key_part_login_ex = NULL;
	}
	return 0;
}
uint8_t rec4Kbuff[4096]={0};
uint16_t rec4kbufflen = 0;
//���ݣ�0XFFF0-Admin 0XFFF1-Opera 0XFFF2-�û���Կ 0XFFF3-KEK 0XFFF4-�û���Կ��KEK
int BackUpUserkey(uint8_t *backupdata,uint32_t *gflag,uint16_t *gpagcount){
	uint16_t paghead= 0XFFF2;
	uint8_t *pbud = backupdata;
	uint8_t *pindex = NULL;
	uint32_t AllLen,index_i,rtval;
	if(*gflag != 1){
		goto NoFirst;
	}
	recover_key_index = 0;

	if(backupdata == NULL){ //����ȡ�����ܳ��ȺͰ���
		pbud = rec4Kbuff;
		//��ѯ��Կ����Ŀ
		rtval = Get_Cipher_Num(pbud);
		if(rtval){
			return rtval;
		}
		//8 + SM4_KEY_LEN+SM2_KEYPAIR_NUM+RSA_KEYPAIR_NUM+KEK_NUM --> 2048
		AllLen = 2048+2*3072+ 2*(*(uint16_t*)(pbud)) * sizeof(SM2KeyPair)+   \
						 2*(*(uint16_t*)(pbud+2)+*(uint16_t*)(pbud+4)) * 1408;
		
		*gflag = AllLen;
		//21-->2048/sizeof(SM2KeyPair)  2-->2048/1408
		*gpagcount = (2*(*(uint16_t*)(pbud))+21)/22 + 1 + 2+ \
								 (2*(*(uint16_t*)(pbud+2)+*(uint16_t*)(pbud+4))+1)/2;
		return 0;
	}
	memcpy(pbud,(uint8_t *)&paghead,2);pbud+=2;//����ͷ
	memcpy(pbud,(uint8_t *)&AllLen,4);pbud+=4;//���ݳ���
	//��ԭ����Կ����2
	data_xor(main_key,eFlash.MAINKEY_MCU,pbud,SM4_KEY_LEN); pbud+=SM4_KEY_LEN;//R2
	//memset(pbud,0,256+64+256);//SM2+RSA+KEK
	//��ȡSM2+RSA��ʶ
	memcpy(pbud,(uint8_t *)SM2_KEYPAIR_INFO_ADDR,SM2_KEYPAIR_NUM*2+2);
	pbud+=SM2_KEYPAIR_NUM*2+2;
	memcpy(pbud,(uint8_t *)RSA_KEYPAIR_INFO_ADDR,RSA_KEYPAIR_NUM*2+2);
	pbud+=RSA_KEYPAIR_NUM*2+2;
	//memcpy(pbud,"0XFF99",2);	//����β
	*gflag = 2048;
	return 0;
NoFirst:
	if(*gflag == 2){  //2,3��Ϊ˽Կ���ʿ�����
		for(index_i=1;index_i<=150;index_i++){
			if(read_cipher_access(index_i,&pbud[20*index_i],(char*)&pbud[20*index_i+2])){
				continue;
			}
		}
		*gflag = 3072;
		return 0;
	}
	if(*gflag == 3){  //2,3��Ϊ˽Կ���ʿ�����
		for(index_i=151;index_i<=SM2_KEYPAIR_NUM+RSA_KEYPAIR_NUM;index_i++){
			if(read_cipher_access(index_i,&pbud[20*(index_i-150)],(char*)&pbud[20*(index_i-150)+2])){
				continue;
			}
		}
		*gflag = 3072;
		return 0;
	}
	recover_key_index+=1;
	pindex = (uint8_t *)SM2_KEYPAIR_INFO_ADDR;
	for(index_i=recover_key_index;index_i<=SM2_KEYPAIR_NUM*2+1;index_i++)
	{
		if(pindex[index_i] == USER_KEYTYPE_SM2){
			 memcpy(pbud,(uint8_t *)(SM2_KEYPAIR_DATA_ADDR+index_i*SM2_KEYPAIR_LEN),SM2_KEYPAIR_LEN);
			 pbud+=SM2_KEYPAIR_LEN;
			 *gflag = pbud-backupdata;
			 if((pbud-backupdata)>=2048){
				 //*gflag = pbud-backupdata;
				 recover_key_index = index_i;
				 return 0;
			 }
		}
		if(index_i == SM2_KEYPAIR_NUM*2+1){
			 recover_key_index = index_i;
			 *gflag = pbud-backupdata;
			if(*gflag>0){
				return 0;
			}
			recover_key_index++;
		}
	}
	pindex = (uint8_t *)RSA_KEYPAIR_INFO_ADDR;
	if(recover_key_index >= SM2_KEYPAIR_NUM*2+2){
		for(index_i=recover_key_index-SM2_KEYPAIR_NUM*2-2;index_i<=RSA_KEYPAIR_NUM*2+1;index_i++)
		{

			if(index_i == RSA_KEYPAIR_NUM*2+1){
				 *gpagcount = 0XFF99;//	β��
			}
			if(pindex[index_i] == USER_KEYTYPE_RSA1024 || pindex[index_i] == USER_KEYTYPE_RSA2048){
				 memcpy(pbud,(uint8_t *)(RSA_KEYPAIR_DATA_ADDR+index_i*RSA2048_BUFFLEN),RSA2048_BUFFLEN);
				 pbud+=RSA2048_BUFFLEN;
				 *gflag = pbud-backupdata;
				 if((pbud-backupdata)>2048){
					 //*gflag = pbud-backupdata;
					 recover_key_index = index_i+SM2_KEYPAIR_NUM*2+2;
					 return 0;
				 }
			}
		}
	}
	return 0;	
}
int RecoverUserkey(uint8_t *backupdata,uint32_t datalen,uint16_t gpagcount){
	uint8_t *pbud = rec4Kbuff;
	uint8_t *pindex = NULL;
	uint8_t *pbackupdata = backupdata;
	static uint8_t *pusrpin = NULL;
	uint32_t AllLen,index_i,rtval;
	if(gpagcount != 1){
		goto NOFirst;
	}
	//��ѯ��Կ����Ŀ
	rtval = Get_Cipher_Num(pbud);
	if(rtval){
		return rtval;
	}
	if((uint16_t)*(pbud)+(uint16_t)*(pbud+2)+(uint16_t)*(pbud+4) != 0){
		return ERR_CIPN_USRKEYEXIT;
	}
	if(pusrpin == NULL){
		pusrpin = pvPortMalloc(2*3072);
	}
	//pusrpin = pvPortMalloc(2*3072);
	memset(pusrpin,0,2*3072);
	recover_key_index = 0;
	memset(rec4Kbuff,0,4096);
	rec4kbufflen = 0;
	memcpy(rec4Kbuff,backupdata,datalen);
	rec4kbufflen = datalen;
	if(datalen < 2048){
		return 0;
	}
	if(*(uint16_t*)rec4Kbuff != 0XFFF2){
		vPortFree(pusrpin);
		pusrpin = NULL;
		return ERR_MANG_RECOVER_LEN;
	}
	pbud += 6; //keytype(2)+datalen(4)
	pbud += 16; //R2
	memcpy((uint8_t *)SM2_KEYPAIR_INFO_ADDR,pbud,SM2_KEYPAIR_NUM*2+2);
	pbud+=SM2_KEYPAIR_NUM*2+2;
	memcpy((uint8_t *)RSA_KEYPAIR_INFO_ADDR,pbud,RSA_KEYPAIR_NUM*2+2);
	//pbud+=RSA_KEYPAIR_NUM*2+2;
	//memcpy((uint8_t *)KEK_INFO_ADDR,pbud,KEK_NUM+1);
	memcpy(rec4Kbuff,rec4Kbuff+2048,2048);
	rec4kbufflen -= 2048;
	
	recover_key_index = 0X1FFF;
	pbud = rec4Kbuff;
	datalen = 0;
NOFirst:
	if(rec4kbufflen+datalen<=4096){ //
		memcpy(rec4Kbuff+rec4kbufflen,backupdata,datalen);
		rec4kbufflen += datalen;
		datalen = 0;
	}else{
		memcpy(rec4Kbuff+rec4kbufflen,backupdata,4096-rec4kbufflen);
		datalen = rec4kbufflen+datalen-4096;
		pbackupdata += 4096-rec4kbufflen;
		rec4kbufflen = 4096;

	}
	if(recover_key_index == 0){		
		if(rec4kbufflen < 2048){
			return 0;
		}
		if(*(uint16_t*)rec4Kbuff != 0XFFF2){
			vPortFree(pusrpin);
			pusrpin = NULL;
			return ERR_MANG_RECOVER_LEN;
		}
		pbud += 6; //keytype(2)+datalen(4)
		pbud += 16; //R2
		memcpy((uint8_t *)SM2_KEYPAIR_INFO_ADDR,pbud,SM2_KEYPAIR_NUM*2+2);
		pbud+=SM2_KEYPAIR_NUM*2+2;
		memcpy((uint8_t *)RSA_KEYPAIR_INFO_ADDR,pbud,RSA_KEYPAIR_NUM*2+2);
		//pbud+=RSA_KEYPAIR_NUM*2+2;
		//memcpy((uint8_t *)KEK_INFO_ADDR,pbud,KEK_NUM+1);
		memcpy(rec4Kbuff,rec4Kbuff+2048,2048);
		rec4kbufflen -= 2048;
		//���ʣ�����ݵ�����buff
		memcpy(rec4Kbuff+rec4kbufflen,backupdata,datalen);
		rec4kbufflen += datalen;
		datalen = 0;
		recover_key_index = 0X1FFF;
		pbud = rec4Kbuff;
	}
	
	//��ȡ��1��˽Կ������
	if(recover_key_index == 0X1FFF){
		if(rec4kbufflen < 3072){
			memcpy(rec4Kbuff+rec4kbufflen,pbackupdata,datalen);
			rec4kbufflen += datalen;
			datalen = 0;
			return 0;
		}
		memcpy(pusrpin,rec4Kbuff,3072);
		rec4kbufflen -= 3072;
		memcpy(rec4Kbuff,rec4Kbuff+3072,rec4kbufflen);
		recover_key_index = 0X2FFF;
	}
	//��ȡ��2��˽Կ������
	if(recover_key_index == 0X2FFF){
		if(rec4kbufflen < 3072){
			memcpy(rec4Kbuff+rec4kbufflen,pbackupdata,datalen);
			rec4kbufflen += datalen;
			datalen = 0;
			return 0;
		}
		memcpy(pusrpin+3072,rec4Kbuff,3072);
		rec4kbufflen -= 3072;
		memcpy(rec4Kbuff,rec4Kbuff+3072,rec4kbufflen);
		recover_key_index = 1;
	}
	
	pindex = (uint8_t *)SM2_KEYPAIR_INFO_ADDR;
	for(index_i=recover_key_index;index_i<=SM2_KEYPAIR_NUM*2+1;index_i++)
	{
		if(rec4kbufflen < SM2_KEYPAIR_LEN){
			memcpy(rec4Kbuff,pbud,rec4kbufflen);
			memcpy(rec4Kbuff+rec4kbufflen,pbackupdata,datalen);
			rec4kbufflen += datalen;
			datalen = 0;
			pbud = rec4Kbuff;
			if(rec4kbufflen < SM2_KEYPAIR_LEN && gpagcount != recover_pag_count){
				recover_key_index = index_i;
				return 0;
			}
		}
		if(pindex[index_i] == USER_KEYTYPE_SM2){
			memcpy((uint8_t *)(SM2_KEYPAIR_DATA_ADDR+index_i*SM2_KEYPAIR_LEN),pbud,SM2_KEYPAIR_LEN);
			pbud+=SM2_KEYPAIR_LEN;
			rec4kbufflen-=SM2_KEYPAIR_LEN;
		}
		if(index_i == SM2_KEYPAIR_NUM*2+1){
			recover_key_index=SM2_KEYPAIR_NUM*2+2;
		}
	}
	pindex = (uint8_t *)RSA_KEYPAIR_INFO_ADDR;
	if(recover_key_index >= SM2_KEYPAIR_NUM*2+2){
		for(index_i=recover_key_index-SM2_KEYPAIR_NUM*2-2;index_i<=RSA_KEYPAIR_NUM*2+1;index_i++)
		{
			if(rec4kbufflen < RSA2048_BUFFLEN){
				memcpy(rec4Kbuff,pbud,rec4kbufflen);
				memcpy(rec4Kbuff+rec4kbufflen,pbackupdata,datalen);
				rec4kbufflen += datalen;
				datalen = 0;
				pbud = rec4Kbuff;
				if(rec4kbufflen < RSA2048_BUFFLEN && gpagcount != recover_pag_count){
					recover_key_index = index_i+SM2_KEYPAIR_NUM*2+2;
					return 0;
				}

			}
			if(pindex[index_i] == USER_KEYTYPE_RSA1024 || pindex[index_i] == USER_KEYTYPE_RSA2048){
				 memcpy((uint8_t *)(RSA_KEYPAIR_DATA_ADDR+index_i*RSA2048_BUFFLEN),pbud,RSA2048_BUFFLEN);
				 pbud+=RSA2048_BUFFLEN;
				 rec4kbufflen-=RSA2048_BUFFLEN;
			}
			if(index_i == RSA_KEYPAIR_NUM*2+1){
				if(gpagcount != recover_pag_count){
					vPortFree(pusrpin);
					pusrpin = NULL;
					return ERR_MANG_RECOVER_LEN;
				}
				if(*(uint16_t *)pbud != 0xFF99){
					vPortFree(pusrpin);
					pusrpin = NULL;
					return ERR_MANG_RECOVER_LEN;
				}
				rtval = revcover_key_file(0XFFF2);//�ָ��û���Կ��?
//				rtval = revcover_key_file(0XFFF2);//�ָ��û���Կ�ļ�
				if(rtval) {
					vPortFree(pusrpin);
					pusrpin = NULL;
					return ERR_CIPN_WRITKEYFILE;
				}
				rtval = revcover_keypin_file(pusrpin);
//				rtval = revcover_keypin_file(pusrpin);
				if(rtval) {
					vPortFree(pusrpin);
					pusrpin = NULL;
					return ERR_CIPN_WRITKEYFILE;
				}
			}
		}
	}
	if(pusrpin){
		vPortFree(pusrpin);
		pusrpin = NULL;
	}
	return 0;
}
int BackUpKEK(uint8_t *backupdata,uint32_t *gflag,uint16_t *gpagcount){
	uint16_t paghead= 0XFFF3;
	uint8_t *pbud = backupdata;
	uint8_t *pindex = NULL;
	uint32_t AllLen,index_i,rtval;
	if(*gflag != 1){
		goto NOFirst;
	}
	recover_key_index = 0;


	if(backupdata == NULL){//��ȡ�����ܳ���
		pbud = rec4Kbuff;
		//��ѯ��Կ����Ŀ
		rtval = Get_Cipher_Num(pbud);
		if(rtval){
			return rtval;
		}
		//8 + SM4_KEY_LEN+SM2_KEYPAIR_NUM+RSA_KEYPAIR_NUM+KEK_NUM --> 2048
		AllLen = 2048 + (*(uint16_t*)(pbud+6)) * KEK_LEN_MAX;
		*gflag = AllLen;
		//64-->2048/KEK_LEN_MAX
		*gpagcount = ((*(uint16_t*)(pbud+6))+64)/65 + 1;
		return 0;
	}
	memcpy(pbud,(uint8_t *)&paghead,2);pbud+=2;//����ͷ
	memcpy(pbud,(uint8_t *)&AllLen,4);pbud+=4;//���ݳ���
	//��ԭ����Կ����2
	data_xor(main_key,eFlash.MAINKEY_MCU,pbud,SM4_KEY_LEN); pbud+=SM4_KEY_LEN;//R2
	//��ȡSM2+RSA+KEK��ʶ
	//memcpy(pbud,(uint8_t *)SM2_KEYPAIR_INFO_ADDR,SM2_KEYPAIR_NUM*2+2);
	pbud+=SM2_KEYPAIR_NUM*2+2;
	//memcpy(pbud,(uint8_t *)RSA_KEYPAIR_INFO_ADDR,RSA_KEYPAIR_NUM*2+2);
	pbud+=RSA_KEYPAIR_NUM*2+2;
	memcpy(pbud,(uint8_t *)KEK_INFO_ADDR,KEK_NUM+1);
	*gflag = 2048;
	return 0;
NOFirst:
	recover_key_index+=1;
	pindex = (uint8_t *)KEK_INFO_ADDR;
	for(index_i=recover_key_index;index_i<=KEK_NUM;index_i++)
	{
		if(index_i == KEK_NUM){
			*gpagcount = 0XFF99;//	β��
			recover_key_index = index_i;
			//*gflag = pbud-backupdata;
		}
		if((pindex[index_i]&0X80) != 0){
			 memcpy(pbud,(uint8_t *)(KEK_DATA_ADDR+index_i*KEK_LEN_MAX),KEK_LEN_MAX);
			 pbud+=KEK_LEN_MAX;
			 *gflag = pbud-backupdata;
			 if((pbud-backupdata)>2048){
				 recover_key_index = index_i;
				 //*gflag = pbud-backupdata;
				 return 0;
			}
		}
	}
	return 0;	
}
int RecoverKEK(uint8_t *backupdata,uint32_t datalen,uint16_t gpagcount){
		uint8_t *pbud = rec4Kbuff;
	uint8_t *pindex = NULL;
	uint8_t *pbackupdata = backupdata;
	uint32_t AllLen,index_i,rtval;
	if(gpagcount != 1){
		goto NOFirst;
	}
	//��ѯ��Կ����Ŀ
	rtval = Get_Cipher_Num(pbud);
	if(rtval){
		return rtval;
	}
	if((uint16_t)*(pbud+6) != 0){
		return ERR_CIPN_USRKEYEXIT;
	}
	recover_key_index = 0;
	memset(rec4Kbuff,0,4096);
	rec4kbufflen = 0;
	memcpy(rec4Kbuff,backupdata,datalen);
	rec4kbufflen = datalen;
	if(datalen < 2048){
		return 0;
	}
	if(*(uint16_t*)rec4Kbuff != 0XFFF3){
		return ERR_MANG_RECOVER_LEN;
	}
	pbud += 6; //keytype(2)+datalen(4)
	pbud += 16; //R2
	//memcpy((uint8_t *)SM2_KEYPAIR_INFO_ADDR,pbud,SM2_KEYPAIR_NUM*2+2);
	pbud+=SM2_KEYPAIR_NUM*2+2;
	//memcpy((uint8_t *)RSA_KEYPAIR_INFO_ADDR,pbud,RSA_KEYPAIR_NUM*2+2);
	pbud+=RSA_KEYPAIR_NUM*2+2;
	memcpy((uint8_t *)KEK_INFO_ADDR,pbud,KEK_NUM+1);
	memcpy(rec4Kbuff,rec4Kbuff+2048,2048);
	rec4kbufflen -= 2048;
	recover_key_index = 1;
	pbud = rec4Kbuff;
	datalen = 0;
NOFirst:
	if(rec4kbufflen+datalen<=4096){
		memcpy(rec4Kbuff+rec4kbufflen,backupdata,datalen);
		rec4kbufflen += datalen;
		datalen = 0;
	}else{
		memcpy(rec4Kbuff+rec4kbufflen,backupdata,4096-rec4kbufflen);
		datalen = rec4kbufflen+datalen-4096;
		pbackupdata += 4096-rec4kbufflen;
		rec4kbufflen = 4096;

	}
	if(recover_key_index == 0){		
		if(datalen < 2048){
			return 0;
		}
		if(*(uint16_t*)rec4Kbuff != 0XFFF3){
			return ERR_MANG_RECOVER_LEN;
		}
		pbud += 6; //keyinfor
		//memcpy((uint8_t *)SM2_KEYPAIR_INFO_ADDR,pbud,SM2_KEYPAIR_NUM*2+2);
		pbud+=SM2_KEYPAIR_NUM*2+2;
		//memcpy((uint8_t *)RSA_KEYPAIR_INFO_ADDR,pbud,RSA_KEYPAIR_NUM*2+2);
		pbud+=RSA_KEYPAIR_NUM*2+2;
		memcpy((uint8_t *)KEK_INFO_ADDR,pbud,KEK_NUM+1);
		memcpy(rec4Kbuff,rec4Kbuff+2048,2048);
		rec4kbufflen -= 2048;
		recover_key_index = 1;
		pbud = rec4Kbuff;
	}
	pindex = (uint8_t *)KEK_INFO_ADDR;
	for(index_i=recover_key_index;index_i<=KEK_NUM;index_i++)
	{
		if(rec4kbufflen < KEK_LEN_MAX){
			memcpy(rec4Kbuff,pbud,rec4kbufflen);
			memcpy(rec4Kbuff+rec4kbufflen,pbackupdata,datalen);
			rec4kbufflen += datalen;
			datalen = 0;
			pbud = rec4Kbuff;
			if(rec4kbufflen < KEK_LEN_MAX && gpagcount != recover_pag_count){
				recover_key_index = index_i;
				return 0;
			}
		}
		if((pindex[index_i]&0X80) != 0){
			 memcpy((uint8_t *)(KEK_DATA_ADDR+index_i*KEK_LEN_MAX),pbud,KEK_LEN_MAX);
			 pbud+=KEK_LEN_MAX;
			 rec4kbufflen-=KEK_LEN_MAX;
		}
		if(index_i == KEK_NUM){
			if(gpagcount != recover_pag_count){
				return ERR_MANG_RECOVER_LEN;
			}
			if(*(uint16_t *)pbud != 0xFF99){
				return ERR_MANG_RECOVER_LEN;
			}
			rtval = revcover_key_file(0XFFF3);//�ָ�KEK��Կ�ļ�
			if(rtval) return ERR_CIPN_WRITKEYFILE;
		}
	}
	return 0;
}
//Userkey + KEK
int BackUpAllKey(uint8_t *backupdata,uint32_t *gflag,uint16_t *gpagcount){
	uint16_t paghead= 0XFFF4;
	uint8_t *pbud = backupdata;
	uint8_t *pindex = NULL;
	uint32_t AllLen,index_i,rtval;
	if(*gflag != 1){
		goto NOFirst;
	}
	recover_key_index = 0;

	if(backupdata == NULL){//��ȡ�����ܳ���
		pbud = rec4Kbuff;
		//��ѯ��Կ����Ŀ
		rtval = Get_Cipher_Num(pbud);
		if(rtval){
			return rtval;
		}
		//8 + SM4_KEY_LEN+SM2_KEYPAIR_NUM+RSA_KEYPAIR_NUM+KEK_NUM --> 2048
		AllLen = 2048+2*3072 + 2*(*(uint16_t*)(pbud)) * sizeof(SM2KeyPair)+   \
						 2*(*(uint16_t*)(pbud+2)+*(uint16_t*)(pbud+4)) * 1408+  \
						 (*(uint16_t*)(pbud+6)) * KEK_LEN_MAX;
		
		*gflag = AllLen;
		//64-->2080/KEK_LEN_MAX
		*gpagcount = (2*(*(uint16_t*)(pbud))+21)/22 +2+1+ \
								 (2*(*(uint16_t*)(pbud+2)+*(uint16_t*)(pbud+4))+1)/2 + \
								 ((*(uint16_t*)(pbud+6))+64)/65;
		return 0;
	}
	memcpy(pbud,(uint8_t *)&paghead,2);pbud+=2;//����ͷ
	memcpy(pbud,(uint8_t *)&AllLen,4);pbud+=4;//���ݳ���
	//��ԭ����Կ����2
	data_xor(main_key,eFlash.MAINKEY_MCU,pbud,SM4_KEY_LEN); pbud+=SM4_KEY_LEN;//R2
	//��ȡSM2+RSA+KEK��ʶ
	memcpy(pbud,(uint8_t *)SM2_KEYPAIR_INFO_ADDR,SM2_KEYPAIR_NUM*2+2);
	pbud+=SM2_KEYPAIR_NUM*2+2;
	memcpy(pbud,(uint8_t *)RSA_KEYPAIR_INFO_ADDR,RSA_KEYPAIR_NUM*2+2);
	pbud+=RSA_KEYPAIR_NUM*2+2;
	memcpy(pbud,(uint8_t *)KEK_INFO_ADDR,KEK_NUM+1);
	*gflag = 2048;
	return 0;
NOFirst:
	if(*gflag == 2){  //2,3��Ϊ˽Կ���ʿ�����
		for(index_i=1;index_i<=150;index_i++){
			if(read_cipher_access(index_i,&pbud[20*index_i],(char*)&pbud[20*index_i+2])){
				continue;
			}
		}
		*gflag = 3072;
		return 0;
	}
	if(*gflag == 3){  //2,3��Ϊ˽Կ���ʿ�����
		for(index_i=151;index_i<=SM2_KEYPAIR_NUM+RSA_KEYPAIR_NUM;index_i++){
			if(read_cipher_access(index_i,&pbud[20*(index_i-150)],(char*)&pbud[20*(index_i-150)+2])){
				continue;
			}
		}
		*gflag = 3072;
		return 0;
	}	
	
	recover_key_index+=1;
	pindex = (uint8_t *)SM2_KEYPAIR_INFO_ADDR;
	for(index_i=recover_key_index;index_i<=SM2_KEYPAIR_NUM*2+1;index_i++)
	{
		if(pindex[index_i] == USER_KEYTYPE_SM2){
			 memcpy(pbud,(uint8_t *)(SM2_KEYPAIR_DATA_ADDR+index_i*SM2_KEYPAIR_LEN),SM2_KEYPAIR_LEN);
			 pbud+=SM2_KEYPAIR_LEN;
			 *gflag = pbud-backupdata;
			 if((pbud-backupdata)>=2048){
				 //*gflag = pbud-backupdata;
				 recover_key_index = index_i;
				 return 0;
			 }
		}
		if(index_i == SM2_KEYPAIR_NUM*2+1){
			 recover_key_index = index_i;
			 *gflag = pbud-backupdata;
			 if(*gflag>0){
					return 0;
			 }
		}
	}
	pindex = (uint8_t *)RSA_KEYPAIR_INFO_ADDR;
	if(recover_key_index >= SM2_KEYPAIR_NUM*2+2){
		for(index_i=recover_key_index-SM2_KEYPAIR_NUM*2-2;index_i<=RSA_KEYPAIR_NUM*2+1;index_i++)
		{
			if(pindex[index_i] == USER_KEYTYPE_RSA1024 || pindex[index_i] == USER_KEYTYPE_RSA2048){
				 memcpy(pbud,(uint8_t *)(RSA_KEYPAIR_DATA_ADDR+index_i*RSA2048_BUFFLEN),RSA2048_BUFFLEN);
				 pbud+=RSA2048_BUFFLEN;
				 *gflag = pbud-backupdata;
				 if((pbud-backupdata)>2048){
					 //*gflag = pbud-backupdata;
					 recover_key_index = index_i+SM2_KEYPAIR_NUM*2+2;
					 return 0;
				 }
			}
			if(index_i == RSA_KEYPAIR_NUM*2+1){
				 recover_key_index = (SM2_KEYPAIR_NUM+RSA_KEYPAIR_NUM+2)*2;
				 *gflag = pbud-backupdata;
				 if(*gflag>0){
						return 0;
				 }
			}
		}
	}
	pindex = (uint8_t *)KEK_INFO_ADDR;
	if(recover_key_index >= (SM2_KEYPAIR_NUM+RSA_KEYPAIR_NUM+2)*2){
		for(index_i=recover_key_index-(SM2_KEYPAIR_NUM+RSA_KEYPAIR_NUM+2)*2;index_i<=KEK_NUM;index_i++)
		{
				if(index_i == 0){
					 continue;//
				}
				if(index_i == KEK_NUM){
					*gpagcount = 0XFF99;//	β��
					recover_key_index = index_i+(SM2_KEYPAIR_NUM+RSA_KEYPAIR_NUM+2)*2;
					//*gflag = pbud-backupdata;
				}
				if((pindex[index_i]&0X80) != 0){
					 memcpy(pbud,(uint8_t *)(KEK_DATA_ADDR+index_i*KEK_LEN_MAX),KEK_LEN_MAX);
					 pbud+=KEK_LEN_MAX;
					 *gflag = pbud-backupdata;
					 if((pbud-backupdata)>2048){
						 recover_key_index = index_i+(SM2_KEYPAIR_NUM+RSA_KEYPAIR_NUM+2)*2;
						 //*gflag = pbud-backupdata;
						 return 0;
					}
				}
		}
	}
	
	return 0;	
}
int RecoverAllKey(uint8_t *backupdata,uint32_t datalen,uint16_t gpagcount){
		//uint16_t paghead= 0XFFF2;
	uint8_t *pbud = rec4Kbuff;
	uint8_t *pindex = NULL;
	uint8_t *pbackupdata = backupdata;
	static uint8_t *pusrpin = NULL;
	uint32_t AllLen,index_i,rtval;
	if(gpagcount != 1){
		goto NOFirst;
	}
	//��ѯ��Կ����Ŀ
	rtval = Get_Cipher_Num(pbud);
	if(rtval){
		return rtval;
	}
	if((uint16_t)*(pbud)+(uint16_t)*(pbud+2)+(uint16_t)*(pbud+4)+(uint16_t)*(pbud+6)!=0){
		return ERR_CIPN_USRKEYEXIT;
	}
	if(pusrpin == NULL){
		pusrpin = pvPortMalloc(2*3072);
	}
	memset(pusrpin,0,3072);
	recover_key_index = 0;
	memset(rec4Kbuff,0,4096);
	rec4kbufflen = 0;
	memcpy(rec4Kbuff,backupdata,datalen);
	rec4kbufflen = datalen;
	if(datalen < 2048){
		return 0;
	}
	if(*(uint16_t*)rec4Kbuff != 0XFFF4){
		vPortFree(pusrpin);
		pusrpin = NULL;
		return ERR_MANG_RECOVER_LEN;
	}
	pbud += 6; //keytype(2)+datalen(4)
	pbud += 16; //R2
	memcpy((uint8_t *)SM2_KEYPAIR_INFO_ADDR,pbud,SM2_KEYPAIR_NUM*2+2);
	pbud+=SM2_KEYPAIR_NUM*2+2;
	memcpy((uint8_t *)RSA_KEYPAIR_INFO_ADDR,pbud,RSA_KEYPAIR_NUM*2+2);
	pbud+=RSA_KEYPAIR_NUM*2+2;
	memcpy((uint8_t *)KEK_INFO_ADDR,pbud,KEK_NUM+1);
	memcpy(rec4Kbuff,rec4Kbuff+2048,2048);
	rec4kbufflen -= 2048;
	recover_key_index = 0X1FFF;
	pbud = rec4Kbuff;
	datalen = 0;
NOFirst:
	if(rec4kbufflen+datalen<=4096){
		memcpy(rec4Kbuff+rec4kbufflen,backupdata,datalen);
		rec4kbufflen += datalen;
		datalen = 0;
	}else{
		memcpy(rec4Kbuff+rec4kbufflen,backupdata,4096-rec4kbufflen);
		datalen = rec4kbufflen+datalen-4096;
		pbackupdata += 4096-rec4kbufflen;
		rec4kbufflen = 4096;
	}
	if(recover_key_index == 0){
		if(datalen < 2048){
			return 0;
		}
		if(*(uint16_t*)rec4Kbuff != 0XFFF2){
			vPortFree(pusrpin);
			pusrpin = NULL;
			return ERR_MANG_RECOVER_LEN;
		}
		pbud += 6; //keytype(2)+datalen(4)
		pbud += 16; //R2
		memcpy((uint8_t *)SM2_KEYPAIR_INFO_ADDR,pbud,SM2_KEYPAIR_NUM*2+2);
		pbud+=SM2_KEYPAIR_NUM*2+2;
		memcpy((uint8_t *)RSA_KEYPAIR_INFO_ADDR,pbud,RSA_KEYPAIR_NUM*2+2);
		pbud+=RSA_KEYPAIR_NUM*2+2;
		memcpy((uint8_t *)KEK_INFO_ADDR,pbud,KEK_NUM+1);
		memcpy(rec4Kbuff,rec4Kbuff+2048,2048);
		rec4kbufflen -= 2048;
		//���ʣ�����ݵ�����buff
		memcpy(rec4Kbuff+rec4kbufflen,backupdata,datalen);
		rec4kbufflen += datalen;
		datalen = 0;
		
		recover_key_index = 0X1FFF;
		pbud = rec4Kbuff;
	}

	//��ȡ��1��˽Կ������
	if(recover_key_index == 0X1FFF){
		if(rec4kbufflen < 3072){
			memcpy(rec4Kbuff+rec4kbufflen,pbackupdata,datalen);
			rec4kbufflen += datalen;
			datalen = 0;
			return 0;
		}
		memcpy(pusrpin,rec4Kbuff,3072);
		rec4kbufflen -= 3072;
		memcpy(rec4Kbuff,rec4Kbuff+3072,rec4kbufflen);
		recover_key_index = 0X2FFF;
	}
	//��ȡ��2��˽Կ������
	if(recover_key_index == 0X2FFF){
		if(rec4kbufflen < 3072){
			memcpy(rec4Kbuff+rec4kbufflen,pbackupdata,datalen);
			rec4kbufflen += datalen;
			datalen = 0;
			return 0;
		}
		memcpy(pusrpin+3072,rec4Kbuff,3072);
		rec4kbufflen -= 3072;
		memcpy(rec4Kbuff,rec4Kbuff+3072,rec4kbufflen);
		recover_key_index = 1;
	}
	
	
	pindex = (uint8_t *)SM2_KEYPAIR_INFO_ADDR;
	for(index_i=recover_key_index;index_i<=SM2_KEYPAIR_NUM*2+1;index_i++)
	{
		if(rec4kbufflen < SM2_KEYPAIR_LEN){
			memcpy(rec4Kbuff,pbud,rec4kbufflen);
			memcpy(rec4Kbuff+rec4kbufflen,pbackupdata,datalen);
			rec4kbufflen += datalen;
			datalen = 0;
			if(rec4kbufflen < SM2_KEYPAIR_LEN && gpagcount != recover_pag_count){
				recover_key_index = index_i;
				return 0;
			}
			pbud = rec4Kbuff;
		}
		if(pindex[index_i] == USER_KEYTYPE_SM2){
			memcpy((uint8_t *)(SM2_KEYPAIR_DATA_ADDR+index_i*SM2_KEYPAIR_LEN),pbud,SM2_KEYPAIR_LEN);
			pbud+=SM2_KEYPAIR_LEN;
			rec4kbufflen-=SM2_KEYPAIR_LEN;
		}
		if(index_i == SM2_KEYPAIR_NUM*2+1){
			recover_key_index=SM2_KEYPAIR_NUM*2+2;
		}
	}
	pindex = (uint8_t *)RSA_KEYPAIR_INFO_ADDR;
	if(recover_key_index >= SM2_KEYPAIR_NUM*2+2){
		for(index_i=recover_key_index-SM2_KEYPAIR_NUM*2-2;index_i<=RSA_KEYPAIR_NUM*2+1;index_i++)
		{
			if(rec4kbufflen < RSA2048_BUFFLEN){
				memcpy(rec4Kbuff,pbud,rec4kbufflen);
				memcpy(rec4Kbuff+rec4kbufflen,pbackupdata,datalen);
				rec4kbufflen += datalen;
				datalen = 0;
				pbud = rec4Kbuff;				
				if(rec4kbufflen < RSA2048_BUFFLEN && gpagcount != recover_pag_count){
					recover_key_index = index_i+SM2_KEYPAIR_NUM*2+2;
					return 0;
				}

			}
			if(pindex[index_i] == USER_KEYTYPE_RSA1024 || pindex[index_i] == USER_KEYTYPE_RSA2048){
				 memcpy((uint8_t *)(RSA_KEYPAIR_DATA_ADDR+index_i*RSA2048_BUFFLEN),pbud,RSA2048_BUFFLEN);
				 pbud+=RSA2048_BUFFLEN;
				 rec4kbufflen-=RSA2048_BUFFLEN;
			}
			if(index_i == RSA_KEYPAIR_NUM*2+1){
					recover_key_index=RSA_KEYPAIR_NUM*2+2+SM2_KEYPAIR_NUM*2+2+1;
			}
		}
	}
	//(SM2_KEYPAIR_NUM+RSA_KEYPAIR_NUM+2)*2
	if(recover_key_index >= (SM2_KEYPAIR_NUM+RSA_KEYPAIR_NUM+2)*2){
		pindex = (uint8_t *)KEK_INFO_ADDR;
		for(index_i=recover_key_index-(SM2_KEYPAIR_NUM+RSA_KEYPAIR_NUM+2)*2;index_i<=KEK_NUM;index_i++)
		{
			if(rec4kbufflen < KEK_LEN_MAX){
				memcpy(rec4Kbuff,pbud,rec4kbufflen);
				memcpy(rec4Kbuff+rec4kbufflen,pbackupdata,datalen);
				rec4kbufflen += datalen;
				datalen = 0;
				pbud = rec4Kbuff;	
				if(rec4kbufflen < KEK_LEN_MAX && gpagcount != recover_pag_count){
					recover_key_index = index_i+(SM2_KEYPAIR_NUM+RSA_KEYPAIR_NUM+2)*2;
					return 0;
				}

			}
			if((pindex[index_i]&0X80) != 0){
				 memcpy((uint8_t *)(KEK_DATA_ADDR+index_i*KEK_LEN_MAX),pbud,KEK_LEN_MAX);
				 pbud+=KEK_LEN_MAX;
				 rec4kbufflen-=KEK_LEN_MAX;
			}
			if(index_i == KEK_NUM){
				if(gpagcount != recover_pag_count){
					vPortFree(pusrpin);
					pusrpin = NULL;
					return ERR_MANG_RECOVER_LEN;
				}
				if(*(uint16_t *)pbud != 0xFF99){
					vPortFree(pusrpin);
					pusrpin = NULL;
					return ERR_MANG_RECOVER_LEN;
				}
				rtval = revcover_key_file(0XFFF4);//�ָ��û���KEK��Կ�ļ�
				if(rtval){ 
					vPortFree(pusrpin);
					pusrpin = NULL;
					return rtval;
				}
				rtval = revcover_keypin_file(pusrpin);
				if(rtval) { 
					vPortFree(pusrpin);
					pusrpin = NULL;
					return rtval;
				}
			}
		}
	}
	if(pusrpin){
		vPortFree(pusrpin);
		pusrpin = NULL;
	}
	return 0;
}

int BackUpAdminQuit(void)
{
	//���������Կ
	memset(recover_mainkey,0,SHAMIR_PART_LEN(MAINKEY_LEN));
	memset(recover_backkey,0,MAINKEY_LEN);
	memset(recover_backkey_part,0,2*MAINKEY_LEN);
	memset(recover_usr_index,0,DEF_ADMIN_TOTAL_NUM);
	recover_login_num=0;
	return 0;
}
 

int  mcu_debug_set(uint32_t Status){
	eFlash.DEV_STATE = Status;
	if(Status == FactoryStatus || Status ==ReadyStatus){
			WriteFlashData();
	}
	*(unsigned short *)FPGA_MCU_DRIVER_WRITE = (0x0001<<(eFlash.DEV_STATE));
	memcpy(main_key,eFlash.AUTHKEY[9],SM4_KEY_LEN);
	loadusrkey();
	return 0;
}
