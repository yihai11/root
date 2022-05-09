#ifndef __USER_MANAGE_H__
#define	__USER_MANAGE_H__
#include "stdint.h"
//#include "devmanage.h"

#define DEF_ADMIN_TOTAL_NUM		3
#define DEF_ADMIN_ACCESS_NUM	2
#define DEF_OPERATOR_NUM_MAX	10				  //���7������Ա

// �û�����
enum UserType {
	NoUser=0,			// ���û���¼
	AdminLogging ,// ����Ա��¼��
	Admin ,		// ����Ա��¼
	Operator	//����Ա��¼
};


#pragma pack(1)
typedef struct USRLOG_STR{
	enum UserType usr_type;					//�û���¼״̬
	unsigned char index;				// ��¼�û���������	
	unsigned char admin_index[DEF_ADMIN_TOTAL_NUM];	//��ǰ��¼�Ĺ���Ա��־	
	unsigned char adm_login_num;		//�ѵ�¼�Ĺ���Ա����
}USRLOG;
#pragma pack()

int DevStatusIs(unsigned int  DEV_S);
int DevStatusNo(unsigned int  DEV_S);
uint8_t *get_backup_data(uint8_t *sdt,uint8_t * data, uint8_t len);
int add_admin(char *PIN, int PINlen, int ukeyindex);

int add_operator(char *PIN, int PINlen, int ukeyindex);

int UserLogin(uint16_t logusrtype,char *PIN, int PINlen);

int UserLogout(void);

int DelUsr(uint8_t usr_index);

int ResetOperatorPWD(uint16_t new_pwd_len,uint16_t index,char * new_pwd);

int ChangePWD(uint16_t old_pwd_len,char *pwd_old,uint16_t new_pwd_len,char *pwd_new);

int ChangePWDOper(uint16_t old_pwd_len,char *pwd_old,uint16_t new_pwd_len,char *pwd_new);
int CleanUkeyWithPin(uint16_t len,char* pin);
int CleanUkey(void);
int BackUpAdminInfo(uint8_t * backupdata);
int BackUpOperaInfo(uint8_t *backupdata);
int RecoverAdminInfo(uint8_t * backupdata);
int RecoverOperaInfo(uint8_t *backupdata);

int BackUpAdminLogin(uint16_t pinlen,uint8_t *pin);

int BackUpAdminQuit(void);

int BackUpUserkey(uint8_t *backupdata,uint32_t *gflag,uint16_t *gpagcount);
int BackUpKEK(uint8_t *backupdata,uint32_t *gflag,uint16_t *gpagcount);
int BackUpAllKey(uint8_t *backupdata,uint32_t *gflag,uint16_t *gpagcount);
int RecoverUserkey(uint8_t *backupdata,uint32_t datalen,uint16_t gpagcount);
int RecoverKEK(uint8_t *backupdata,uint32_t datalen,uint16_t gpagcount);
int RecoverAllKey(uint8_t *backupdata,uint32_t datalen,uint16_t gpagcount);	
int mcu_debug_set(uint32_t Status);	
#endif
