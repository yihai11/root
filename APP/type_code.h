#ifndef __TYPE_CODE_H__
#define	__TYPE_CODE_H__


//-----------��Կ����-----------//
#define	MCUCMD_START		0x1000

#define	SD_TASK_GETDEVINFO						0x1001	//	��ȡ�豸��Ϣ
#define	SD_TASK_GETKEYACCRINGHT				0x1002	//	��ȡ˽ԿȨ��
#define	SD_TASK_EXPSIGNPUB_RSA				0x1003	//	����RSAǩ����Կ
#define	SD_TASK_EXPENCPUB_RSA					0x1004	//	����RSA���ܹ�Կ
#define	SD_TASK_GENKEYPAIREXPORT_RSA	0x1005	//	����RSA��Կ�Բ����
#define	SD_TASK_GENKEYWIHTIPK_RSA			0x1006	//	���ɻỰ��Կ�����ڲ�RSA��Կ�������
#define	SD_TASK_GENKEYWITHEPK_RSA			0x1007	//	���ɻỰ��Կ�����ⲿRSA��Կ�������
#define	SD_TASK_IMPORTKEYWITHISK_RSA	0x1008	//	����Ự��Կ�����ڲ�RSA˽Կ����
#define	SD_TASK_EXPSIGNPUB_ECC				0x1009	//	����ECCǩ����Կ
#define	SD_TASK_EXPENCPUB_ECC					0x100A	//	����ECC���ܹ�Կ
#define	SD_TASK_GENKEYPAIREXPORT_ECC	0x100B	//	����ECC�ǶԳ���Կ�Բ����
#define	SD_TASK_GENKEYWIHTIPK_ECC			0x100C	//	���ɻỰ��Կ�����ڲ�ECC��Կ�������
#define	SD_TASK_GENKEYWITHEPK_ECC			0x100D	//	���ɻỰ��Կ�����ⲿECC��Կ�������
#define	SD_TASK_IMPORTKEYWITHISK_ECC	0x100E	//	����Ự��Կ�����ڲ�ECC˽Կ����
#define	SD_TASK_GENAGREEDATAWITHECC		0x100F	//	������ԿЭ�̲��������
#define	SD_TASK_GENKEYWITHECC					0x1010	//	����Ự��Կ
#define	SD_TASK_GENAGREEANDKEYWITHECC	0x1011	//	����Э�̲���������Ự��Կ
#define	SD_TASK_GENKEYWIHTKEK					0x1012	//	���ɻỰ��Կ������Կ������Կ�������
#define	SD_TASK_IMPORTKEYWITHKEK			0x1013	//	����Ự��Կ������Կ������Կ����KEK
#define	SD_TASK_IMPORTSESSIONKEY			0x1014	//	���ĵ���/�����Ự��Կ
#define	SD_TASK_DESTORYKEY						0x1015	//	���ٻỰ��Կ
#define	SD_TASK_EXTPUBKEYOPER_RSA			0x1016	//	�ⲿ��ԿRSA����
#define	SD_TASK_EXTPRIKEYOPER_RSA			0x1017	//	�ⲿ˽ԿRSA����
#define	SD_TASK_INTPUBKEYOPER_RSA			0x1018	//	�ڲ���ԿRSA����
#define	SD_TASK_INTPRIKEYOPER_RSA			0x1019	//	�ڲ�˽ԿRSA����
#define	SD_TASK_INTSYMENC_AES					0x101A	//	AES�ڲ���Կ����
#define	SD_TASK_EXTSYMENC_AES					0x101B	//	AES�ⲿ��Կ����
#define	SD_TASK_INTSYMENC_DES					0x101C	//	DES�ڲ���Կ����
#define	SD_TASK_EXTSYMENC_DES					0x101D	//	DES�ⲿ��Կ����
#define	SD_TASK_INTSYMDEC_AES					0x101E	//	AES�ڲ���Կ����
#define	SD_TASK_EXTSYMDEC_AES					0x101F	//	AES�ⲿ��Կ����
#define	SD_TASK_INTSYMDEC_DES					0x1020	//	DES�ڲ���Կ����
#define	SD_TASK_EXTSYMDEC_DES					0x1021	//	DES�ⲿ��Կ����
#define	SD_TASK_CREATEFILE						0x1022	//	�����ļ�
#define	SD_TASK_READFILE							0x1023	//	��ȡ�ļ�
#define	SD_TASK_WRITEFILE							0x1024	//	д���ļ�
#define	SD_TASK_DELETEFILE						0x1025	//	ɾ���ļ�
#define	SD_TASK_CLEARFILE							0x1026	//	����ļ���
#define	SD_TASK_ENUMFILE							0x1027	//	ö���ļ�
#define	SD_TASK_ADDUSER								0x1028	//	����û�
#define	SD_TASK_USERLOGIN							0x1029	//	�û���¼
#define	SD_TASK_USERLOGOUT						0x102A	//	�û��ǳ�
#define	SD_TASK_RESETPWD							0x102B	//	�����û�����NULLNULLNULL
#define	SD_TASK_DELUSER								0x102C	//	ɾ������Ա
#define	SD_TASK_RESETOPERATORPWD			0x102D	//	����Ա�������ã���Ҫ����̬��
#define	SD_TASK_GETLOGINSTATUS				0x102E	//	��ȡ��¼״̬
#define	SD_TASK_CHGOCURPWD						0x102F	//	�޸ĵ�ǰ�û����루����Ҫ����̬��
#define	SD_TASK_CONFIGFILE						0x1030	//	������󵥸��ļ���С���ļ�����
#define	SD_TASK_BACKUPADMININFO				0x1031	//	���ݹ���Ա��Ϣ
#define	SD_TASK_RECOVERYADMININFO			0x1032	//	�ָ�����Ա��Ϣ
#define	SD_TASK_BACKUPOPERATOR				0x1033	//	���ݲ���Ա��ȫ����
#define	SD_TASK_BACKUPKEY							0x1034	//	������Կ
#define	SD_TASK_BACKUPADMINLOGIN			0x1035	//	���ݹ���Ա��¼
#define	SD_TASK_BACKUPADMINQUIT				0x1036	//	���ݹ���Ա�ǳ�
#define	SD_TASK_GETDEVICESTATE				0x1037	//	��ȡ�豸״̬
#define	SD_TASK_RECOVEROPERATOR				0x1038	//	�ָ�����Ա�����У�
#define	SD_TASK_CHECKSELF							0x1039	//	�豸�Լ�
#define	SD_TASK_CYCLECHECKSELF				0x103A	//	�����Լ�
#define	SD_TASK_GENDEVKEY							0x103B	//	�����豸��Կ
#define	SD_TASK_EXPORTDEVPUBKEY				0x103C	//	�����豸��Կ��Կ
#define	SD_TASK_GENKEYUSERKEYPAIR			0x103D	//	�����û���Կ��
#define	SD_TASK_CHGKEYKEYPAIRPWD			0x103E	//	�û���Կ˽Կ���ʿ����޸�
#define	SD_TASK_GENKEK								0x103F	//	������Կ������Կ
#define	SD_TASK_DELKEK								0x1040	//	ɾ����Կ������Կ
#define	SD_TASK_RECOVERKEY						0x1041	//	�ָ���Կ
#define	SD_TASK_IMPORTKEYPAIR					0x1042	//	������Կ��
#define	SD_TASK_DESKEYPAIR						0x1043	//	������Կ��
#define	SD_TASK_GETKEYPAIRNUM					0x1044	//	��ѯ��Կ������
#define	SD_TASK_GETKEYPAIRSTAT				0x1045	//	��ѯ��Կ��״̬
#define	SD_TASK_EXPORTKEYPAIR					0x1046	//	������Կ��
#define	SD_TASK_GETUSERKEYCHK					0x1047	//	�����û���ԿУ��ֵ
#define	SD_TASK_GETKEKCHK							0x1048	//	����KEKУ��ֵ
#define	SD_TASK_IMPORTENCKEY					0x1049	//	���������Կ
#define	SD_TASK_IMPORTKEK							0x104A	//	����KEK
#define	SD_TASK_DEVKEKENC							0x104B	//	�豸��Կ����
#define	SD_TASK_DEVKEKDEC							0x104C	//	�豸��Կ����
#define	SD_TASK_DEVKEKSIGN						0x104D	//	�豸��Կǩ��
#define	SD_TASK_DEVKEKVERIFY					0x104E	//	�豸��Կ��ǩ
#define	SD_TASK_DESTORYDEV						0x104F	//	�豸����
#define	SD_TASK_CLEARUKEY							0x1050	//	���Ukey��Ϣ
#define	SD_MANU_UPDATEDEV							0x1051	//	�豸����
#define	SD_MANU_CLEARMCU							0x1052	//	����MCU
#define	SD_MANU_SETDEVINFO						0x1053	//	���ü��ܿ���Ϣ
#define	SD_MANU_CLEARUKEY							0x1054	//	���UKEY
#define SD_TASK_HASHSHA1							0x1055	//	SHA1
#define SD_TASK_HASHSHA256						0x1056	//	SHA256
#define SD_TASK_EXCHDIGENVELOP_RSA		0x1057	//	����RSA�������ŷ�
#define SD_TASK_EXCHDIGENVELOP_ECC		0x1058	//	����SM2�������ŷ�
#define	SD_TASK_EXTPUBKEYENC_ECC			0x1059	//	�ⲿ��ԿECC��������
#define	SD_TASK_EXTPRIKEYDEC_ECC			0x105A	//	�ⲿ˽ԿECC��������
#define	SD_TASK_INTPUBKEYENC_ECC			0x105B	//	�ڲ���ԿECC��������
#define	SD_TASK_INTPRIKEYDEC_ECC			0x105C	//	�ڲ�˽ԿECC��������
#define	SD_TASK_GOTOFACTORY						0x105D	//	�ָ�����̬
#define	SD_TASK_INTPRIKEYSIGN_ECC			0x105E	//	�ڲ�˽ԿECCǩ��
#define	SD_TASK_INTPUBKEYVERI_ECC			0x105F	//	�ڲ���ԿECC��ǩ
#define	SD_TASK_EXTPRIKEYSIGN_ECC			0x1060	//	�ⲿ˽ԿECCǩ��
#define	SD_TASK_EXTPUBKEYVERI_ECC			0x1061	//	�ⲿ��ԿECC��ǩ
#define	SD_TASK_SHA384								0x1062	//	SHA384
#define	SD_TASK_SHA512								0x1063	//	SHA512
#define	SD_TASK_INTSYMENC_SM1					0x1064	//	SM1�ڲ���Կ����
#define	SD_TASK_INTSYMDEC_SM1					0x1065	//	SM1�ڲ���Կ����
#define	SD_TASK_EXTSYMENC_SM1					0x1066	//	SM1�ⲿ��Կ����
#define	SD_TASK_EXTSYMDEC_SM1					0x1067	//	SM1�ⲿ��Կ����
#define	SD_TASK_GETMUCVERSION					0x1068	//	��ȡMCU�汾
#define	SD_TASK_GOTOFACTORY_NOADMIN		0x1069	//	�ָ�����̬�޹���Ա
#define	MCUCMD_END		0x1070


//#define SDR_UNKNOWERR					0x0001						//δ֪����
//#define SDR_NOTSUPPORT				0x0002						//��֧�ֵĽӿڵ���
//#define SDR_COMMFAIL					0x0003						//���豸ͨ��ʧ��
//#define SDR_HARDFAIL					0x0004						//����ģ������Ӧ
//#define SDR_OPENDEVICE				0x0005						//���豸ʧ��
//#define SDR_OPENSESSION				0x0006						//�����Ựʧ��
//#define SDR_PARDENY						0x0007						//��˽Կʹ��Ȩ�
#define SDR_ALGNOTSUPPORT			0x0009						//��֧�ֵ��㷨����
#define SDR_KEYNOTEXIST				0x0008							//�����ڵ���Կ����
//#define SDR_ALGMODNOTSUPPORT	0x000A						//��֧�ֵ��㷨ģʽ����
#define SDR_PKOPERR						0x000B						//��Կ����ʧ��
#define SDR_SKOPERR						0x000C						//˽Կ����ʧ��
#define SDR_SIGNERR						0x000D						//ǩ������ʧ��
#define SDR_VERIFYERR					0x000E						//��֤ǩ��ʧ��
//#define SDR_SYMOPERR					0x000F						//�Գ��㷨����ʧ��
//#define SDR_STEPERR						0x0010						//�ಽ���㲽�����
#define SDR_FILESIZEERR				0x0011						//�ļ����ȳ�������
#define SDR_FILENOEXIST				0x0012						//ָ�����ļ�������
#define SDR_FILEOFSERR 				0x0013						//�ļ���ʼλ�ô���
#define SDR_KEYTYPEERR 				0x0014						//��Կ���ʹ���
#define SDR_KEYERR 						0x0015						//��Կ�Դ���
#define SDR_ENCDATAERR				0x0016						//ECC�������ݴ���
#define SDR_RANDERR						0x0017						//���������ʧ��
//#define SDR_PRKRERR						0x0018						//˽Կʹ��Ȩ�޻�ȡʧ��
//#define SDR_MACERR 						0x0019						//MAC����ʧ��
//#define SDR_FILEEXISTS				0x001A						//ָ���ļ��Ѵ���
#define SDR_FILEWERR					0x001B						//�ļ�д��ʧ��
#define SDR_NOBUFFER					0x001C						//�洢�ռ䲻��
#define SDR_INARGERR					0x001D						//�����������
//#define SDR_OUTARGERR 				0x001E						//�����������


//������
#define ERR_UKEY   0X1000        //Ukey�����
#define ERR_DVES   0X2000        //���ܿ������
#define ERR_MANG   0X3000        //���������
#define ERR_CIPH   0X4000        //���������
#define ERR_COMM   0X5000        //�������
#define ERR_TEST 	 0X0500        //�Լ������
//0X1000  //Ukey�����
#define ERR_UKEY_CONNECT        ERR_UKEY + 0X01    //����Ukeyʧ��
#define ERR_UKEY_DEVAUTH        ERR_UKEY + 0X02    //�Ƿ�Ukey�����ƶ�����Ukey
#define ERR_UKEY_NOFREE         ERR_UKEY + 0X03    //��ǰUkey���ǿհ�Ukey���޷�����ָ��Ukey
#define ERR_UKEY_APP            ERR_UKEY + 0X04    //UkeyӦ�ò���ʧ�ܣ��������Ա�ͱ���Ӧ��
#define ERR_UKEY_FILE           ERR_UKEY + 0X05    //Ukey�ļ���������
//#define ERR_UKEY_SERKEY         ERR_UKEY + 0X06    //Ukey ���кŻ�ȡ����
#define ERR_UKEY_PIN            ERR_UKEY + 0X07    //Ukey PIN У�����
#define ERR_UKEY_CHANGEPIN      ERR_UKEY + 0X08    //�޸� Ukey PIN ����
//#define ERR_UKEY_DECDATA        ERR_UKEY + 0X09    //Ukey���ݽ���ʧ��
#define ERR_UKEY_KIND           ERR_UKEY + 0X0a    //Ukey���ʹ��󣬵�ǰUkey����Ҫ���������
#define ERR_UKEY_FIELD          ERR_UKEY + 0X0b    //Ukey����󣬷ǵ�ǰ�������Ukey
//#define	ERR_UKEY_TIMEOUT			  ERR_UKEY + 0X0c		 //Ukey��ʱ
#define	ERR_UKEY_LOCK			  		ERR_UKEY + 0X0d		 //Ukey����
#define	ERR_UKEY_VOID			  		ERR_UKEY + 0X0e		 //Ukeyδʶ���Ϊ��


//0X2000	//���ܿ��豸״̬����
#define ERR_DVES_INIT           ERR_DVES + 0X01     //��������Աʱ���豸״̬��
#define ERR_DVES_INIT_BACKUP    ERR_DVES + 0X02     //�ָ�����ʱ,�������Ѵ���
#define ERR_DVES_OPER           ERR_DVES + 0X03     //����ɾ������Աʱ���豸״̬�ǹ���̬
#define ERR_DVES_USERLOGIN      ERR_DVES + 0X04     //�û���¼ʱ���豸״̬����
//#define ERR_DVES_BADMLOGIN      ERR_DVES + 0X05     //���ݹ���Ա��¼���豸״̬����
//#define ERR_DVES_BACKUPUKEY     ERR_DVES + 0X06     //��������ʱ���豸״̬�ǹ���̬
//#define ERR_DVES_RECOVERUKEY    ERR_DVES + 0X07     //�ָ���������ʱ���豸״̬����
//#define ERR_DVES_CLEANUP        ERR_DVES + 0X08     //������������ʱ���豸״̬����
//#define ERR_DVES_DESTORY        ERR_DVES + 0X09     //���ٹ�������ʱ���豸״̬����
#define ERR_DVES_USERLOGOUT     ERR_DVES + 0X0a     //�˳��û���¼ʱ���豸״̬����
//#define ERR_DVES_USERPOLICY     ERR_DVES + 0X0b     //�û��������ʱ���豸״̬����
//#define ERR_DVES_ERTUKEY        ERR_DVES + 0X0C     //����Ukeyʱ���豸״̬����,����ԿΪNULL
//#define	ERR_DVES_BACKUPUSR			ERR_DVES + 0x0D			//�����û�����ʱ���豸�ǹ���̬
#define	ERR_DVES_WORKSTATE			ERR_DVES + 0x0E			//�豸�ǹ���̬��Ȩ�޴���
#define	ERR_DVES_MANGSTATE			ERR_DVES + 0x0F			//�豸�ǹ���̬��Ȩ�޴���
#define	ERR_DVES_FACTYSTATE			ERR_DVES + 0x10			//�豸�ǳ���̬��Ȩ�޴���
#define	ERR_DVES_STATETODO			ERR_DVES + 0x11			//�豸״̬��������ò���
#define	ERR_DVES_ENSHIELD				ERR_DVES + 0x12			//�豸���Ǳ��������ظ������Ǳ����Ѿ�����
#define	ERR_DVES_DISSHIELD			ERR_DVES + 0x13			//�豸���Ǳ��������ظ������Ǳ����Ѿ��ر�


//0X3000    //���������
#define ERR_MANG_PINLEN		      ERR_MANG + 0X01     //PIN ����ȴ���
#define ERR_MANG_PINCHECK		    ERR_MANG + 0X02     //PIN ����У�����
#define ERR_MANG_ADMNUM 	    	ERR_MANG + 0X03     //��������Ա��������������
#define ERR_MANG_RELOGIN	    	ERR_MANG + 0X04     //����ԱUKEY���ظ���¼����Ukey�Ѿ���¼����
//#define ERR_MANG_AUTHKEY 	    	ERR_MANG + 0X05     //�豸��֤����
#define ERR_MANG_BACKLOGIN   		ERR_MANG + 0X06     //��¼�ı��ݹ���Ա���һ�ε�¼�ķ�ͬһ������
//#define ERR_MANG_BAUKEYANT	    ERR_MANG + 0X07     //����Ukey��֤����
//#define ERR_MANG_NUM 	        	ERR_MANG + 0X08     //��������Ա��������������
//#define ERR_MANG_USERPOLICY 	  ERR_MANG + 0X09     //���ù������ʱ������ֵ�����Ϲ涨
//#define ERR_UPFI_SERNU 	        ERR_MANG + 0X0A     //���߸��¹̼�������Ŵ���
//#define ERR_UPFI_FPGAFL	        ERR_MANG + 0X0B     //���߸��¹̼���дFPGA FLASH����
//#define ERR_UPFI_ARMFL 	        ERR_MANG + 0X0C     //���߸��¹̼���дARM FLASH����
//#define ERR_DELE_UKEYNULL 	    ERR_MANG + 0X0D     //UkeyΪ�հ�Ukey������Ҫ��ʼ����
//#define ERR_STAU_MANG 	        ERR_MANG + 0X0E     //���óɹ���̬��������ԿΪ�ա�
//#define ERR_STAU_READY 	        ERR_MANG + 0X0f     //���óɾ���̬��������ԿΪ�ա�
//#define ERR_STAU_MANGDECKEY 	  ERR_MANG + 0X11     //���óɹ���̬���������豸��Կ��˽Կ����
#define	ERR_MANG_RE_ADD					ERR_MANG + 0x12			//�����û�ʱ���û����к��Ѵ���
#define ERR_MANG_ERROR_USR			ERR_MANG + 0x13		  //��¼��ɾ�������ڵ��û�
#define ERR_MANG_DEL_ADMIN			ERR_MANG + 0x14			//ɾ������Ա����
#define ERR_MANG_RECOVER_LEN		ERR_MANG + 0x15			//�ָ�����ʱ�����ݻ򳤶��쳣
#define ERR_MANG_AUTHUSR 	    	ERR_MANG + 0X16     //�û���֤����
#define ERR_MANG_CHECKCODE 	    ERR_MANG + 0X17     //������У�������
#define ERR_MANG_BACKAUTH 	    ERR_MANG + 0X18     //���ݹ���Ա��¼��������

//0X4000    //���������
#define ERR_CIPN_SKEYFULL     	ERR_CIPH + 0X01    //�Ự��Կ����
#define ERR_CIPN_SKEYINFPGA    	ERR_CIPH + 0X02    //�Ựд��FPGAʧ��
#define ERR_CIPN_SKEYINDEXERR   ERR_CIPH + 0X03    //�Ự��Կ�����Ӧ����ֵ�Ƿ�
#define ERR_CIPN_SKEYINDEXNULL  ERR_CIPH + 0X04    //�Ự��Կ�����Ӧ����ֵ����Կ
#define ERR_CIPN_SKEYLEN    	ERR_CIPH + 0X05    //�Ự��Կ���ݳ��ȴ���
//0X0000
#define ERR_CIPN_INDEXLEN       SDR_INARGERR	//ERR_CIPH + 0X06    //������С���ȴ���
#define ERR_CIPN_GENRANDOM      SDR_RANDERR		//ERR_CIPH + 0X07    //�������������
#define ERR_CIPN_FPGASM2ENCIN   SDR_ENCDATAERR//ERR_CIPH + 0X08    //FPGAsm2�ڲ����ܴ���
#define ERR_CIPN_FPGASM2DECIN   SDR_ENCDATAERR//ERR_CIPH + 0X09    //FPGAsm2�ڲ����ܴ���
//#define ERR_CIPN_FPGASM2ENCIN   ERR_CIPH + 0X08    //FPGAsm2�ڲ����ܴ���
//#define ERR_CIPN_FPGASM2DECIN   ERR_CIPH + 0X09    //FPGAsm2�ڲ����ܴ���
#define ERR_CIPN_RSAPUBKEYOP    SDR_PKOPERR//ERR_CIPH + 0X11    //RSA��Կ��������
#define ERR_CIPN_RSAPRIKEYOP    SDR_SKOPERR//ERR_CIPH + 0X12    //RSA˽Կ��������

//#define ERR_CIPN_FPGASM4        ERR_CIPH + 0X0a    //FPGAsm4�ڲ��������
#define ERR_CIPN_GENSM2KEY   		ERR_CIPH + 0X0b    //����SM2��Կ��
#define ERR_CIPN_GETSM2KEY   		ERR_CIPH + 0X0c    //��ȡSM2��Կ����
#define ERR_CIPN_GENRSAKEY   		ERR_CIPH + 0X0d    //����RSA��Կ��MCU�㷨ʧ��
#define ERR_CIPN_GETRSAKEY      ERR_CIPH + 0X0e    //��ȡRSA��Կʧ��
#define ERR_CIPN_EXPRSAPUBKEY   ERR_CIPH + 0X0f    //����RSA��Կʧ��
#define ERR_CIPN_RSAINLEN       ERR_CIPH + 0X10    //RSA�����������

#define ERR_CIPH_DECMAIN 	      ERR_CIPH + 0X1f    //��������Կ��������,������Կ����ʧ�ܡ�
//#define	ERR_CIPN_ERR_AUTH			  ERR_CIPH + 0x20		 //UKEY��֤��Կ����
#define	ERR_CIPN_RANDOM 			  ERR_CIPH + 0x21		 //��ȡ���������
#define	ERR_CIPN_DECDATA 			  ERR_CIPH + 0x22		 //�������ݴ���
#define	ERR_CIPN_CREATEFILE 	  ERR_CIPH + 0x23		 //��������Կ���ļ�����
#define	ERR_CIPN_OPENKEYFILE 		ERR_CIPH + 0x24		 //�򿪣���Կ���ļ�����
#define	ERR_CIPN_DELKEYFILE 		ERR_CIPH + 0x25		 //ɾ������Կ���ļ�����
#define	ERR_CIPN_READKEYFILE 		ERR_CIPH + 0x26		 //��  ����Կ���ļ�����
#define	ERR_CIPN_WRITKEYFILE 		ERR_CIPH + 0x27		 //д  ����Կ���ļ�����
#define	ERR_CIPN_DECKEYFILE 		ERR_CIPH + 0x28		 //���ܣ���Կ���ļ�����
#define	ERR_CIPN_ENCKEYFILE 		ERR_CIPH + 0x29		 //���ܣ���Կ���ļ�����
#define	ERR_CIPN_USRKEYEXIT 		ERR_CIPH + 0x30		 //��Կ�����Ѿ����ڴ���
#define	ERR_CIPN_USRKEYNOEXIT 	ERR_CIPH + 0x31		 //��Կ���������ڴ���
#define	ERR_CIPN_USRKEYERR 		  ERR_CIPH + 0x32		 //��Կ�����Ƿ�
#define	ERR_CIPN_SM2ARGENKEY 	  ERR_CIPH + 0x33	   //sm2Э�̼�����Կ����
#define	ERR_CIPN_SM2ARGEEXCHE 	ERR_CIPH + 0x34	   //FPGAЭ�̽�����������

//0X5000  //����ͨ�ô���
//0X0000
#define	ERR_COMM_MALLOC         SDR_NOBUFFER//ERR_COMM + 0x01    //�ڴ�����ʧ��
#define	ERR_COMM_INPUT          SDR_INARGERR//ERR_COMM + 0x02    //�������ݴ���
#define	ERR_COMM_INDATA         ERR_COMM + 0x03    //�ڲ������쳣
#define	ERR_COMM_INPUTLEN       ERR_COMM + 0x04    //�������ݴ���
#define	ERR_COMM_OUTTIME        ERR_COMM + 0x05    //��ʱ

//0X0500  //�Լ������
#define	ERR_TEST_RANDOM       ERR_TEST + 0x01    //������Լ�ʧ��
#define	ERR_TEST_SM1          ERR_TEST + 0x02    //SM1�㷨�Լ�ʧ��
#define	ERR_TEST_SM2         	ERR_TEST + 0x03    //SM2�㷨�Լ�ʧ��
#define	ERR_TEST_SM3       		ERR_TEST + 0x04    //SM3�㷨�Լ�ʧ��
#define	ERR_TEST_SM4        	ERR_TEST + 0x05    //SM4�㷨�Լ�ʧ��
#define	ERR_TEST_RSA        	ERR_TEST + 0x06    //RSA�㷨�Լ�ʧ��
#define	ERR_TEST_FWAREDATA    ERR_TEST + 0x07    //�̼������Լ��
#define	ERR_TEST_USRDATA    	ERR_TEST + 0x08    //�û����������Լ��
#define	ERR_TEST_KEYDATA    	ERR_TEST + 0x09    //��Կ�����Բ���ʧ��
#define	ERR_TEST_ELSE   		ERR_TEST + 0x0A    //�����Լ����
#endif
